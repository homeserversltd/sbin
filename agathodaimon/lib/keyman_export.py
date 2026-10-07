"""Private, root-only handoff from Keyman exchange files into mutable memory."""
from __future__ import annotations

import errno
import fcntl
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

KEYMAN = "/vault/keyman/keyman"
SERVICE_NAMES = frozenset({"nas", "nas_backup", "service_suite"})
MAX_KEY_FILE_BYTES = 1024 * 1024
MAX_EXCHANGE_BYTES = 64 * 1024
EXPORT_TIMEOUT_SECONDS = 10

NON_ROOT = "non-root"
UNINITIALIZED_SYSTEM = "uninitialized-system"
MISSING_KEY = "missing-key"
MALFORMED_KEY_FILE = "malformed-key-file"
PREFLIGHT_UNOBSERVABLE = "preflight-unobservable"
SERVICE_NAME_INVALID = "service-name-invalid"
EXCHANGE_ARTIFACT_PREEXISTING = "exchange-artifact-preexisting"
EXCHANGE_ARTIFACT_MALFORMED = "exchange-artifact-malformed"
EXCHANGE_ARTIFACT_RACED = "exchange-artifact-raced"
EXCHANGE_CLEANUP_FAILED = "exchange-cleanup-failed"
EXPORT_FAILED = "export-failed"
EXPORT_TIMEOUT = "export-timeout"
EXPORT_UNAVAILABLE = "export-unavailable"
SCRATCH_CONTEXT_INVALID = "scratch-context-invalid"


class KeymanExportError(Exception):
    """A static, non-secret refusal signal from the private export membrane."""

    def __init__(self, signal: str, return_code: int | None = None):
        self.signal = signal
        self.return_code = return_code
        super().__init__(signal)


@dataclass(frozen=True)
class _Layout:
    keyman: str
    keys_dir: str
    skeleton_dir: str
    exchange_dir: str
    child_root: str | None


def _refuse(signal: str, return_code: int | None = None) -> NoReturn:
    raise KeymanExportError(signal, return_code) from None


def _absolute(value: str | os.PathLike[str]) -> str:
    text = os.fspath(value)
    if not isinstance(text, str) or not text or "\x00" in text or not os.path.isabs(text):
        _refuse(SCRATCH_CONTEXT_INVALID)
    return os.path.normpath(text)


def _layout(scratch_root: str | os.PathLike[str] | None,
            exporter: str | os.PathLike[str] | None) -> _Layout:
    if scratch_root is None and exporter is None:
        return _Layout(KEYMAN, "/vault/.keys", "/root/key", "/mnt/keyexchange", None)
    if scratch_root is None or exporter is None:
        _refuse(SCRATCH_CONTEXT_INVALID)
    root = _absolute(scratch_root)
    executable = _absolute(exporter)
    return _Layout(executable, os.path.join(root, "vault", ".keys"),
                   os.path.join(root, "root", "key"),
                   os.path.join(root, "mnt", "keyexchange"), root)


def _open_dir(path: str) -> int:
    parts = Path(path).parts
    if not Path(path).is_absolute() or any(part in {".", ".."} for part in parts):
        _refuse(PREFLIGHT_UNOBSERVABLE)
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = -1
    try:
        fd = os.open("/", flags)
        for component in parts[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except FileNotFoundError:
        if fd >= 0:
            os.close(fd)
        raise
    except OSError:
        if fd >= 0:
            os.close(fd)
        _refuse(PREFLIGHT_UNOBSERVABLE)


def _open_key_file(directory_fd: int, name: str) -> tuple[int, os.stat_result] | None:
    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        _refuse(PREFLIGHT_UNOBSERVABLE)
    if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
            or before.st_size <= 0 or before.st_size > MAX_KEY_FILE_BYTES):
        _refuse(MALFORMED_KEY_FILE)
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd: int | None = None
    try:
        fd = os.open(name, flags, dir_fd=directory_fd)
        opened = os.fstat(fd)
        after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        if fd is not None:
            os.close(fd)
        _refuse(MALFORMED_KEY_FILE)
    except OSError as failure:
        if fd is not None:
            os.close(fd)
        if failure.errno == errno.ELOOP:
            _refuse(MALFORMED_KEY_FILE)
        _refuse(PREFLIGHT_UNOBSERVABLE)
    assert fd is not None
    if ((not stat.S_ISREG(opened.st_mode)) or opened.st_size <= 0
            or opened.st_size > MAX_KEY_FILE_BYTES
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)):
        os.close(fd)
        _refuse(MALFORMED_KEY_FILE)
    return fd, opened


def _same_path_inode(directory_fd: int, name: str, identity: os.stat_result) -> bool:
    try:
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return False
    return (stat.S_ISREG(current.st_mode) and not stat.S_ISLNK(current.st_mode)
            and (current.st_dev, current.st_ino) == (identity.st_dev, identity.st_ino))


def _parse_credential(record: bytearray, service_name: str) -> bytearray:
    if not record or 0 in record:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    fields: dict[bytes, tuple[int, int]] = {}
    cursor = 0
    length = len(record)
    while cursor < length:
        newline = record.find(b"\n", cursor)
        line_end = length if newline < 0 else newline
        if line_end > cursor and record[line_end - 1] == 13:
            line_end -= 1
        if line_end == cursor or record.find(b"\r", cursor, line_end) >= 0:
            _refuse(EXCHANGE_ARTIFACT_MALFORMED)
        separator = record.find(b"=", cursor, line_end)
        if separator <= cursor:
            _refuse(EXCHANGE_ARTIFACT_MALFORMED)
        field = bytes(record[cursor:separator])
        if field not in {b"service", b"username", b"password"} or field in fields:
            _refuse(EXCHANGE_ARTIFACT_MALFORMED)
        fields[field] = (separator + 1, line_end)
        if newline < 0:
            cursor = length
        else:
            cursor = newline + 1
    if not {b"username", b"password"}.issubset(fields):
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    if b"service" in fields:
        service_start, service_end = fields[b"service"]
        expected_service = service_name.encode("ascii")
        if record[service_start:service_end] != expected_service:
            _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    username_start, username_end = fields[b"username"]
    password_start, password_end = fields[b"password"]
    if username_start == username_end:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    password = bytes(record[password_start:password_end]).strip()
    if not password:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    if password[0] in (ord("'"), ord('"')) and len(password) >= 2:
        quote = password[0]
        if password[-1] == quote:
            password = password[1:-1]
    if not password:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    return bytearray(password)


def _observe_exchange(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        return None


def _owned_exchange_identity(identity: os.stat_result | None) -> bool:
    return (identity is not None and stat.S_ISREG(identity.st_mode)
            and not stat.S_ISLNK(identity.st_mode) and identity.st_uid == os.geteuid()
            and stat.S_IMODE(identity.st_mode) == 0o600
            and 0 < identity.st_size <= MAX_EXCHANGE_BYTES)


def _cleanup_observed_exchange(directory_fd: int, name: str,
                               identity: os.stat_result | None,
                               return_code: int | None = None) -> None:
    if not _owned_exchange_identity(identity):
        return
    try:
        material = _read_and_remove_exchange(directory_fd, name, expected_identity=identity)
    except KeymanExportError as failure:
        if failure.signal == EXCHANGE_CLEANUP_FAILED:
            _refuse(EXCHANGE_CLEANUP_FAILED, return_code)
        return
    for index in range(len(material)):
        material[index] = 0


def _read_and_remove_exchange(directory_fd: int, name: str,
                              expected_identity: os.stat_result | None = None,
                              require_identity: bool = False) -> bytearray:
    record = bytearray()
    password: bytearray | None = None
    opened_fd: int | None = None
    identity: os.stat_result | None = None
    cleanup_authorized = False
    failure_signal: str | None = None
    try:
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            _refuse(EXPORT_FAILED)
        except OSError:
            _refuse(PREFLIGHT_UNOBSERVABLE)
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size <= 0 or before.st_size > MAX_EXCHANGE_BYTES
                or (expected_identity is not None
                    and (before.st_dev, before.st_ino)
                    != (expected_identity.st_dev, expected_identity.st_ino))
                or (require_identity and expected_identity is None)):
            _refuse(EXCHANGE_ARTIFACT_MALFORMED)
        flags = os.O_RDWR | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            opened_fd = os.open(name, flags, dir_fd=directory_fd)
            identity = os.fstat(opened_fd)
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            _refuse(EXCHANGE_ARTIFACT_RACED)
        except OSError as error:
            if error.errno == errno.ELOOP:
                _refuse(EXCHANGE_ARTIFACT_MALFORMED)
            _refuse(PREFLIGHT_UNOBSERVABLE)
        if ((not stat.S_ISREG(identity.st_mode)) or identity.st_uid != os.geteuid()
                or stat.S_IMODE(identity.st_mode) != 0o600
                or (before.st_dev, before.st_ino) != (identity.st_dev, identity.st_ino)
                or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)):
            _refuse(EXCHANGE_ARTIFACT_RACED)
        cleanup_authorized = True
        while len(record) <= MAX_EXCHANGE_BYTES:
            chunk = os.read(opened_fd, min(16384, MAX_EXCHANGE_BYTES + 1 - len(record)))
            if not chunk:
                break
            record.extend(chunk)
        after = os.fstat(opened_fd)
        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (len(record) > MAX_EXCHANGE_BYTES or after.st_size != len(record)
                or (after.st_dev, after.st_ino) != (identity.st_dev, identity.st_ino)
                or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
                or after.st_mtime_ns != identity.st_mtime_ns
                or after.st_ctime_ns != identity.st_ctime_ns):
            _refuse(EXCHANGE_ARTIFACT_RACED)
        password = _parse_credential(record, name)
    except KeymanExportError as error:
        failure_signal = error.signal
    except OSError:
        failure_signal = EXCHANGE_ARTIFACT_RACED
    finally:
        if opened_fd is not None:
            try:
                if (not cleanup_authorized or identity is None
                        or not _same_path_inode(directory_fd, name, identity)):
                    failure_signal = EXCHANGE_ARTIFACT_RACED
                else:
                    current_fd = os.fstat(opened_fd)
                    if (not stat.S_ISREG(current_fd.st_mode)
                            or (current_fd.st_dev, current_fd.st_ino) != (identity.st_dev, identity.st_ino)
                            or current_fd.st_size > MAX_EXCHANGE_BYTES):
                        failure_signal = EXCHANGE_ARTIFACT_RACED
                    else:
                        remaining = current_fd.st_size
                        os.lseek(opened_fd, 0, os.SEEK_SET)
                        zeroes = b"\x00" * min(16384, max(1, remaining))
                        while remaining:
                            chunk = zeroes[:min(len(zeroes), remaining)]
                            written = os.write(opened_fd, chunk)
                            if written <= 0:
                                raise OSError("short-scrub")
                            remaining -= written
                        os.ftruncate(opened_fd, 0)
                        os.fsync(opened_fd)
                        if not _same_path_inode(directory_fd, name, identity):
                            failure_signal = EXCHANGE_ARTIFACT_RACED
                        else:
                            os.unlink(name, dir_fd=directory_fd)
            except OSError:
                failure_signal = EXCHANGE_CLEANUP_FAILED
            finally:
                try:
                    os.close(opened_fd)
                except OSError:
                    failure_signal = EXCHANGE_CLEANUP_FAILED
        for index in range(len(record)):
            record[index] = 0
    if failure_signal is not None:
        if password is not None:
            for index in range(len(password)):
                password[index] = 0
        _refuse(failure_signal)
    if password is None:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    return password


def export_key(service_name: str, *,
               scratch_root: str | os.PathLike[str] | None = None,
               exporter: str | os.PathLike[str] | None = None) -> bytearray:
    """Export one named key into a mutable buffer; scratch overrides are Python-only."""
    if not isinstance(service_name, str) or service_name not in SERVICE_NAMES:
        _refuse(SERVICE_NAME_INVALID)
    scratch_mode = scratch_root is not None or exporter is not None
    if not scratch_mode and os.geteuid() != 0:
        _refuse(NON_ROOT)
    layout = _layout(scratch_root, exporter)
    keys_fd = skeleton_dir_fd = skeleton_fd = service_fd = named_fd = exchange_fd = None
    try:
        try:
            skeleton_dir_fd = _open_dir(layout.skeleton_dir)
            keys_fd = _open_dir(layout.keys_dir)
        except FileNotFoundError:
            _refuse(UNINITIALIZED_SYSTEM)
        skeleton = _open_key_file(skeleton_dir_fd, "skeleton.key")
        if skeleton is None:
            _refuse(UNINITIALIZED_SYSTEM)
        skeleton_fd, _skeleton_metadata = skeleton
        try:
            # This advisory lock serializes staff callers only. Native Keyman
            # exporters do not take it; inode checks refuse observable races, but
            # the shared exchange file is not an atomic child-owned return channel.
            fcntl.flock(skeleton_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not _same_path_inode(skeleton_dir_fd, "skeleton.key", os.fstat(skeleton_fd)):
                _refuse(PREFLIGHT_UNOBSERVABLE)
        except OSError:
            _refuse(PREFLIGHT_UNOBSERVABLE)
        service = _open_key_file(keys_fd, "service_suite.key")
        if service is None:
            _refuse(UNINITIALIZED_SYSTEM)
        service_fd, _service_metadata = service
        if service_name == "service_suite":
            named = service
        else:
            named = _open_key_file(keys_fd, service_name + ".key")
            if named is None:
                _refuse(MISSING_KEY)
        named_fd, _named_metadata = named
        try:
            exchange_fd = _open_dir(layout.exchange_dir)
        except FileNotFoundError:
            _refuse(PREFLIGHT_UNOBSERVABLE)
        try:
            os.stat(service_name, dir_fd=exchange_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        except OSError:
            _refuse(PREFLIGHT_UNOBSERVABLE)
        else:
            _refuse(EXCHANGE_ARTIFACT_PREEXISTING)
        if (not _same_path_inode(skeleton_dir_fd, "skeleton.key", os.fstat(skeleton_fd))
                or not _same_path_inode(keys_fd, "service_suite.key", os.fstat(service_fd))
                or not _same_path_inode(keys_fd, service_name + ".key", os.fstat(named_fd))):
            _refuse(PREFLIGHT_UNOBSERVABLE)
        child_environment = os.environ.copy()
        child_environment.pop("KEYMAN_ROOT", None)
        if layout.child_root is not None:
            child_environment["KEYMAN_ROOT"] = layout.child_root
        try:
            result = subprocess.run([layout.keyman, "export", service_name],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, env=child_environment,
                                    timeout=EXPORT_TIMEOUT_SECONDS, check=False, close_fds=True)
        except subprocess.TimeoutExpired:
            # The native timer remains authoritative. Best-effort cleanup is
            # limited to the unchanged, bounded inode observed after our child.
            _cleanup_observed_exchange(
                exchange_fd, service_name, _observe_exchange(exchange_fd, service_name))
            _refuse(EXPORT_TIMEOUT)
        except OSError:
            _refuse(EXPORT_UNAVAILABLE)
        observed_exchange = _observe_exchange(exchange_fd, service_name)
        if (not _same_path_inode(skeleton_dir_fd, "skeleton.key", os.fstat(skeleton_fd))
                or not _same_path_inode(keys_fd, "service_suite.key", os.fstat(service_fd))
                or not _same_path_inode(keys_fd, service_name + ".key", os.fstat(named_fd))):
            _cleanup_observed_exchange(exchange_fd, service_name, observed_exchange,
                                       int(result.returncode) if result.returncode != 0 else None)
            _refuse(PREFLIGHT_UNOBSERVABLE)
        if result.returncode != 0:
            # Never remove a pre-existing or replaced path. The bounded inode
            # observed after our child is eligible only for guarded cleanup.
            _cleanup_observed_exchange(exchange_fd, service_name, observed_exchange,
                                       int(result.returncode))
            if result.returncode == 1:
                _refuse(MALFORMED_KEY_FILE, int(result.returncode))
            _refuse(EXPORT_FAILED, int(result.returncode))
        return _read_and_remove_exchange(exchange_fd, service_name,
                                         expected_identity=observed_exchange,
                                         require_identity=True)
    finally:
        for fd in {item for item in (exchange_fd, named_fd, service_fd, skeleton_fd,
                                     keys_fd, skeleton_dir_fd) if item is not None}:
            try:
                os.close(fd)
            except OSError:
                pass

"""Private, root-only handoff from Keyman exchange files into mutable memory."""
from __future__ import annotations

import errno
import fcntl
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

KEYMAN = "/vault/keyman/keyman"
SERVICE_NAMES = frozenset({"nas", "nas_backup", "service_suite"})
# Credential exports (username and password) take any plain Keyman service name.
CREDENTIAL_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
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
EXCHANGE_MOUNT_FAILED = "exchange-mount-failed"
EXCHANGE_OBLITERATION_FAILED = "exchange-obliteration-failed"


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


def _dequote(value: bytes) -> bytes:
    value = value.strip()
    if value and value[0] in (ord("'"), ord('"')) and len(value) >= 2 and value[-1] == value[0]:
        value = value[1:-1]
    return value


def _parse_credential(record: bytearray, service_name: str,
                      username_out: bytearray | None = None) -> bytearray:
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
    password = _dequote(bytes(record[password_start:password_end]))
    if not password:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    if username_out is not None:
        username = _dequote(bytes(record[username_start:username_end]))
        if not username:
            _refuse(EXCHANGE_ARTIFACT_MALFORMED)
        username_out[:] = username
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
                              require_identity: bool = False,
                              username_out: bytearray | None = None) -> bytearray:
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
        if before.st_nlink != 1:
            _refuse(EXCHANGE_ARTIFACT_RACED)
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
        password = _parse_credential(record, name, username_out)
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
        if username_out is not None:
            for index in range(len(username_out)):
                username_out[index] = 0
        _refuse(failure_signal)
    if password is None:
        _refuse(EXCHANGE_ARTIFACT_MALFORMED)
    return password


@dataclass
class _Exchange:
    layout: _Layout
    scratch: bool
    parent_fd: int | None = None
    exchange_fd: int | None = None
    mount_id: str | None = None
    mount_attempted: bool = False
    reclaimed: bool = False
    underlay_identity: tuple[int, int] | None = None


class ExportedKey(bytearray):
    """Mutable key bytes with secret-free lifecycle metadata."""

    def __new__(cls, value: bytes | bytearray = b"", *, exchange_reclaimed: bool = False):
        return super().__new__(cls)

    def __init__(self, value: bytes | bytearray = b"", *, exchange_reclaimed: bool = False):
        super().__init__(value)
        self.exchange_reclaimed = bool(exchange_reclaimed)


def _mount_rows() -> list[tuple[str, str, str]] | None:
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as stream:
            lines = stream.read().splitlines()
    except (OSError, UnicodeError):
        return None
    rows: list[tuple[str, str, str]] = []
    for line in lines:
        before, separator, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not separator or len(fields) < 6 or not tail or not fields[0].isdigit():
            return None
        target = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), fields[4])
        rows.append((fields[0], target, tail[0]))
    return rows if rows else None


def _mounts_at(rows: list[tuple[str, str, str]], path: str) -> tuple[list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    exact = [row for row in rows if row[1] == path]
    nested = [row for row in rows if row[1].startswith(path.rstrip("/") + "/")]
    return exact, nested


def _open_child_directory(parent_fd: int, name: str) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    return os.open(name, flags, dir_fd=parent_fd)


def _silent_command(argv: list[str]) -> tuple[bool, int | None]:
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False, close_fds=True)
    except OSError:
        return False, None
    return result.returncode == 0, int(result.returncode)


def _exchange_parent(state: _Exchange) -> int:
    try:
        if state.scratch:
            assert state.layout.child_root is not None
            root_fd = _open_dir(state.layout.child_root)
            try:
                root_stat = os.fstat(root_fd)
                if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != os.geteuid():
                    _refuse(SCRATCH_CONTEXT_INVALID)
            finally:
                os.close(root_fd)
            parent_fd = _open_dir(os.path.dirname(state.layout.exchange_dir))
            parent_stat = os.fstat(parent_fd)
            if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.geteuid():
                os.close(parent_fd)
                _refuse(SCRATCH_CONTEXT_INVALID)
            return parent_fd
        parent_fd = _open_dir("/mnt")
        parent_stat = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != 0:
            os.close(parent_fd)
            _refuse(EXCHANGE_MOUNT_FAILED)
        return parent_fd
    except KeymanExportError:
        raise
    except OSError:
        _refuse(SCRATCH_CONTEXT_INVALID if state.scratch else EXCHANGE_MOUNT_FAILED)


def _entry_stat(parent_fd: int) -> os.stat_result | None:
    try:
        return os.stat("keyexchange", dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError:
        raise


def _scrub_regular(parent_fd: int, name: str, before: os.stat_result) -> bool:
    """Zero an unaliased inode; unlink only this name for multiply-linked files."""
    if before.st_nlink != 1:
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                return False
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            return False
        return False
    flags = os.O_WRONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = None
    try:
        fd = os.open(name, flags, dir_fd=parent_fd)
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            if opened.st_nlink > 1 and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino):
                os.close(fd)
                fd = None
                current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino):
                    os.unlink(name, dir_fd=parent_fd)
            return False
        remaining = opened.st_size
        zeroes = b"\x00" * 4096
        os.lseek(fd, 0, os.SEEK_SET)
        while remaining:
            count = os.write(fd, zeroes[:min(len(zeroes), remaining)])
            if count <= 0:
                return False
            remaining -= count
        os.ftruncate(fd, 0)
        os.fsync(fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)):
            return False
        os.unlink(name, dir_fd=parent_fd)
        return True
    except OSError:
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        # Even when zeroing cannot be established, remove only the still-identical
        # directory entry so final teardown can continue without touching aliases.
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (before.st_dev, before.st_ino):
                os.unlink(name, dir_fd=parent_fd)
        except OSError:
            pass


def _scrub_tree(directory_fd: int, root_device: int, path: str) -> bool:
    safe = True
    try:
        names = os.listdir(directory_fd)
    except OSError:
        return False
    for name in names:
        child_path = os.path.join(path, name)
        rows = _mount_rows()
        if rows is None:
            safe = False
            continue
        exact, nested = _mounts_at(rows, child_path)
        if exact or nested:
            safe = False
            continue
        try:
            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            safe = False
            continue
        if before.st_dev != root_device:
            safe = False
            continue
        if stat.S_ISREG(before.st_mode):
            safe = _scrub_regular(directory_fd, name, before) and safe
            continue
        if stat.S_ISDIR(before.st_mode) and not stat.S_ISLNK(before.st_mode):
            child_fd = None
            try:
                child_fd = _open_child_directory(directory_fd, name)
                opened = os.fstat(child_fd)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                        or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
                        or opened.st_dev != root_device):
                    safe = False
                    continue
                safe = _scrub_tree(child_fd, root_device, child_path) and safe
            except OSError:
                safe = False
                continue
            finally:
                if child_fd is not None:
                    try:
                        os.close(child_fd)
                    except OSError:
                        safe = False
            try:
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                    safe = False
                else:
                    os.rmdir(name, dir_fd=directory_fd)
            except OSError:
                safe = False
            continue
        # A symlink is unlinked as a directory entry only; its target is never opened.
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                safe = False
            else:
                os.unlink(name, dir_fd=directory_fd)
        except OSError:
            safe = False
    return safe


def _remove_exchange_entry(state: _Exchange, *, expected_uid: int) -> bool:
    assert state.parent_fd is not None
    parent_fd = state.parent_fd
    path = state.layout.exchange_dir
    rows = _mount_rows()
    if rows is None:
        return False
    exact, nested = _mounts_at(rows, path)
    if nested:
        return False
    entry = _entry_stat(parent_fd)
    if entry is None:
        return not exact
    if stat.S_ISLNK(entry.st_mode):
        if exact:
            return False
        try:
            current = _entry_stat(parent_fd)
            if current is None:
                return True
            if (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino):
                return False
            os.unlink("keyexchange", dir_fd=parent_fd)
            return _entry_stat(parent_fd) is None
        except OSError:
            return False
    if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != expected_uid:
        return False
    if exact:
        if state.scratch or len(exact) != 1 or exact[0][2] != "tmpfs":
            return False
        if state.mount_id is None:
            if not state.mount_attempted:
                return False
            state.mount_id = exact[0][0]
        if exact[0][0] != state.mount_id:
            return False
    elif state.underlay_identity is not None and (entry.st_dev, entry.st_ino) != state.underlay_identity:
        return False
    fd = None
    safe = True
    try:
        fd = _open_child_directory(parent_fd, "keyexchange")
        opened = os.fstat(fd)
        current = os.stat("keyexchange", dir_fd=parent_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino)
                or (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_uid != expected_uid):
            safe = False
        else:
            safe = _scrub_tree(fd, opened.st_dev, path)
    except OSError:
        safe = False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                safe = False
    if exact:
        rows = _mount_rows()
        if rows is None:
            return False
        current_exact, nested = _mounts_at(rows, path)
        if nested or len(current_exact) != 1 or current_exact[0][0] != state.mount_id:
            return False
        okay, _ = _silent_command(["/usr/bin/umount", path])
        if not okay:
            return False
        rows = _mount_rows()
        if rows is None:
            return False
        current_exact, nested = _mounts_at(rows, path)
        if current_exact or nested:
            return False
        # The directory beneath a former tmpfs mount is still part of this exact exchange path.
        entry = _entry_stat(parent_fd)
        if entry is None or stat.S_ISLNK(entry.st_mode) or not stat.S_ISDIR(entry.st_mode):
            return False
        if entry.st_uid != expected_uid:
            return False
        if (state.underlay_identity is not None
                and (entry.st_dev, entry.st_ino) != state.underlay_identity):
            return False
        try:
            fd = _open_child_directory(parent_fd, "keyexchange")
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino)
                    or opened.st_uid != expected_uid):
                safe = False
            else:
                safe = _scrub_tree(fd, opened.st_dev, path) and safe
        except OSError:
            safe = False
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    safe = False
                fd = None
    if not safe:
        # Continue to remove the exact empty directory when possible, but report that
        # complete zeroing could not be established (for example, an external hard link).
        try:
            current = os.stat("keyexchange", dir_fd=parent_fd, follow_symlinks=False)
            if (stat.S_ISDIR(current.st_mode) and current.st_uid == expected_uid
                    and (current.st_dev, current.st_ino) == (entry.st_dev, entry.st_ino)):
                os.rmdir("keyexchange", dir_fd=parent_fd)
        except OSError:
            pass
        return False
    try:
        current = os.stat("keyexchange", dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (entry.st_dev, entry.st_ino):
            return False
        os.rmdir("keyexchange", dir_fd=parent_fd)
    except OSError:
        return False
    return _entry_stat(parent_fd) is None


def _obliterate_exchange(state: _Exchange) -> None:
    if state.parent_fd is None:
        return
    if state.exchange_fd is not None:
        rows = _mount_rows()
        if rows is None:
            safe = False
        else:
            _exact, nested = _mounts_at(rows, state.layout.exchange_dir)
            safe = not nested
        if safe:
            try:
                opened = os.fstat(state.exchange_fd)
                safe = _scrub_tree(state.exchange_fd, opened.st_dev, state.layout.exchange_dir)
            except OSError:
                safe = False
        try:
            os.close(state.exchange_fd)
        except OSError:
            safe = False
        state.exchange_fd = None
        if not safe:
            # Still attempt the guarded mount teardown and exact directory removal below.
            cleanup_safe = False
        else:
            cleanup_safe = True
    else:
        cleanup_safe = True
    expected_uid = os.geteuid() if state.scratch else 0
    entry = _entry_stat(state.parent_fd)
    rows = _mount_rows()
    if rows is None:
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    exact, nested = _mounts_at(rows, state.layout.exchange_dir)
    if nested:
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    if exact:
        if state.scratch or len(exact) != 1 or exact[0][2] != "tmpfs":
            _refuse(EXCHANGE_OBLITERATION_FAILED)
        if state.mount_id is None:
            if not state.mount_attempted:
                _refuse(EXCHANGE_OBLITERATION_FAILED)
            state.mount_id = exact[0][0]
        if exact[0][0] != state.mount_id:
            _refuse(EXCHANGE_OBLITERATION_FAILED)
    if entry is not None and (not stat.S_ISDIR(entry.st_mode) or entry.st_uid != expected_uid):
        if not (stat.S_ISLNK(entry.st_mode) and not exact):
            _refuse(EXCHANGE_OBLITERATION_FAILED)
    if entry is not None or exact:
        if not _remove_exchange_entry(state, expected_uid=expected_uid):
            _refuse(EXCHANGE_OBLITERATION_FAILED)
    rows = _mount_rows()
    if rows is None:
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    exact, nested = _mounts_at(rows, state.layout.exchange_dir)
    if exact or nested or _entry_stat(state.parent_fd) is not None or not cleanup_safe:
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    state.mount_id = None
    state.mount_attempted = False
    state.underlay_identity = None


def _begin_exchange(state: _Exchange) -> None:
    state.parent_fd = _exchange_parent(state)
    path = state.layout.exchange_dir
    rows = _mount_rows()
    if rows is None:
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    exact, nested = _mounts_at(rows, path)
    entry = _entry_stat(state.parent_fd)
    if nested or (exact and entry is None):
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    if entry is not None:
        state.reclaimed = True
        if exact:
            if state.scratch or len(exact) != 1 or exact[0][2] != "tmpfs":
                _refuse(EXCHANGE_OBLITERATION_FAILED)
            state.mount_id = exact[0][0]
        _obliterate_exchange(state)
    elif exact:
        _refuse(EXCHANGE_OBLITERATION_FAILED)
    try:
        os.mkdir("keyexchange", 0o700, dir_fd=state.parent_fd)
    except OSError:
        _refuse(SCRATCH_CONTEXT_INVALID if state.scratch else EXCHANGE_MOUNT_FAILED)
    expected_uid = os.geteuid() if state.scratch else 0
    try:
        created = _entry_stat(state.parent_fd)
    except OSError:
        _refuse(SCRATCH_CONTEXT_INVALID if state.scratch else EXCHANGE_MOUNT_FAILED)
    if (created is None or stat.S_ISLNK(created.st_mode) or not stat.S_ISDIR(created.st_mode)
            or created.st_uid != expected_uid):
        _refuse(SCRATCH_CONTEXT_INVALID if state.scratch else EXCHANGE_MOUNT_FAILED)
    state.underlay_identity = (created.st_dev, created.st_ino)
    try:
        if stat.S_IMODE(created.st_mode) != 0o700:
            os.chmod("keyexchange", 0o700, dir_fd=state.parent_fd, follow_symlinks=False)
        created = _entry_stat(state.parent_fd)
    except (OSError, NotImplementedError):
        _refuse(SCRATCH_CONTEXT_INVALID if state.scratch else EXCHANGE_MOUNT_FAILED)
    if (created is None or stat.S_ISLNK(created.st_mode) or not stat.S_ISDIR(created.st_mode)
            or (created.st_dev, created.st_ino) != state.underlay_identity
            or created.st_uid != expected_uid or stat.S_IMODE(created.st_mode) != 0o700):
        _refuse(SCRATCH_CONTEXT_INVALID if state.scratch else EXCHANGE_MOUNT_FAILED)
    if state.scratch:
        rows = _mount_rows()
        if rows is None:
            _refuse(SCRATCH_CONTEXT_INVALID)
        exact, nested = _mounts_at(rows, path)
        if exact or nested:
            _refuse(SCRATCH_CONTEXT_INVALID)
        try:
            state.exchange_fd = _open_child_directory(state.parent_fd, "keyexchange")
            opened = os.fstat(state.exchange_fd)
            current = os.stat("keyexchange", dir_fd=state.parent_fd, follow_symlinks=False)
            if ((opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)
                    or (opened.st_dev, opened.st_ino) != state.underlay_identity
                    or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o700):
                _refuse(SCRATCH_CONTEXT_INVALID)
        except OSError:
            _refuse(SCRATCH_CONTEXT_INVALID)
        return
    state.mount_attempted = True
    okay, _ = _silent_command(["/usr/bin/mount", "-t", "tmpfs", "-o",
                               "size=1m,mode=0700", "tmpfs", path])
    rows = _mount_rows()
    if rows is None:
        _refuse(EXCHANGE_MOUNT_FAILED)
    exact, nested = _mounts_at(rows, path)
    if len(exact) == 1 and exact[0][2] == "tmpfs":
        state.mount_id = exact[0][0]
    if not okay or len(exact) != 1 or exact[0][2] != "tmpfs" or nested:
        _refuse(EXCHANGE_MOUNT_FAILED)
    try:
        # The exact mountinfo tmpfs confirmation above precedes this dirfd open.
        state.exchange_fd = _open_child_directory(state.parent_fd, "keyexchange")
        opened = os.fstat(state.exchange_fd)
        current_rows = _mount_rows()
        if current_rows is None:
            _refuse(EXCHANGE_MOUNT_FAILED)
        current_exact, current_nested = _mounts_at(current_rows, path)
        current = os.stat("keyexchange", dir_fd=state.parent_fd, follow_symlinks=False)
        if (len(current_exact) != 1 or current_exact[0][0] != state.mount_id
                or current_exact[0][2] != "tmpfs" or current_nested
                or not stat.S_ISDIR(opened.st_mode) or opened.st_uid != 0
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino)):
            _refuse(EXCHANGE_MOUNT_FAILED)
    except OSError:
        _refuse(EXCHANGE_MOUNT_FAILED)


def export_key(service_name: str, *,
               scratch_root: str | os.PathLike[str] | None = None,
               exporter: str | os.PathLike[str] | None = None) -> ExportedKey:
    """Export one named key into mutable memory through a per-call exchange."""
    if not isinstance(service_name, str) or service_name not in SERVICE_NAMES:
        _refuse(SERVICE_NAME_INVALID)
    return _export(service_name, scratch_root, exporter, None)


def export_credential(service_name: str, *,
                      scratch_root: str | os.PathLike[str] | None = None,
                      exporter: str | os.PathLike[str] | None = None) -> tuple[ExportedKey, ExportedKey]:
    """Export one service's username and password through the same per-call exchange."""
    if not isinstance(service_name, str) or not CREDENTIAL_NAME.fullmatch(service_name):
        _refuse(SERVICE_NAME_INVALID)
    username = ExportedKey()
    try:
        password = _export(service_name, scratch_root, exporter, username)
    except BaseException:
        for index in range(len(username)):
            username[index] = 0
        raise
    username.exchange_reclaimed = password.exchange_reclaimed
    return username, password


def _export(service_name: str, scratch_root: str | os.PathLike[str] | None,
            exporter: str | os.PathLike[str] | None,
            username_out: bytearray | None) -> ExportedKey:
    scratch_mode = scratch_root is not None or exporter is not None
    if not scratch_mode and os.geteuid() != 0:
        _refuse(NON_ROOT)
    layout = _layout(scratch_root, exporter)
    state = _Exchange(layout, scratch_mode)
    keys_fd = skeleton_dir_fd = skeleton_fd = service_fd = named_fd = None
    result_secret: ExportedKey | None = None
    parsed_material: bytearray | None = None
    cleanup_failed = False
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
            fcntl.flock(skeleton_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if not _same_path_inode(skeleton_dir_fd, "skeleton.key", os.fstat(skeleton_fd)):
                _refuse(PREFLIGHT_UNOBSERVABLE)
        except OSError:
            _refuse(PREFLIGHT_UNOBSERVABLE)
        _begin_exchange(state)
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
        exchange_fd = state.exchange_fd
        if exchange_fd is None:
            _refuse(EXCHANGE_MOUNT_FAILED)
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
            _cleanup_observed_exchange(exchange_fd, service_name, observed_exchange,
                                       int(result.returncode))
            if result.returncode == 1:
                _refuse(MALFORMED_KEY_FILE, int(result.returncode))
            _refuse(EXPORT_FAILED, int(result.returncode))
        parsed_material = _read_and_remove_exchange(exchange_fd, service_name,
                                                    expected_identity=observed_exchange,
                                                    require_identity=True,
                                                    username_out=username_out)
        result_secret = ExportedKey(parsed_material, exchange_reclaimed=state.reclaimed)
        for index in range(len(parsed_material)):
            parsed_material[index] = 0
        return result_secret
    finally:
        try:
            _obliterate_exchange(state)
        except BaseException:
            cleanup_failed = True
        if parsed_material is not None:
            for index in range(len(parsed_material)):
                parsed_material[index] = 0
        if cleanup_failed and result_secret is not None:
            for index in range(len(result_secret)):
                result_secret[index] = 0
        for fd in {item for item in (named_fd, service_fd, keys_fd, skeleton_dir_fd,
                                     state.parent_fd) if item is not None}:
            try:
                os.close(fd)
            except OSError:
                pass
        # The skeleton descriptor is the staff serialization lock and closes last.
        if skeleton_fd is not None:
            try:
                os.close(skeleton_fd)
            except OSError:
                pass
        if cleanup_failed:
            _refuse(EXCHANGE_OBLITERATION_FAILED)

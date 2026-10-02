"""Converge the owner passwordless-sudo fragment."""
from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import sys
from typing import Sequence

from agathodaimon._envelope import EnvelopeError, attach, read

_SCHEMA = "agathodaimon.appliance.sudo-passwordless.v1"
_DIRECTORY = "/etc/sudoers.d"
_TARGET = "owner-nopasswd"
_PATH = f"{_DIRECTORY}/{_TARGET}"
_FRAGMENT = b"owner ALL=(ALL:ALL) NOPASSWD: ALL\n"
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | _NOFOLLOW | _CLOEXEC
_FILE_FLAGS = os.O_RDONLY | _NOFOLLOW | _CLOEXEC
_TEMP_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC


class _VisudoRefused(Exception):
    """The candidate sudoers fragment did not pass visudo."""


def _open_sudoers_directory() -> int:
    """Open the fixed parent through no-follow directory descriptors."""
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for component in ("etc", "sudoers.d"):
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise OSError("unsafe sudoers directory")
            following = os.open(component, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = following
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise OSError("unsafe sudoers directory")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _lstat_present(directory_fd: int) -> bool:
    try:
        os.stat(_TARGET, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    return True


def _metadata_is_exact(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == 0
        and metadata.st_gid == 0
        and stat.S_IMODE(metadata.st_mode) == 0o440
    )


def _fragment_is_exact(directory_fd: int) -> bool:
    """Read only the named leaf, refusing symlinks and inode races."""
    try:
        before = os.stat(_TARGET, dir_fd=directory_fd, follow_symlinks=False)
        if not _metadata_is_exact(before):
            return False
        descriptor = os.open(_TARGET, _FILE_FLAGS, dir_fd=directory_fd)
    except OSError:
        return False
    try:
        after = os.fstat(descriptor)
        if (
            (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or not _metadata_is_exact(after)
        ):
            return False
        content = bytearray()
        while len(content) <= len(_FRAGMENT):
            block = os.read(descriptor, len(_FRAGMENT) + 1 - len(content))
            if not block:
                break
            content.extend(block)
        return bytes(content) == _FRAGMENT
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _readback(directory_fd: int | None, *, inspect_fragment: bool) -> tuple[bool | None, bool | None]:
    if directory_fd is None:
        return None, None
    try:
        present = _lstat_present(directory_fd)
    except OSError:
        return None, None
    if not present:
        return False, False
    if inspect_fragment:
        return (True if _fragment_is_exact(directory_fd) else None), True
    return True, True


def _emit(
    *,
    ok: bool,
    passwordless: bool | None,
    fragment_present: bool | None,
    changed: bool,
    signal: str,
    request,
) -> int:
    receipt = {
        "schema": _SCHEMA,
        "ok": ok,
        "passwordless": passwordless,
        "fragment_present": fragment_present,
        "changed": changed,
        "path": _PATH,
        "firstMissingSignal": signal,
    }
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if ok else 1


def _failure(signal: str, request, directory_fd: int | None, changed: bool) -> int:
    passwordless, present = _readback(directory_fd, inspect_fragment=True)
    return _emit(
        ok=False,
        passwordless=passwordless,
        fragment_present=present,
        changed=changed,
        signal=f"agathodaimon-sudo-passwordless-{signal}",
        request=request,
    )


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short sudoers fragment write")
        view = view[written:]


def _install_fragment(directory_fd: int) -> None:
    temporary_name = None
    descriptor = None
    try:
        for _ in range(16):
            candidate = f".{_TARGET}.{secrets.token_hex(8)}.tmp"
            try:
                descriptor = os.open(candidate, _TEMP_FLAGS, 0o600, dir_fd=directory_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if descriptor is None or temporary_name is None:
            raise OSError("could not create sudoers temporary file")

        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o440)
        _write_all(descriptor, _FRAGMENT)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None

        try:
            result = subprocess.run(
                ["/usr/sbin/visudo", "-cf", f"{_DIRECTORY}/{temporary_name}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise _VisudoRefused from exc
        if result.returncode != 0:
            raise _VisudoRefused

        os.replace(
            temporary_name,
            _TARGET,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        temporary_name = None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass


def _read_only(request) -> int:
    try:
        directory_fd = _open_sudoers_directory()
    except OSError:
        return _failure("write-failed", request, None, False)
    try:
        try:
            present = _lstat_present(directory_fd)
        except OSError:
            return _failure("write-failed", request, directory_fd, False)
        return _emit(
            ok=True,
            passwordless=present,
            fragment_present=present,
            changed=False,
            signal="none",
            request=request,
        )
    finally:
        os.close(directory_fd)


def _converge(passwordless: bool, request) -> int:
    try:
        directory_fd = _open_sudoers_directory()
    except OSError:
        return _failure("write-failed", request, None, False)

    changed = False
    try:
        if passwordless:
            if not _fragment_is_exact(directory_fd):
                try:
                    _install_fragment(directory_fd)
                except _VisudoRefused:
                    return _failure("visudo-refused", request, directory_fd, changed)
                changed = True
                os.fsync(directory_fd)
            try:
                present = _lstat_present(directory_fd)
            except OSError:
                return _failure("write-failed", request, directory_fd, changed)
            if not present or not _fragment_is_exact(directory_fd):
                return _failure("write-failed", request, directory_fd, changed)
            return _emit(
                ok=True,
                passwordless=True,
                fragment_present=True,
                changed=changed,
                signal="none",
                request=request,
            )

        try:
            present = _lstat_present(directory_fd)
        except OSError:
            return _failure("write-failed", request, directory_fd, changed)
        if present:
            try:
                os.unlink(_TARGET, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            else:
                changed = True
                os.fsync(directory_fd)
        try:
            present = _lstat_present(directory_fd)
        except OSError:
            return _failure("write-failed", request, directory_fd, changed)
        if present:
            return _failure("write-failed", request, directory_fd, changed)
        return _emit(
            ok=True,
            passwordless=False,
            fragment_present=False,
            changed=changed,
            signal="none",
            request=request,
        )
    except OSError:
        return _failure("write-failed", request, directory_fd, changed)
    finally:
        os.close(directory_fd)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    request = None
    request_valid = True
    try:
        request = read(known_fields=("passwordless", "op"))
    except (EnvelopeError, OSError, UnicodeError, ValueError):
        request_valid = False

    if os.geteuid() != 0:
        return _emit(
            ok=False,
            passwordless=None,
            fragment_present=None,
            changed=False,
            signal="agathodaimon-sudo-passwordless-root-required",
            request=request,
        )
    if not request_valid or args or request is None:
        return _emit(
            ok=False,
            passwordless=None,
            fragment_present=None,
            changed=False,
            signal="agathodaimon-sudo-passwordless-payload-invalid",
            request=request,
        )

    payload = request.payload
    if "op" in payload:
        if payload.get("op") != "read" or "passwordless" in payload:
            return _failure("payload-invalid", request, None, False)
        return _read_only(request)
    value = payload.get("passwordless")
    if "passwordless" not in payload or type(value) is not bool:
        return _failure("payload-invalid", request, None, False)
    return _converge(value, request)


if __name__ == "__main__":
    raise SystemExit(main())

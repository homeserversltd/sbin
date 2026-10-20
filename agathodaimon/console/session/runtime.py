"""Arcadia OS owner-runtime selector and Steam power sentinels."""
from __future__ import annotations

import fcntl
import os
import pwd
import secrets
import stat
from pathlib import Path
from typing import Iterator
from contextlib import contextmanager

OWNER = "owner"
SELECTOR_NAME = "ARCADIA_CONSOLE_SESSION"
SHUTDOWN_SENTINEL = "STEAMOS_STEAM_SHUTDOWN_SENTINEL"
REBOOT_SENTINEL = "STEAMOS_STEAM_REBOOT_SENTINEL"
SELECTOR_LOCK = "ARCADIA_CONSOLE_SESSION.lock"
MODES = frozenset({"desktop", "steam"})


def owner_account() -> pwd.struct_passwd:
    try:
        account = pwd.getpwnam(OWNER)
    except KeyError as error:
        raise ValueError("console-owner-account-missing") from error
    if account.pw_uid == 0:
        raise ValueError("console-owner-identity-invalid")
    return account


def root_path() -> Path:
    raw = os.environ.get("CADUCEUS_ROOT", "/")
    root = Path(raw)
    if (
        not root.is_absolute()
        or any(part in {".", ".."} for part in raw.split("/") if part)
        or "\x00" in raw
    ):
        raise ValueError("console-runtime-root-invalid")
    return root


def runtime_path() -> Path:
    account = owner_account()
    return root_path() / "run" / "user" / str(account.pw_uid)


def open_rooted_directory(parts: tuple[str, ...]) -> tuple[int, Path]:
    """Open a directory beneath CADUCEUS_ROOT without following symlinks."""
    root = root_path()
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open("/", flags)
    try:
        for part in (*root.parts[1:], *parts):
            if not part or part in {".", ".."} or "/" in part or "\x00" in part:
                raise ValueError("console-runtime-path-invalid")
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, root.joinpath(*parts)
    except BaseException:
        os.close(descriptor)
        raise


def open_runtime() -> tuple[int, Path, pwd.struct_passwd]:
    account = owner_account()
    if os.geteuid() not in (0, account.pw_uid):
        raise ValueError("console-owner-runtime-identity-refused")
    descriptor, path = open_rooted_directory(("run", "user", str(account.pw_uid)))
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != account.pw_uid
        or metadata.st_mode & 0o077
    ):
        os.close(descriptor)
        raise ValueError("console-owner-runtime-directory-unsafe")
    return descriptor, path, account


def session_environment_updates() -> dict[str, str]:
    """Expose Steam power sentinels and a scratch-rooted runtime directory."""
    root = root_path()
    runtime = runtime_path()
    updates = {
        SHUTDOWN_SENTINEL: str(runtime / SHUTDOWN_SENTINEL),
        REBOOT_SENTINEL: str(runtime / REBOOT_SENTINEL),
    }
    if root != Path("/"):
        updates["XDG_RUNTIME_DIR"] = str(runtime)
    return updates


def read_selector(directory_fd: int, owner_uid: int) -> str | None:
    try:
        descriptor = os.open(
            SELECTOR_NAME,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except FileNotFoundError:
        return None
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != owner_uid
            or metadata.st_mode & 0o077
            or metadata.st_size > 16
        ):
            raise ValueError("console-session-selector-unsafe")
        raw = os.read(descriptor, 17)
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError("console-session-selector-invalid") from error
    if value not in MODES or raw not in (b"desktop\n", b"steam\n", b"desktop", b"steam"):
        raise ValueError("console-session-selector-invalid")
    return value


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise OSError("console-selector-write-short")
        view = view[count:]


def atomic_write_selector(directory_fd: int, owner: pwd.struct_passwd, value: str) -> None:
    if value not in MODES:
        raise ValueError("console-session-selector-invalid")
    temporary = f".{SELECTOR_NAME}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("console-session-selector-temp-unsafe")
        if os.geteuid() == 0:
            os.fchown(descriptor, owner.pw_uid, owner.pw_gid)
        elif metadata.st_uid != owner.pw_uid:
            raise ValueError("console-session-selector-custody-failed")
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, (value + "\n").encode("ascii"))
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    os.close(descriptor)
    try:
        os.replace(
            temporary,
            SELECTOR_NAME,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except OSError:
            pass
        raise


def restore_selector(directory_fd: int, owner: pwd.struct_passwd, previous: str | None) -> None:
    if previous is None:
        try:
            os.unlink(SELECTOR_NAME, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.fsync(directory_fd)
    else:
        atomic_write_selector(directory_fd, owner, previous)


@contextmanager
def selector_lock(directory_fd: int, owner: pwd.struct_passwd) -> Iterator[None]:
    descriptor = os.open(
        SELECTOR_LOCK,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("console-session-selector-lock-unsafe")
        if os.geteuid() == 0:
            os.fchown(descriptor, owner.pw_uid, owner.pw_gid)
            os.fchmod(descriptor, 0o600)
        elif metadata.st_uid != owner.pw_uid or metadata.st_mode & 0o077:
            raise ValueError("console-session-selector-lock-custody-failed")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def consume_power_sentinels(directory_fd: int) -> set[str]:
    consumed: set[str] = set()
    for name in (SHUTDOWN_SENTINEL, REBOOT_SENTINEL):
        try:
            os.unlink(name, dir_fd=directory_fd)
        except FileNotFoundError:
            continue
        consumed.add(name)
    if consumed:
        os.fsync(directory_fd)
    return consumed

"""Arcadia OS owner-runtime directory custody."""
from __future__ import annotations

import os
import pwd
import stat
from pathlib import Path

OWNER = "owner"


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
    """Use the rooted owner runtime directory for isolated session launches."""
    if root_path() != Path("/"):
        return {"XDG_RUNTIME_DIR": str(runtime_path())}
    return {}

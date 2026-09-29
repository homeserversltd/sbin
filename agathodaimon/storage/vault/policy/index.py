"""Root-owned Keyman vault policy writer for the mounted mapper."""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from typing import Any, Sequence

_SCHEMA = "caduceus.vault.policy-write.v1"
_POLICY_SCHEMA = "caduceus.vault_policy.v1"
_POLICY_MODE = "separate_luks_vault"
_POLICY_NAME = ".keyman-vault-policy.json"
_MAPPER = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_UNLOCKS = {"crypttab_keyfile", "manual_passphrase"}
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")


def _receipt(ok: bool, mountpoint: str | None, signal: str) -> dict[str, Any]:
    return {
        "schema": _SCHEMA,
        "ok": ok,
        "mountpoint": mountpoint,
        "firstMissingSignal": signal,
    }


def _decode_mountinfo(value: str) -> str:
    return _OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _find_mountpoint(mapper_path: str, mapper_stat: os.stat_result) -> str | None:
    mapper_realpath = os.path.realpath(mapper_path)
    mapper_device = None
    if stat.S_ISBLK(mapper_stat.st_mode):
        mapper_device = f"{os.major(mapper_stat.st_rdev)}:{os.minor(mapper_stat.st_rdev)}"

    matches: list[str] = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as mountinfo:
            lines = mountinfo.readlines()
    except (OSError, UnicodeError):
        return None

    for line in lines:
        before, separator, after = line.partition(" - ")
        if not separator:
            continue
        fields = before.split()
        post_fields = after.split()
        if len(fields) < 5 or len(post_fields) < 2:
            continue
        source = _decode_mountinfo(post_fields[1])
        device_match = mapper_device is not None and fields[2] == mapper_device
        source_match = source.startswith("/") and os.path.realpath(source) == mapper_realpath
        if device_match or source_match:
            mountpoint = _decode_mountinfo(fields[4])
            if mountpoint.startswith("/"):
                matches.append(mountpoint)

    return matches[0] if len(matches) == 1 else None


def _read_policy(parent_fd: int) -> tuple[dict[str, Any], os.stat_result] | None:
    try:
        fd = os.open(
            _POLICY_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError:
        return None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            return None
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)

    try:
        document = json.loads(b"".join(chunks).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if (
        not isinstance(document, dict)
        or document.get("schema") != _POLICY_SCHEMA
        or document.get("mode") != _POLICY_MODE
    ):
        return None
    return document, metadata


def _write_all(fd: int, content: bytes) -> None:
    remaining = memoryview(content)
    while remaining:
        count = os.write(fd, remaining)
        if count <= 0:
            raise OSError("vault-policy-short-write")
        remaining = remaining[count:]


def _same_snapshot(before: os.stat_result, current: os.stat_result) -> bool:
    return (
        stat.S_ISREG(current.st_mode)
        and before.st_dev == current.st_dev
        and before.st_ino == current.st_ino
        and before.st_mode == current.st_mode
        and before.st_uid == current.st_uid
        and before.st_gid == current.st_gid
        and before.st_size == current.st_size
        and before.st_mtime_ns == current.st_mtime_ns
        and before.st_ctime_ns == current.st_ctime_ns
    )


def _install_policy(parent_fd: int, document: dict[str, Any], metadata: os.stat_result) -> None:
    encoded = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    temporary: str | None = None
    temporary_fd: int | None = None
    try:
        for _attempt in range(32):
            candidate = f".{_POLICY_NAME}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd is None or temporary is None:
            raise OSError("vault-policy-temp-create-failed")

        os.fchown(temporary_fd, metadata.st_uid, metadata.st_gid)
        os.fchmod(temporary_fd, stat.S_IMODE(metadata.st_mode))
        _write_all(temporary_fd, encoded)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        current = os.stat(_POLICY_NAME, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_snapshot(metadata, current):
            raise OSError("vault-policy-document-changed")
        os.replace(temporary, _POLICY_NAME, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except FileNotFoundError:
                pass


def _apply(mapper: str, unlock: str) -> dict[str, Any]:
    mapper_path = f"/dev/mapper/{mapper}"
    try:
        mapper_stat = os.stat(mapper_path)
    except OSError:
        return _receipt(False, None, "vault-policy-mapper-not-open")

    mountpoint = _find_mountpoint(mapper_path, mapper_stat)
    if mountpoint is None:
        return _receipt(False, None, "vault-policy-mountpoint-ambiguous")

    parent_fd: int | None = None
    try:
        parent_fd = os.open(
            mountpoint,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
            return _receipt(False, mountpoint, "vault-policy-write-failed")
    except OSError:
        if parent_fd is not None:
            os.close(parent_fd)
        return _receipt(False, mountpoint, "vault-policy-write-failed")

    try:
        loaded = _read_policy(parent_fd)
        if loaded is None:
            return _receipt(False, mountpoint, "vault-policy-document-invalid")
        document, metadata = loaded
        document["unlock"] = unlock
        try:
            _install_policy(parent_fd, document, metadata)
        except (OSError, ValueError, TypeError):
            return _receipt(False, mountpoint, "vault-policy-write-failed")
        return _receipt(True, mountpoint, "none")
    finally:
        os.close(parent_fd)


def _dispatch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _receipt(False, None, "vault-policy-mapper-invalid")
    payload = value.get("payload") if "schema" in value else value
    if not isinstance(payload, dict):
        return _receipt(False, None, "vault-policy-mapper-invalid")
    if set(payload) != {"mapper", "unlock"}:
        if "mapper" not in payload or set(payload) - {"mapper", "unlock"}:
            return _receipt(False, None, "vault-policy-mapper-invalid")
        return _receipt(False, None, "vault-policy-unlock-invalid")

    mapper = payload.get("mapper")
    if not isinstance(mapper, str) or _MAPPER.fullmatch(mapper) is None:
        return _receipt(False, None, "vault-policy-mapper-invalid")
    unlock = payload.get("unlock")
    if not isinstance(unlock, str) or unlock not in _UNLOCKS:
        return _receipt(False, None, "vault-policy-unlock-invalid")
    return _apply(mapper, unlock)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        value = json.load(sys.stdin)
    except Exception:
        receipt = _receipt(False, None, "vault-policy-mapper-invalid")
    else:
        try:
            receipt = _dispatch(value)
        except Exception:
            receipt = _receipt(False, None, "vault-policy-write-failed")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

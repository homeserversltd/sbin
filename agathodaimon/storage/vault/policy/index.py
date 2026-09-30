"""Root-owned Keyman vault policy writer for the mounted mapper."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from typing import Any, Sequence

_SCHEMA = "caduceus.vault.policy-write.v1"
_POLICY_SCHEMA = "caduceus.vault_policy.v1"
_POLICY_MODE = "separate_luks_vault"
_POLICY_NAME = ".keyman-vault-policy.json"
_MAPPER = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_UNLOCKS = {"crypttab_keyfile", "manual_passphrase"}
_OCTAL_ESCAPE = re.compile(r"\\([0-7]{3})")


def _receipt(
    ok: bool,
    op: str | None,
    mountpoint: str | None,
    unlock: str | None,
    signal: str,
    *,
    crypttab_changed: bool = False,
    crypttab_restored: bool | None = None,
) -> dict[str, Any]:
    receipt = {
        "schema": _SCHEMA,
        "ok": ok,
        "op": op,
        "mountpoint": mountpoint,
        "unlock": unlock,
        "firstMissingSignal": signal,
    }
    if op == "write":
        receipt["crypttab"] = {"changed": crypttab_changed}
    if crypttab_restored is not None:
        receipt["crypttabRestored"] = crypttab_restored
    return receipt


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


class _CrypttabWriteError(OSError):
    def __init__(self, message: str, changed: bool = False, snapshot: os.stat_result | None = None):
        super().__init__(message)
        self.changed = changed
        self.snapshot = snapshot


def _read_crypttab(etc_fd: int) -> tuple[bytes, os.stat_result]:
    fd = os.open(
        "crypttab",
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=etc_fd,
    )
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("vault-crypttab-not-regular")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(fd)


def _same_owner_mode(expected: os.stat_result, current: os.stat_result) -> bool:
    return (
        current.st_uid == expected.st_uid
        and current.st_gid == expected.st_gid
        and stat.S_IMODE(current.st_mode) == stat.S_IMODE(expected.st_mode)
    )


def _atomic_replace_crypttab(
    etc_fd: int,
    content: bytes,
    metadata: os.stat_result,
    expected: os.stat_result,
) -> os.stat_result:
    temporary: str | None = None
    temporary_fd: int | None = None
    renamed = False
    try:
        for _attempt in range(32):
            candidate = f".crypttab.{os.getpid()}.{os.urandom(8).hex()}.tmp"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=etc_fd,
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd is None or temporary is None:
            raise OSError("vault-crypttab-temp-create-failed")

        os.fchown(temporary_fd, metadata.st_uid, metadata.st_gid)
        os.fchmod(temporary_fd, stat.S_IMODE(metadata.st_mode))
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        current = os.stat("crypttab", dir_fd=etc_fd, follow_symlinks=False)
        if not _same_snapshot(expected, current):
            raise OSError("vault-crypttab-document-changed")
        os.replace(temporary, "crypttab", src_dir_fd=etc_fd, dst_dir_fd=etc_fd)
        temporary = None
        renamed = True
        os.fsync(etc_fd)

        observed, installed = _read_crypttab(etc_fd)
        if observed != content or not _same_owner_mode(metadata, installed):
            raise OSError("vault-crypttab-write-not-observed")
        return installed
    except Exception as exc:
        snapshot = None
        if renamed:
            try:
                observed, current = _read_crypttab(etc_fd)
                if observed == content and _same_owner_mode(metadata, current):
                    snapshot = current
            except OSError:
                pass
        raise _CrypttabWriteError(str(exc), renamed, snapshot) from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=etc_fd)
            except OSError:
                pass


def _valid_keyfile(keyfile: Any) -> bool:
    if not isinstance(keyfile, str) or not keyfile.startswith("/root/key/"):
        return False
    name = keyfile[len("/root/key/") :]
    if (
        not name
        or name in {".", ".."}
        or "/" in name
        or "\x00" in name
        or any(character.isspace() for character in name)
    ):
        return False

    try:
        os.fsencode(keyfile)
    except UnicodeError:
        return False

    root_fd: int | None = None
    key_dir_fd: int | None = None
    keyfile_fd: int | None = None
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        slash_fd = os.open("/", flags)
        try:
            root_fd = os.open("root", flags, dir_fd=slash_fd)
        finally:
            os.close(slash_fd)
        key_dir_fd = os.open("key", flags, dir_fd=root_fd)
        parent = os.fstat(key_dir_fd)
        if (
            parent.st_uid != 0
            or parent.st_gid != 0
            or parent.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            return False

        keyfile_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
            dir_fd=key_dir_fd,
        )
        metadata = os.fstat(keyfile_fd)
        return (
            stat.S_ISREG(metadata.st_mode)
            and metadata.st_uid == 0
            and metadata.st_gid == 0
            and stat.S_IMODE(metadata.st_mode) in {0o400, 0o600}
        )
    except (OSError, UnicodeError):
        return False
    finally:
        for fd in (keyfile_fd, key_dir_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _backing_device(mapper_stat: os.stat_result) -> str | None:
    if not stat.S_ISBLK(mapper_stat.st_mode):
        return None
    device_id = f"{os.major(mapper_stat.st_rdev)}:{os.minor(mapper_stat.st_rdev)}"
    try:
        dm_name = os.path.basename(os.path.realpath(f"/sys/dev/block/{device_id}"))
        if re.fullmatch(r"dm-[0-9]+", dm_name) is None:
            return None
        slaves = os.listdir(f"/sys/block/{dm_name}/slaves")
    except OSError:
        return None
    if len(slaves) != 1 or slaves[0] in {"", ".", ".."} or "/" in slaves[0]:
        return None
    return f"/dev/{slaves[0]}"


def _crypttab_uuid(device: str) -> str | None:
    try:
        result = subprocess.run(
            ["/usr/sbin/blkid", "-s", "UUID", "-o", "value", device],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout
    if value.endswith(b"\n"):
        value = value[:-1]
    if not value or any(character in b" \t\r\n\v\f" for character in value):
        return None
    try:
        uuid = value.decode("ascii")
    except UnicodeDecodeError:
        return None
    if re.fullmatch(r"[A-Za-z0-9._:-]+", uuid) is None:
        return None
    return uuid


def _crypttab_content(
    original: bytes,
    mapper: str,
    uuid: str,
    unlock: str,
    keyfile: str | None,
) -> bytes:
    mapper_field = mapper.encode("ascii")
    uuid_field = uuid.encode("ascii")
    if unlock == "crypttab_keyfile":
        assert keyfile is not None
        replacement = b" ".join(
            (mapper_field, uuid_field, os.fsencode(keyfile), b"luks,nofail")
        ) + b"\n"
    else:
        replacement = b" ".join(
            (mapper_field, uuid_field, b"none", b"luks,noauto,nofail")
        ) + b"\n"

    lines = original.splitlines(keepends=True)
    replaced = False
    result: list[bytes] = []
    for line in lines:
        fields = line.split(None, 1)
        if not replaced and fields and fields[0] == mapper_field:
            result.append(replacement)
            replaced = True
        else:
            result.append(line)
    content = b"".join(result)
    if not replaced:
        if content and not content.endswith(b"\n"):
            content += b"\n"
        content += replacement
    if content and not content.endswith(b"\n"):
        content += b"\n"
    return content


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


def _apply(
    mapper: str,
    op: str,
    unlock: str | None = None,
    keyfile: Any = None,
) -> dict[str, Any]:
    mapper_path = f"/dev/mapper/{mapper}"
    try:
        mapper_stat = os.stat(mapper_path)
    except OSError:
        return _receipt(False, op, None, None, "vault-policy-mapper-not-open")

    mountpoint = _find_mountpoint(mapper_path, mapper_stat)
    if mountpoint is None:
        return _receipt(False, op, None, None, "vault-policy-mountpoint-ambiguous")

    io_failure = "vault-policy-read-failed" if op == "read" else "vault-policy-write-failed"

    parent_fd: int | None = None
    try:
        parent_fd = os.open(
            mountpoint,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        )
        if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
            return _receipt(False, op, mountpoint, None, io_failure)
    except OSError:
        if parent_fd is not None:
            os.close(parent_fd)
        return _receipt(False, op, mountpoint, None, io_failure)

    try:
        loaded = _read_policy(parent_fd)
        if loaded is None:
            return _receipt(False, op, mountpoint, None, "vault-policy-document-invalid")
        document, metadata = loaded
        if op == "read":
            observed_unlock = document.get("unlock")
            if not isinstance(observed_unlock, str) or observed_unlock not in _UNLOCKS:
                observed_unlock = None
            return _receipt(True, op, mountpoint, observed_unlock, "none")

        assert unlock is not None
        if unlock == "crypttab_keyfile" and not _valid_keyfile(keyfile):
            return _receipt(False, op, mountpoint, None, "vault-crypttab-keyfile-invalid")

        device = _backing_device(mapper_stat)
        if device is None:
            return _receipt(False, op, mountpoint, None, "vault-crypttab-device-ambiguous")
        uuid = _crypttab_uuid(device)
        if uuid is None:
            return _receipt(False, op, mountpoint, None, "vault-crypttab-uuid-missing")

        try:
            etc_fd = os.open(
                "/etc",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError:
            return _receipt(False, op, mountpoint, None, "vault-crypttab-read-failed")
        try:
            try:
                original, crypttab_metadata = _read_crypttab(etc_fd)
            except OSError:
                return _receipt(False, op, mountpoint, None, "vault-crypttab-read-failed")

            try:
                desired = _crypttab_content(original, mapper, uuid, unlock, keyfile)
            except (UnicodeError, ValueError, TypeError):
                return _receipt(False, op, mountpoint, None, "vault-crypttab-keyfile-invalid")
            crypttab_changed = desired != original
            installed_metadata: os.stat_result | None = None
            if crypttab_changed:
                try:
                    installed_metadata = _atomic_replace_crypttab(
                        etc_fd,
                        desired,
                        crypttab_metadata,
                        crypttab_metadata,
                    )
                except _CrypttabWriteError as exc:
                    return _receipt(
                        False,
                        op,
                        mountpoint,
                        None,
                        "vault-crypttab-write-failed",
                        crypttab_changed=exc.changed,
                    )

            document["unlock"] = unlock
            try:
                _install_policy(parent_fd, document, metadata)
            except Exception:
                restored: bool | None = None
                if crypttab_changed:
                    restored = False
                    try:
                        if installed_metadata is None:
                            raise OSError("vault-crypttab-restoration-snapshot-missing")
                        _atomic_replace_crypttab(
                            etc_fd,
                            original,
                            crypttab_metadata,
                            installed_metadata,
                        )
                        restored_bytes, restored_metadata = _read_crypttab(etc_fd)
                        restored = (
                            restored_bytes == original
                            and _same_owner_mode(crypttab_metadata, restored_metadata)
                        )
                    except Exception:
                        restored = False
                return _receipt(
                    False,
                    op,
                    mountpoint,
                    None,
                    "vault-policy-write-failed",
                    crypttab_changed=crypttab_changed,
                    crypttab_restored=restored,
                )
            return _receipt(
                True,
                op,
                mountpoint,
                unlock,
                "none",
                crypttab_changed=crypttab_changed,
            )
        finally:
            os.close(etc_fd)
    finally:
        os.close(parent_fd)


def _dispatch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _receipt(False, None, None, None, "vault-policy-mapper-invalid")
    payload = value.get("payload") if "schema" in value else value
    if not isinstance(payload, dict):
        return _receipt(False, None, None, None, "vault-policy-mapper-invalid")

    op = payload.get("op")
    if not isinstance(op, str) or op not in {"read", "write"}:
        return _receipt(False, None, None, None, "vault-policy-op-invalid")

    mapper = payload.get("mapper")
    if not isinstance(mapper, str) or _MAPPER.fullmatch(mapper) is None:
        return _receipt(False, op, None, None, "vault-policy-mapper-invalid")

    keyfile: Any = None
    if op == "read":
        if "unlock" in payload:
            return _receipt(False, op, None, None, "vault-policy-unlock-invalid")
        allowed_fields = {"op", "mapper"}
        unlock = None
    else:
        unlock = payload.get("unlock")
        if not isinstance(unlock, str) or unlock not in _UNLOCKS:
            return _receipt(False, op, None, None, "vault-policy-unlock-invalid")
        if unlock == "crypttab_keyfile":
            if "keyfile" not in payload:
                return _receipt(False, op, None, None, "vault-crypttab-keyfile-invalid")
            keyfile = payload.get("keyfile")
            allowed_fields = {"op", "mapper", "unlock", "keyfile"}
        else:
            if "keyfile" in payload:
                return _receipt(False, op, None, None, "vault-crypttab-keyfile-invalid")
            allowed_fields = {"op", "mapper", "unlock"}

    if set(payload) != allowed_fields:
        return _receipt(False, op, None, None, "vault-policy-mapper-invalid")
    return _apply(mapper, op, unlock, keyfile)


def _op_hint(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    payload = value.get("payload") if "schema" in value else value
    if isinstance(payload, dict):
        op = payload.get("op")
        if isinstance(op, str) and op in {"read", "write"}:
            return op
    return None


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        value = json.load(sys.stdin)
    except Exception:
        receipt = _receipt(False, None, None, None, "vault-policy-op-invalid")
    else:
        try:
            receipt = _dispatch(value)
        except Exception:
            op = _op_hint(value)
            if op is None:
                receipt = _receipt(False, None, None, None, "vault-policy-op-invalid")
            else:
                signal = "vault-policy-read-failed" if op == "read" else "vault-policy-write-failed"
                receipt = _receipt(False, op, None, None, signal)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

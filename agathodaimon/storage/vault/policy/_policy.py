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
_LEGACY_POLICY_SCHEMA = "fulcrum.keyman.vault_policy.v1"
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
    fstab_changed: bool = False,
    crypttab_restored: bool | None = None,
    fstab_restored: bool | None = None,
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
        receipt["fstab_changed"] = fstab_changed
    if crypttab_restored is not None:
        receipt["crypttabRestored"] = crypttab_restored
    if fstab_restored is not None:
        receipt["fstabRestored"] = fstab_restored
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


def _read_file(directory_fd: int, name: str) -> tuple[bytes, os.stat_result]:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise OSError("vault-file-not-regular")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks), metadata
    finally:
        os.close(fd)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"vault-policy-invalid-json-constant:{value}")


def _read_policy(
    parent_fd: int,
) -> tuple[dict[str, Any], os.stat_result | None, bytes] | None:
    try:
        content, metadata = _read_file(parent_fd, _POLICY_NAME)
    except FileNotFoundError:
        return (
            {
                "schema": _POLICY_SCHEMA,
                "mode": _POLICY_MODE,
                "unlock": "manual_passphrase",
            },
            None,
            b"",
        )
    except OSError:
        return None

    try:
        document = json.loads(content.decode("utf-8"), parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(document, dict):
        return None
    schema = document.get("schema")
    observed_unlock = document.get("unlock")
    if (
        not isinstance(schema, str)
        or schema not in {_POLICY_SCHEMA, _LEGACY_POLICY_SCHEMA}
        or document.get("mode") != _POLICY_MODE
        or not isinstance(observed_unlock, str)
        or observed_unlock not in _UNLOCKS
    ):
        return None
    return document, metadata, content


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


class _AtomicFileWriteError(OSError):
    def __init__(
        self,
        message: str,
        changed: bool = False,
        snapshot: os.stat_result | None = None,
        conflict: bool = False,
    ):
        super().__init__(message)
        self.changed = changed
        self.snapshot = snapshot
        self.conflict = conflict


def _read_file_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _same_owner_mode(expected: os.stat_result, current: os.stat_result) -> bool:
    return (
        current.st_uid == expected.st_uid
        and current.st_gid == expected.st_gid
        and stat.S_IMODE(current.st_mode) == stat.S_IMODE(expected.st_mode)
    )


def _atomic_replace_file(
    directory_fd: int,
    name: str,
    content: bytes,
    metadata: os.stat_result,
    expected: os.stat_result,
    expected_content: bytes,
) -> os.stat_result:
    temporary: str | None = None
    temporary_fd: int | None = None
    temporary_metadata: os.stat_result | None = None
    renamed = False
    conflict = False
    try:
        for _attempt in range(32):
            candidate = f".{name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
            try:
                temporary_fd = os.open(
                    candidate,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=directory_fd,
                )
                temporary = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd is None or temporary is None:
            raise OSError("vault-file-temp-create-failed")

        os.fchown(temporary_fd, metadata.st_uid, metadata.st_gid)
        os.fchmod(temporary_fd, stat.S_IMODE(metadata.st_mode))
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        temporary_metadata = os.fstat(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        try:
            current_content, current = _read_file(directory_fd, name)
        except OSError as exc:
            conflict = True
            raise OSError(f"vault-{name}-document-changed") from exc
        if not _same_snapshot(expected, current) or current_content != expected_content:
            conflict = True
            raise OSError(f"vault-{name}-document-changed")
        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = None
        renamed = True
        os.fsync(directory_fd)

        observed, installed = _read_file(directory_fd, name)
        if (
            observed != content
            or not _same_owner_mode(metadata, installed)
            or temporary_metadata is None
            or not _read_file_identity(temporary_metadata, installed)
        ):
            raise OSError(f"vault-{name}-write-not-observed")
        return installed
    except Exception as exc:
        changed = renamed
        snapshot: os.stat_result | None = None
        try:
            observed, current = _read_file(directory_fd, name)
            if (
                temporary_metadata is not None
                and _read_file_identity(temporary_metadata, current)
                and observed == content
                and _same_owner_mode(metadata, current)
            ):
                changed = True
                snapshot = current
        except OSError:
            pass
        raise _AtomicFileWriteError(str(exc), changed, snapshot, conflict) from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass


def _restore_file(
    directory_fd: int,
    name: str,
    original_content: bytes,
    original_metadata: os.stat_result,
    installed_content: bytes,
    installed_metadata: os.stat_result | None,
) -> bool:
    if installed_metadata is not None:
        try:
            _atomic_replace_file(
                directory_fd,
                name,
                original_content,
                original_metadata,
                installed_metadata,
                installed_content,
            )
        except Exception:
            pass
    try:
        observed, current = _read_file(directory_fd, name)
        return observed == original_content and _same_owner_mode(original_metadata, current)
    except OSError:
        return False


_FSTAB_OCTAL_ESCAPE = re.compile(rb"\\([0-7]{3})")


def _fstab_fields(line: bytes) -> list[tuple[int, int, bytes]]:
    end = len(line)
    if end and line[end - 1] == 10:
        end -= 1
        if end and line[end - 1] == 13:
            end -= 1
    fields: list[tuple[int, int, bytes]] = []
    position = 0
    while position < end:
        while position < end and line[position] in b" \t":
            position += 1
        if position >= end or line[position] == ord("#"):
            break
        start = position
        while position < end and line[position] not in b" \t":
            if (
                line[position] == ord("\\")
                and position + 3 < end
                and all(byte in b"01234567" for byte in line[position + 1 : position + 4])
            ):
                position += 4
            else:
                position += 1
        fields.append((start, position, line[start:position]))
    return fields


def _fstab_content(
    original: bytes,
    mountpoint: str,
    unlock: str,
) -> tuple[bytes | None, str | None]:
    target = os.fsencode(mountpoint)
    matches: list[tuple[int, list[tuple[int, int, bytes]]]] = []
    lines = original.splitlines(keepends=True)
    for index, line in enumerate(lines):
        fields = _fstab_fields(line)
        if len(fields) < 2:
            continue
        decoded = _FSTAB_OCTAL_ESCAPE.sub(
            lambda match: bytes((int(match.group(1), 8),)),
            fields[1][2],
        )
        if decoded == target:
            matches.append((index, fields))

    if not matches:
        return None, "vault-fstab-target-missing"
    if len(matches) != 1:
        return None, "vault-fstab-target-ambiguous"
    index, fields = matches[0]
    if len(fields) < 4:
        return None, "vault-fstab-target-invalid"

    option_start, option_end, options = fields[3]
    parts = options.split(b",")
    if unlock == "crypttab_keyfile":
        updated_parts = [part for part in parts if part != b"noauto"]
    else:
        updated_parts = []
        kept_noauto = False
        for part in parts:
            if part == b"noauto":
                if not kept_noauto:
                    updated_parts.append(part)
                    kept_noauto = True
            else:
                updated_parts.append(part)
        if not kept_noauto:
            updated_parts.append(b"noauto")
    if not updated_parts:
        updated_parts.append(b"defaults")
    updated_options = b",".join(updated_parts)
    lines[index] = lines[index][:option_start] + updated_options + lines[index][option_end:]
    return b"".join(lines), None


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
    uuid_field = b"UUID=" + uuid.encode("ascii")
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


def _atomic_create_policy(parent_fd: int, content: bytes) -> os.stat_result:
    temporary: str | None = None
    temporary_fd: int | None = None
    temporary_metadata: os.stat_result | None = None
    linked = False
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

        os.fchown(temporary_fd, 0, 0)
        os.fchmod(temporary_fd, 0o600)
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        temporary_metadata = os.fstat(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = None

        os.link(
            temporary,
            _POLICY_NAME,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
        linked = True
        os.unlink(temporary, dir_fd=parent_fd)
        temporary = None
        os.fsync(parent_fd)

        observed, installed = _read_file(parent_fd, _POLICY_NAME)
        if (
            observed != content
            or installed.st_uid != 0
            or installed.st_gid != 0
            or stat.S_IMODE(installed.st_mode) != 0o600
            or temporary_metadata is None
            or not _read_file_identity(temporary_metadata, installed)
        ):
            raise OSError("vault-policy-write-not-observed")
        return installed
    except Exception as exc:
        changed = linked
        snapshot: os.stat_result | None = None
        try:
            observed, current = _read_file(parent_fd, _POLICY_NAME)
            if (
                temporary_metadata is not None
                and _read_file_identity(temporary_metadata, current)
                and observed == content
                and current.st_uid == 0
                and current.st_gid == 0
                and stat.S_IMODE(current.st_mode) == 0o600
            ):
                changed = True
                snapshot = current
        except OSError:
            pass
        raise _AtomicFileWriteError(
            str(exc),
            changed,
            snapshot,
            isinstance(exc, FileExistsError),
        ) from exc
    finally:
        if temporary_fd is not None:
            os.close(temporary_fd)
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=parent_fd)
            except OSError:
                pass


def _remove_created_policy(
    parent_fd: int,
    content: bytes,
    installed_metadata: os.stat_result | None,
) -> bool:
    if installed_metadata is None:
        return False
    try:
        observed, current = _read_file(parent_fd, _POLICY_NAME)
        if not _same_snapshot(installed_metadata, current) or observed != content:
            return False
        os.unlink(_POLICY_NAME, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except FileNotFoundError:
        return True
    except OSError:
        pass
    try:
        _read_file(parent_fd, _POLICY_NAME)
        return False
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _install_policy(
    parent_fd: int,
    encoded: bytes,
    metadata: os.stat_result | None,
    original: bytes,
) -> None:
    if metadata is None:
        _atomic_create_policy(parent_fd, encoded)
        return
    _atomic_replace_file(
        parent_fd,
        _POLICY_NAME,
        encoded,
        metadata,
        metadata,
        original,
    )


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
        document, policy_metadata, policy_original = loaded
        if op == "read":
            return _receipt(True, op, mountpoint, document["unlock"], "none")

        assert unlock is not None
        if unlock == "crypttab_keyfile" and not _valid_keyfile(keyfile):
            return _receipt(False, op, mountpoint, None, "vault-crypttab-keyfile-invalid")

        document["schema"] = _POLICY_SCHEMA
        document["unlock"] = unlock
        try:
            policy_content = (json.dumps(document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        except (UnicodeError, ValueError, TypeError):
            return _receipt(False, op, mountpoint, None, "vault-policy-document-encoding-failed")

        try:
            etc_fd = os.open(
                "/etc",
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError:
            return _receipt(False, op, mountpoint, None, "vault-crypttab-read-failed")
        try:
            try:
                crypttab_original, crypttab_metadata = _read_file(etc_fd, "crypttab")
            except OSError:
                return _receipt(False, op, mountpoint, None, "vault-crypttab-read-failed")
            try:
                fstab_original, fstab_metadata = _read_file(etc_fd, "fstab")
            except OSError:
                return _receipt(False, op, mountpoint, None, "vault-fstab-read-failed")

            fstab_desired, fstab_signal = _fstab_content(fstab_original, mountpoint, unlock)
            if fstab_signal is not None:
                return _receipt(False, op, mountpoint, None, fstab_signal)
            assert fstab_desired is not None

            device = _backing_device(mapper_stat)
            if device is None:
                return _receipt(False, op, mountpoint, None, "vault-crypttab-device-ambiguous")
            uuid = _crypttab_uuid(device)
            if uuid is None:
                return _receipt(False, op, mountpoint, None, "vault-crypttab-uuid-missing")

            try:
                crypttab_desired = _crypttab_content(
                    crypttab_original,
                    mapper,
                    uuid,
                    unlock,
                    keyfile,
                )
            except (UnicodeError, ValueError, TypeError):
                return _receipt(False, op, mountpoint, None, "vault-crypttab-keyfile-invalid")

            crypttab_changed = False
            fstab_changed = False
            crypttab_installed: os.stat_result | None = None
            fstab_installed: os.stat_result | None = None

            if crypttab_desired != crypttab_original:
                try:
                    crypttab_installed = _atomic_replace_file(
                        etc_fd,
                        "crypttab",
                        crypttab_desired,
                        crypttab_metadata,
                        crypttab_metadata,
                        crypttab_original,
                    )
                    crypttab_changed = True
                except _AtomicFileWriteError as exc:
                    crypttab_changed = exc.changed
                    restored = None
                    if exc.changed:
                        restored = _restore_file(
                            etc_fd,
                            "crypttab",
                            crypttab_original,
                            crypttab_metadata,
                            crypttab_desired,
                            exc.snapshot,
                        )
                    signal = (
                        "vault-crypttab-document-changed"
                        if exc.conflict
                        else "vault-crypttab-write-failed"
                    )
                    return _receipt(
                        False,
                        op,
                        mountpoint,
                        None,
                        signal,
                        crypttab_changed=crypttab_changed,
                        crypttab_restored=restored,
                    )

            if fstab_desired != fstab_original:
                try:
                    fstab_installed = _atomic_replace_file(
                        etc_fd,
                        "fstab",
                        fstab_desired,
                        fstab_metadata,
                        fstab_metadata,
                        fstab_original,
                    )
                    fstab_changed = True
                except _AtomicFileWriteError as exc:
                    fstab_changed = exc.changed
                    fstab_restored = None
                    if exc.changed:
                        fstab_restored = _restore_file(
                            etc_fd,
                            "fstab",
                            fstab_original,
                            fstab_metadata,
                            fstab_desired,
                            exc.snapshot,
                        )
                    crypttab_restored = None
                    if crypttab_changed:
                        crypttab_restored = _restore_file(
                            etc_fd,
                            "crypttab",
                            crypttab_original,
                            crypttab_metadata,
                            crypttab_desired,
                            crypttab_installed,
                        )
                    signal = (
                        "vault-fstab-document-changed"
                        if exc.conflict
                        else "vault-fstab-write-failed"
                    )
                    return _receipt(
                        False,
                        op,
                        mountpoint,
                        None,
                        signal,
                        crypttab_changed=crypttab_changed,
                        fstab_changed=fstab_changed,
                        crypttab_restored=crypttab_restored,
                        fstab_restored=fstab_restored,
                    )

            try:
                _install_policy(parent_fd, policy_content, policy_metadata, policy_original)
            except _AtomicFileWriteError as exc:
                if exc.changed:
                    if policy_metadata is None:
                        _remove_created_policy(parent_fd, policy_content, exc.snapshot)
                    elif exc.snapshot is not None:
                        _restore_file(
                            parent_fd,
                            _POLICY_NAME,
                            policy_original,
                            policy_metadata,
                            policy_content,
                            exc.snapshot,
                        )
                fstab_restored = None
                if fstab_changed:
                    fstab_restored = _restore_file(
                        etc_fd,
                        "fstab",
                        fstab_original,
                        fstab_metadata,
                        fstab_desired,
                        fstab_installed,
                    )
                crypttab_restored = None
                if crypttab_changed:
                    crypttab_restored = _restore_file(
                        etc_fd,
                        "crypttab",
                        crypttab_original,
                        crypttab_metadata,
                        crypttab_desired,
                        crypttab_installed,
                    )
                signal = (
                    "vault-policy-document-changed"
                    if exc.conflict
                    else "vault-policy-write-failed"
                )
                return _receipt(
                    False,
                    op,
                    mountpoint,
                    None,
                    signal,
                    crypttab_changed=crypttab_changed,
                    fstab_changed=fstab_changed,
                    crypttab_restored=crypttab_restored,
                    fstab_restored=fstab_restored,
                )
            return _receipt(
                True,
                op,
                mountpoint,
                unlock,
                "none",
                crypttab_changed=crypttab_changed,
                fstab_changed=fstab_changed,
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

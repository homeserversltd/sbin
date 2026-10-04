"""Caduceus vault opener for Keyman and explicit passphrase requests."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from typing import Any, Sequence

import agathodaimon.lib.sacred_credential.index as sacred_credential

_SCHEMA = "caduceus.vault.keyman-open.v1"
_SERVICE = "homeconsole-vault"
_CRYPTSETUP = "/usr/sbin/cryptsetup"
_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._-]+$")
_MAPPER = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _receipt(ok: bool, present: bool, signal: str) -> dict[str, Any]:
    return {"schema": _SCHEMA, "ok": ok, "present": present, "firstMissingSignal": signal}


def _unlock_receipt(
    ok: bool,
    present: bool,
    signal: str,
    *,
    already_open: bool = False,
    mounted: bool | None = False,
    mapper_closed: bool = False,
    rite: dict[str, Any] | None = None,
) -> dict[str, Any]:
    receipt = {
        "schema": _SCHEMA,
        "ok": ok,
        "present": present,
        "already_open": already_open,
        "mounted": mounted,
        "mapper_closed": mapper_closed,
        "firstMissingSignal": signal,
    }
    if rite is not None:
        receipt["rite"] = rite
    return receipt


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def open_from_seated_record(payload: object, *, device_fd: int | None = None) -> dict[str, Any]:
    """Adapt the legacy Keyman request to the root vault-unlock path."""
    if not isinstance(payload, dict) or set(payload) != {"device", "mapper"}:
        return _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    device, mapper = payload.get("device"), payload.get("mapper")
    if (
        not isinstance(device, str)
        or (device_fd is None and _DEVICE.fullmatch(device) is None)
        or not isinstance(mapper, str)
        or _MAPPER.fullmatch(mapper) is None
    ):
        return _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    try:
        if not sacred_credential.seated_service_record_present(_SERVICE):
            # Caduceus owns its external fallback when no Keyman record is seated.
            return _receipt(True, False, "none")
    except (OSError, subprocess.SubprocessError, sacred_credential.CaduceusAccessRefused):
        return _receipt(False, True, "agathodaimon-vault-keyman-open-refused")

    return _unlock(
        {"op": "unlock", "device": device, "mapper": mapper, "mountpoint": "/vault"},
        None,
        True,
        keyman_record_present=True,
        device_fd=device_fd,
    )


def _cryptsetup_open(mapper: str, device_fd: int, material: bytearray) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            _CRYPTSETUP,
            "open",
            "--batch-mode",
            "--key-file",
            "-",
            f"/proc/self/fd/{device_fd}",
            mapper,
        ],
        input=bytes(material),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
        pass_fds=(device_fd,),
    )


def _open_block_device(path: str) -> int | None:
    if not path.startswith("/dev/") or path.startswith("//") or path.endswith("/"):
        return None
    parts = path.split("/")[1:]
    if len(parts) < 2 or parts[0] != "dev" or any(part in {"", ".", ".."} for part in parts):
        return None
    parent_fd: int | None = None
    current_fd: int | None = None
    device_fd: int | None = None
    try:
        parent_fd = os.open("/", _DIR_FLAGS)
        current_fd = os.open("dev", _DIR_FLAGS, dir_fd=parent_fd)
        os.close(parent_fd)
        parent_fd = None
        for part in parts[1:-1]:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        device_flags = getattr(os, "O_PATH", os.O_RDONLY) | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        device_fd = os.open(parts[-1], device_flags, dir_fd=current_fd)
        if not stat.S_ISBLK(os.fstat(device_fd).st_mode):
            return None
        pinned_fd = device_fd
        device_fd = None
        return pinned_fd
    except OSError:
        return None
    finally:
        for fd in (device_fd, current_fd, parent_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _mountpoint_parts(path: Any) -> tuple[str, ...] | None:
    if not isinstance(path, str) or not path.startswith("/") or path in {"", "/"} or "\x00" in path:
        return None
    if path.startswith("//") or path.endswith("/"):
        return None
    parts = tuple(path[1:].split("/"))
    if any(part in {"", ".", ".."} for part in parts):
        return None
    if parts[0] not in {"mnt", "vault"} and len(parts) != 1:
        return None
    return parts


def _mountpoint_is_safe(parts: tuple[str, ...]) -> bool:
    """Check existing components without following links or creating anything."""
    root_fd: int | None = None
    current_fd: int | None = None
    try:
        root_fd = os.open("/", _DIR_FLAGS)
        if parts[0] in {"mnt", "vault"}:
            current_fd = os.open(parts[0], _DIR_FLAGS, dir_fd=root_fd)
            os.close(root_fd)
            root_fd = None
            for part in parts[1:]:
                try:
                    next_fd = os.open(part, _DIR_FLAGS, dir_fd=current_fd)
                except FileNotFoundError:
                    return True
                os.close(current_fd)
                current_fd = next_fd
            return True
        try:
            os.stat(parts[0], dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False
    except OSError:
        return False
    finally:
        for fd in (current_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _walk_mountpoint(parts: tuple[str, ...], *, create: bool) -> int | None:
    """Open/create allowed mountpoint components without following symlinks."""
    root_fd: int | None = None
    current_fd: int | None = None
    try:
        root_fd = os.open("/", _DIR_FLAGS)
        if parts[0] in {"mnt", "vault"}:
            current_fd = os.open(parts[0], _DIR_FLAGS, dir_fd=root_fd)
            os.close(root_fd)
            root_fd = None
            rest = parts[1:]
        else:
            # A new direct child of / is allowed; overlaying an existing root
            # directory is not. This keeps the root allowance from replacing
            # system mountpoints such as /etc or /var.
            if create:
                try:
                    os.mkdir(parts[0], 0o755, dir_fd=root_fd)
                except FileExistsError:
                    return None
                current_fd = os.open(parts[0], _DIR_FLAGS, dir_fd=root_fd)
                os.close(root_fd)
                root_fd = None
                return current_fd
            try:
                os.stat(parts[0], dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            return None
        for part in rest:
            if create:
                try:
                    os.mkdir(part, 0o755, dir_fd=current_fd)
                except FileExistsError:
                    pass
            try:
                next_fd = os.open(part, _DIR_FLAGS, dir_fd=current_fd)
            except FileNotFoundError:
                return None
            os.close(current_fd)
            current_fd = next_fd
        result_fd = current_fd
        current_fd = None
        return result_fd
    except OSError:
        return None
    finally:
        for fd in (current_fd, root_fd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _mapper_is_open(mapper: str) -> bool | None:
    try:
        metadata = os.stat(f"/dev/mapper/{mapper}")
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True if stat.S_ISBLK(metadata.st_mode) else None


def _mountinfo_unescape(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _mounted_source_state(parts: tuple[str, ...], mapper: str) -> bool | None:
    """Return whether this exact target is mounted from this mapper, failing closed."""
    try:
        mapper_metadata = os.stat(f"/dev/mapper/{mapper}")
    except OSError:
        return None
    if not stat.S_ISBLK(mapper_metadata.st_mode):
        return None

    target = "/" + "/".join(parts)
    entries: list[tuple[str, str]] = []
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as mountinfo:
            for line in mountinfo:
                fields = line.split()
                if len(fields) < 10:
                    return None
                try:
                    separator = fields.index("-")
                except ValueError:
                    return None
                if separator < 6 or separator + 2 >= len(fields):
                    return None
                if _mountinfo_unescape(fields[4]) == target:
                    entries.append((fields[2], _mountinfo_unescape(fields[separator + 2])))
    except (OSError, UnicodeError):
        return None

    if not entries:
        return False
    if len(entries) != 1:
        return None
    device_number, source = entries[0]
    expected_number = f"{os.major(mapper_metadata.st_rdev)}:{os.minor(mapper_metadata.st_rdev)}"
    if device_number != expected_number or not source.startswith("/dev/") or source.startswith("//"):
        return None
    try:
        source_metadata = os.stat(source)
    except OSError:
        return None
    if not stat.S_ISBLK(source_metadata.st_mode) or source_metadata.st_rdev != mapper_metadata.st_rdev:
        return None
    return True


def _run_vault_init_rite() -> dict[str, Any]:
    init_script = "/vault/scripts/init.sh"
    try:
        os.lstat(init_script)
    except FileNotFoundError:
        return {"result": "absent"}
    except OSError:
        return {"result": "failed", "exit_code": None}

    try:
        result = subprocess.run(
            [init_script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            env={"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.SubprocessError):
        return {"result": "failed", "exit_code": None}
    if result.returncode != 0:
        return {"result": "failed", "exit_code": result.returncode}
    return {"result": "ran"}


def _close_mapper(mapper: str) -> bool:
    try:
        result = subprocess.run(
            [_CRYPTSETUP, "close", mapper],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _unlock(
    payload: Any,
    secret: bytearray | None,
    passphrase_valid: bool,
    *,
    keyman_record_present: bool | None = None,
    device_fd: int | None = None,
) -> dict[str, Any]:
    required = {"op", "mapper", "device", "mountpoint"}
    present = secret is not None or keyman_record_present is True
    invalid = _unlock_receipt(False, present, "agathodaimon-vault-open-request-invalid")
    if (
        not isinstance(payload, dict)
        or set(payload) != required
        or payload.get("op") != "unlock"
        or not passphrase_valid
    ):
        return invalid
    mapper, device, mountpoint = payload.get("mapper"), payload.get("device"), payload.get("mountpoint")
    if os.geteuid() != 0:
        return invalid
    if not isinstance(mapper, str) or _MAPPER.fullmatch(mapper) is None:
        return invalid
    if not isinstance(device, str) or not isinstance(mountpoint, str):
        return invalid
    parts = _mountpoint_parts(mountpoint)
    if parts is None or not _mountpoint_is_safe(parts):
        return invalid
    owns_device_fd = device_fd is None
    if device_fd is None:
        device_fd = _open_block_device(device)
        if device_fd is None:
            return invalid

    already_open = False
    opened_here = False
    mapper_closed = False
    mount_fd: int | None = None
    mount_started = False

    def refuse(
        signal: str,
        *,
        mounted: bool | None = False,
        preserve_mapper: bool = False,
    ) -> dict[str, Any]:
        nonlocal opened_here, mapper_closed
        if opened_here and not preserve_mapper:
            mapper_closed = _close_mapper(mapper)
            opened_here = False
        return _unlock_receipt(
            False,
            present,
            signal,
            already_open=already_open,
            mounted=mounted,
            mapper_closed=mapper_closed,
        )

    try:
        mapper_state = _mapper_is_open(mapper)
        if mapper_state is None:
            return refuse("agathodaimon-vault-unlock-refused")
        already_open = mapper_state
        if already_open:
            present = True
        if not already_open:
            if secret is None:
                has_keyman_record = keyman_record_present
                if has_keyman_record is None:
                    try:
                        has_keyman_record = sacred_credential.seated_service_record_present(_SERVICE)
                    except (OSError, subprocess.SubprocessError, sacred_credential.CaduceusAccessRefused):
                        return refuse("agathodaimon-vault-keyman-open-refused")
                if not has_keyman_record:
                    return _unlock_receipt(
                        False,
                        False,
                        "agathodaimon-vault-open-key-absent",
                        already_open=already_open,
                    )
                present = True
                material = bytearray()
                try:
                    material = sacred_credential.read_seated_service_password(_SERVICE)
                    opened = _cryptsetup_open(mapper, device_fd, material)
                except (OSError, subprocess.SubprocessError, sacred_credential.CaduceusAccessRefused):
                    return refuse("agathodaimon-vault-keyman-open-refused")
                finally:
                    _wipe(material)
                if opened.returncode != 0:
                    return refuse("agathodaimon-vault-keyman-open-refused")
                opened_here = True
            else:
                opened = _cryptsetup_open(mapper, device_fd, secret)
                if opened.returncode != 0:
                    return refuse("agathodaimon-vault-unlock-refused")
                opened_here = True

        mount_state = _mounted_source_state(parts, mapper)
        if mount_state is None:
            return refuse("agathodaimon-vault-mount-refused")
        if mount_state:
            rite = (
                {"result": "skipped", "reason": "already-mounted"}
                if mountpoint == "/vault"
                else {"result": "not_applicable", "reason": "mountpoint-not-vault"}
            )
            return _unlock_receipt(
                True,
                present,
                "none",
                already_open=already_open,
                mounted=True,
                rite=rite,
            )

        mount_fd = _walk_mountpoint(parts, create=True)
        if mount_fd is None:
            return refuse("agathodaimon-vault-mountpoint-refused")
        mount_started = True
        try:
            mounted = subprocess.run(
                ["/usr/bin/mount", "--", f"/dev/mapper/{mapper}", f"/proc/self/fd/{mount_fd}"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
                pass_fds=(mount_fd,),
            )
        finally:
            try:
                os.close(mount_fd)
            except OSError:
                pass
            mount_fd = None
        mount_state = _mounted_source_state(parts, mapper)
        if mounted.returncode != 0:
            return refuse(
                "agathodaimon-vault-mount-refused",
                mounted=mount_state,
                preserve_mapper=mount_state is not False,
            )
        if mount_state is not True:
            return refuse(
                "agathodaimon-vault-mount-refused",
                mounted=mount_state,
                preserve_mapper=mount_state is None,
            )

        if mountpoint == "/vault":
            try:
                rite = _run_vault_init_rite()
            except Exception:
                # The mount is already established; never close its mapper on rite failure.
                rite = {"result": "failed", "exit_code": None}
        else:
            rite = {"result": "not_applicable", "reason": "mountpoint-not-vault"}
        if rite["result"] == "failed":
            return _unlock_receipt(
                False,
                present,
                "agathodaimon-vault-init-failed",
                already_open=already_open,
                mounted=True,
                mapper_closed=False,
                rite=rite,
            )
        return _unlock_receipt(
            True,
            present,
            "none",
            already_open=already_open,
            mounted=True,
            rite=rite,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        if mount_started:
            return refuse("agathodaimon-vault-mount-refused", mounted=None, preserve_mapper=True)
        return refuse("agathodaimon-vault-unlock-refused")
    finally:
        if mount_fd is not None:
            try:
                os.close(mount_fd)
            except OSError:
                pass
        if owns_device_fd:
            try:
                os.close(device_fd)
            except OSError:
                pass


def _dispatch(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    payload = value.get("payload") if "schema" in value else value
    if not isinstance(payload, dict):
        return _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    if payload.get("op") == "unlock":
        passphrase = payload.pop("passphrase", None)
        passphrase_valid = passphrase is None or isinstance(passphrase, str)
        secret: bytearray | None = None
        if isinstance(passphrase, str):
            try:
                secret = bytearray(passphrase.encode("utf-8"))
            except UnicodeError:
                passphrase_valid = False
            finally:
                del passphrase
        try:
            return _unlock(payload, secret, passphrase_valid)
        finally:
            if secret is not None:
                _wipe(secret)
    return open_from_seated_record(payload)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        receipt = _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    else:
        try:
            raw = bytearray()
            try:
                raw.extend(sys.stdin.buffer.read(131073))
                if len(raw) > 131072:
                    raise ValueError
                value = json.loads(raw.decode("utf-8"))
            finally:
                _wipe(raw)
            receipt = _dispatch(value)
        except Exception:
            receipt = _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Caduceus disk-door actuator; secrets only ever cross child stdin."""
from __future__ import annotations
import json, os, posixpath, re, subprocess, sys
from typing import Any, Sequence

SCHEMA = "caduceus.disk.door.v1"
MAX_INPUT_BYTES = 64 * 1024
EXPORT_NAS = "/vault/scripts/exportNAS.sh"
MOUNT_DRIVE = "/vault/scripts/mountDrive.sh"
UNMOUNT_DRIVE = "/vault/scripts/unmountDrive.sh"
CRYPTSETUP = "/usr/sbin/cryptsetup"
FINDMNT = "/usr/bin/findmnt"
BASH = "/usr/bin/bash"
TEST = "/usr/bin/test"
WIPEFS = "/usr/sbin/wipefs"
_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAPPER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}_crypt$")
_FORBIDDEN = re.compile(r"(?:ssh|lan\.key|authorized_keys)", re.I)
_SAFE_STEP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")


class Refusal(ValueError):
    def __init__(self, signal: str, failed_step: str | None = None, return_code: int | None = None):
        super().__init__(signal)
        self.signal = signal
        self.failed_step = failed_step
        self.return_code = return_code


def _sudo(argv: Sequence[str]) -> list[str]:
    return ["sudo", "-n", *argv]


def _step_name(argv: list[str]) -> str:
    index = 2 if len(argv) > 2 and argv[:2] == ["sudo", "-n"] else 0
    executable = os.path.basename(argv[index]) if len(argv) > index else "unknown"
    if executable in {"bash", "sh"} and len(argv) > index + 1 and argv[index + 1].startswith("/"):
        executable = os.path.basename(argv[index + 1])
    return executable if _SAFE_STEP.fullmatch(executable) else "unknown"


def _run(argv: list[str], secret: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, input=secret, text=True, capture_output=True, check=False)
    except OSError:
        raise Refusal("agathodaimon-disk-command-start-refused", _step_name(argv))


def _check(result: subprocess.CompletedProcess[str], signal: str,
           argv: list[str]) -> subprocess.CompletedProcess[str]:
    if result.returncode != 0:
        raise Refusal(signal, _step_name(argv), int(result.returncode))
    return result


def _receipt(action: str, planned: bool, commands: list[list[str]], **extra: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": True, "action": action, "planned": planned,
            "mutationPerformed": not planned, "commands": commands, "firstMissingSignal": "none", **extra}


def _fail(signal: str, failed_step: str | None = None, return_code: int | None = None) -> dict[str, Any]:
    failure = {"schema": SCHEMA, "ok": False, "action": "unknown", "planned": False,
               "mutationPerformed": False, "commands": [], "firstMissingSignal": signal}
    if failed_step is not None:
        failure["failedStep"] = failed_step
    if return_code is not None:
        failure["returnCode"] = return_code
    return failure


def _device(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/") or "\x00" in value or "/" in value[5:] or not _COMPONENT.fullmatch(value[5:]):
        raise Refusal("agathodaimon-disk-device-invalid")
    return value


def _mapper(value: Any) -> str:
    if not isinstance(value, str) or not _MAPPER.fullmatch(value):
        raise Refusal("agathodaimon-disk-mapper-invalid")
    return value


def _mountpoint(value: Any) -> str:
    if not isinstance(value, str) or "\x00" in value or not value.startswith("/mnt/") or posixpath.normpath(value) != value:
        raise Refusal("agathodaimon-disk-mountpoint-invalid")
    if any(not _COMPONENT.fullmatch(part) for part in value[5:].split("/")):
        raise Refusal("agathodaimon-disk-mountpoint-invalid")
    return value


def _forbid(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if _FORBIDDEN.search(str(key)):
                raise Refusal("agathodaimon-disk-secret-path-forbidden")
            _forbid(item)
    elif isinstance(value, list):
        for item in value:
            _forbid(item)


def _find(mountpoint: str) -> list[str]:
    return _sudo([FINDMNT, "-n", "-o", "SOURCE,TARGET", "--target", mountpoint])


def _mapper_path(mapper: str) -> str:
    return f"/dev/mapper/{mapper}"


def _mapper_cmd(mapper: str) -> list[str]:
    return _sudo([TEST, "-e", _mapper_path(mapper)])


def _mapper_readback(mapper: str) -> dict[str, Any]:
    return {"path": _mapper_path(mapper), "exists": os.path.exists(_mapper_path(mapper))}


def _mount_readback(result: subprocess.CompletedProcess[str], mountpoint: str) -> dict[str, Any]:
    fields = result.stdout.strip().split(None, 1) if result.returncode == 0 else []
    if len(fields) == 2:
        source, target = fields
        mounted = bool(source) and target == mountpoint
        return {"mountpoint": mountpoint, "mounted": mounted,
                "source": source if mounted else None, "target": target}
    return {"mountpoint": mountpoint, "mounted": False, "source": None, "target": None}


def unlock(payload: dict[str, Any], planned: bool) -> dict[str, Any]:
    device = _device(payload.get("device"))
    mapper = _mapper(f"{posixpath.basename(device)}_crypt")
    export = _sudo([BASH, EXPORT_NAS])
    open_command = _sudo([CRYPTSETUP, "open", device, mapper])
    mapper_check = _mapper_cmd(mapper)
    commands = [export, open_command, mapper_check]
    if planned:
        return _receipt("unlock", True, commands, device=device, mapper=mapper,
                        mapperReadback={"path": _mapper_path(mapper), "exists": None, "planned": True})
    result = _check(_run(export), "agathodaimon-disk-vault-export-failed", export)
    secret = result.stdout.strip()
    if not secret:
        raise Refusal("agathodaimon-disk-vault-export-failed")
    opened = _run(open_command, secret)
    readback = _mapper_readback(mapper)
    _check(opened, "agathodaimon-disk-cryptsetup-open-refused", open_command)
    if not readback["exists"]:
        raise Refusal("agathodaimon-disk-mapper-readback-missing")
    return _receipt("unlock", False, commands, device=device, mapper=mapper, mapperReadback=readback)


def _mount_device(value: Any) -> tuple[str, str | None]:
    if isinstance(value, str) and value.startswith("/dev/mapper/"):
        return value, _mapper(value[12:])
    return _device(value), None


def mount(payload: dict[str, Any], planned: bool) -> dict[str, Any]:
    device, embedded = _mount_device(payload.get("device"))
    mountpoint = _mountpoint(payload.get("mountpoint"))
    mapper_value = payload.get("mapper")
    mapper = _mapper(mapper_value) if mapper_value is not None else embedded
    command = _sudo([BASH, MOUNT_DRIVE, "mount", device, mountpoint] + ([mapper] if mapper else []))
    read_command = _find(mountpoint)
    commands = [command, read_command]
    planned_readback = {"mountpoint": mountpoint, "mounted": True, "source": device,
                        "target": mountpoint, "planned": True}
    if planned:
        return _receipt("mount", True, commands, device=device, mountpoint=mountpoint,
                        mapper=mapper, mountReadback=planned_readback)
    _check(_run(command), "agathodaimon-disk-mount-refused", command)
    read_result = _run(read_command)
    _check(read_result, "agathodaimon-disk-mount-readback-missing", read_command)
    readback = _mount_readback(read_result, mountpoint)
    if not readback["mounted"] or readback["target"] != mountpoint:
        raise Refusal("agathodaimon-disk-mount-readback-missing")
    return _receipt("mount", False, commands, device=device, mountpoint=mountpoint,
                    mapper=mapper, mountReadback=readback)


def unmount(payload: dict[str, Any], planned: bool) -> dict[str, Any]:
    device = _device(payload.get("device"))
    mountpoint = _mountpoint(payload.get("mountpoint"))
    mapper_value = payload.get("mapper")
    mapper = _mapper(mapper_value) if mapper_value is not None else None
    unmount_command = _sudo([BASH, UNMOUNT_DRIVE, device, mountpoint] + ([mapper] if mapper else []))
    read_command = _find(mountpoint)
    commands = [unmount_command, read_command]
    if mapper:
        commands.extend([_mapper_cmd(mapper), _sudo([CRYPTSETUP, "close", mapper]), _mapper_cmd(mapper)])
    planned_mount = {"mountpoint": mountpoint, "mounted": False, "source": None,
                     "target": None, "planned": True}
    planned_mapper = {"path": _mapper_path(mapper), "exists": False, "planned": True} if mapper else None
    if planned:
        return _receipt("unmount", True, commands, device=device, mountpoint=mountpoint,
                        mapper=mapper, mountReadback=planned_mount, mapperReadback=planned_mapper)
    script_result = _run(unmount_command)
    observed = _run(read_command)
    if observed.returncode not in {0, 1}:
        raise Refusal("agathodaimon-disk-mount-readback-missing", _step_name(read_command), int(observed.returncode))
    mount_readback = _mount_readback(observed, mountpoint)
    if mount_readback["mounted"]:
        if script_result.returncode != 0:
            raise Refusal("agathodaimon-disk-mount-remains", _step_name(unmount_command), int(script_result.returncode))
        raise Refusal("agathodaimon-disk-mount-remains")
    mapper_readback = None
    if mapper:
        mapper_readback = _mapper_readback(mapper)
        if mapper_readback["exists"]:
            close_command = _sudo([CRYPTSETUP, "close", mapper])
            _check(_run(close_command), "agathodaimon-disk-cryptsetup-close-refused", close_command)
            mapper_readback = _mapper_readback(mapper)
            if mapper_readback["exists"]:
                raise Refusal("agathodaimon-disk-mapper-remains")
    return _receipt("unmount", False, commands, device=device, mountpoint=mountpoint,
                    mapper=mapper, mountReadback=mount_readback, mapperReadback=mapper_readback)


def wipe_disk(payload: dict[str, Any], planned: bool) -> dict[str, Any]:
    device = _device(payload.get("device"))
    commands = [_sudo([WIPEFS, "-a", device])]
    if planned:
        return _receipt("wipe", True, commands, device=device, target=device)
    _check(_run(commands[0]), "agathodaimon-disk-wipe-refused", commands[0])
    return _receipt("wipe", False, commands, device=device, target=device)


def dispatch(value: dict[str, Any]) -> dict[str, Any]:
    if set(value) - {"actuator", "metadata"} or not isinstance(value.get("metadata"), dict):
        raise Refusal("agathodaimon-disk-request-invalid")
    payload = value["metadata"]
    _forbid(payload)
    action = payload.get("action")
    planned = payload.get("dryRun", payload.get("planned", False))
    if not isinstance(planned, bool):
        raise Refusal("agathodaimon-disk-planned-invalid")
    if action == "wipe":
        return wipe_disk(payload, planned)
    if action == "unlock":
        return unlock(payload, planned)
    if action == "mount":
        return mount(payload, planned)
    if action == "unmount":
        return unmount(payload, planned)
    raise Refusal("agathodaimon-disk-action-invalid")


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise Refusal("agathodaimon-disk-request-too-large")
        value = json.loads(raw.decode())
        receipt = dispatch(value) if isinstance(value, dict) else _fail("agathodaimon-disk-request-invalid")
    except Refusal as error:
        receipt = _fail(error.signal, error.failed_step, error.return_code)
    except (UnicodeDecodeError, json.JSONDecodeError):
        receipt = _fail("agathodaimon-disk-request-invalid")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

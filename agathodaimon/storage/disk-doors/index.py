"""Caduceus wipe-only disk actuator."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Any, Sequence

SCHEMA = "caduceus.disk.door.v1"
MAX_INPUT_BYTES = 64 * 1024
WIPEFS = "/usr/sbin/wipefs"
_COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
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
    return executable if _SAFE_STEP.fullmatch(executable) else "unknown"


def _run(argv: Sequence[str]) -> subprocess.CompletedProcess[Any]:
    try:
        return subprocess.run(argv, capture_output=True, check=False)
    except OSError:
        raise Refusal("agathodaimon-disk-command-start-refused", _step_name(list(argv))) from None


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


def _check(result: subprocess.CompletedProcess[Any], signal: str,
           argv: list[str]) -> subprocess.CompletedProcess[Any]:
    if result.returncode != 0:
        raise Refusal(signal, _step_name(argv), int(result.returncode))
    return result


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
    action = payload.get("action")
    planned = payload.get("dryRun", payload.get("planned", False))
    if not isinstance(planned, bool):
        raise Refusal("agathodaimon-disk-planned-invalid")
    if action == "wipe":
        return wipe_disk(payload, planned)
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

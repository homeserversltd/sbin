"""Control a system or owner systemd unit through fixed argument vectors."""
from __future__ import annotations

import re
import subprocess


OWNER = "owner"  # Same owner identity as console/restart.
ACTIONS = frozenset({"start", "stop", "restart", "enable", "disable", "status"})
UNIT = re.compile(r"[A-Za-z0-9_:][A-Za-z0-9_.:-]*(?:@[A-Za-z0-9_:][A-Za-z0-9_.:-]*)?\.(?:service|target|mount|path)\Z")
PROPERTIES = {"LoadState": "load_state", "ActiveState": "active_state", "SubState": "sub_state", "UnitFileState": "unit_file_state"}


def _run(argv, timeout=30):
    try:
        result = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=timeout)
        return result.returncode, result.stdout
    except (OSError, subprocess.SubprocessError):
        return None, ""


def _show(prefix, unit):
    code, output = _run([*prefix, "show", unit, "--property=LoadState,ActiveState,SubState,UnitFileState"])
    values = {name: None for name in PROPERTIES.values()}
    for line in output.splitlines():
        key, sep, value = line.partition("=")
        if sep and key in PROPERTIES:
            values[PROPERTIES[key]] = value
    return code, values


def control(action, unit, scope, deadline_seconds=30, *, planned=False):
    receipt = {"ok": False, "action": action, "unit": unit, "scope": scope,
               "command": None, "returncode": None,
               "observed": {name: None for name in PROPERTIES.values()},
               "readback": {name: None for name in PROPERTIES.values()},
               "mutation_performed": False, "first_missing_signal": None}
    if isinstance(deadline_seconds, bool) or not isinstance(deadline_seconds, (int, float)) or not 1 <= deadline_seconds <= 600:
        receipt["first_missing_signal"] = "invalid-deadline"
        return receipt
    if not isinstance(action, str) or action not in ACTIONS:
        receipt["first_missing_signal"] = "invalid-action"
        return receipt
    if not isinstance(unit, str) or len(unit) > 255 or not UNIT.fullmatch(unit):
        receipt["first_missing_signal"] = "invalid-unit"
        return receipt
    if scope not in ("system", "owner", "hermes"):
        receipt["first_missing_signal"] = "invalid-scope"
        return receipt
    if scope == "hermes" and (unit != "hermes-dashboard.service" or action != "restart"):
        receipt["first_missing_signal"] = "hermes-scope-not-permitted"
        return receipt
    prefix = ["systemctl"] + (["--user", "-M", f"{scope}@.host"] if scope in ("owner", "hermes") else [])
    if action == "restart" and planned:
        receipt.update(ok=True, command=[*prefix, action, unit], first_missing_signal="none")
        return receipt
    code, initial = _show(prefix, unit)
    receipt["observed"] = dict(initial)
    receipt["readback"] = initial
    if initial["load_state"] == "not-found":
        receipt["first_missing_signal"] = "unit-not-found"
        return receipt
    if code != 0 or initial["load_state"] is None:
        receipt["first_missing_signal"] = "unit-load-state-read-failed"
        return receipt
    if initial["load_state"] != "loaded":
        receipt["first_missing_signal"] = "unit-not-loaded"
        return receipt
    if action in ("start", "stop") and initial["active_state"] is None:
        receipt["first_missing_signal"] = "unit-active-state-read-failed"
        return receipt
    if action in ("enable", "disable") and initial["unit_file_state"] is None:
        receipt["first_missing_signal"] = "unit-file-state-read-failed"
        return receipt
    command_code = 0
    if action != "status":
        receipt["command"] = [*prefix, action, unit]
        receipt["mutation_performed"] = (
            (action == "start" and initial["active_state"] in ("inactive", "failed"))
            or (action == "stop" and initial["active_state"] in ("active", "reloading", "activating"))
            or action == "restart"
            or (action == "enable" and initial["unit_file_state"] != "enabled")
            or (action == "disable" and initial["unit_file_state"] != "disabled")
        )
        command_code, _ = _run(receipt["command"], timeout=deadline_seconds)
        receipt["returncode"] = command_code
    read_code, readback = _show(prefix, unit)
    receipt["readback"] = readback
    if action == "status":
        receipt["returncode"] = read_code
    if command_code != 0:
        receipt["first_missing_signal"] = "unit-command-failed"
    elif read_code != 0 or any(value is None for value in readback.values()):
        receipt["first_missing_signal"] = "unit-readback-failed"
    elif readback["load_state"] != "loaded":
        receipt["first_missing_signal"] = "unit-readback-not-loaded"
    else:
        receipt["ok"] = True
        receipt["first_missing_signal"] = "none"
    return receipt

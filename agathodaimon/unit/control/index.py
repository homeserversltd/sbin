"""Control a system or owner systemd unit through fixed argument vectors."""
from __future__ import annotations

import json
import re
import subprocess

from agathodaimon import _envelope

SCHEMA = "agathodaimon.unit.control.v1"
OWNER = "owner"  # Same owner identity as console/restart.
ACTIONS = frozenset({"start", "stop", "restart", "enable", "disable", "status"})
UNIT = re.compile(r"[A-Za-z0-9_:][A-Za-z0-9_.:-]*(?:@[A-Za-z0-9_:][A-Za-z0-9_.:-]*)?\.(?:service|target|mount|path)\Z")
PROPERTIES = {"LoadState": "load_state", "ActiveState": "active_state", "SubState": "sub_state", "UnitFileState": "unit_file_state"}


def _run(argv):
    try:
        result = subprocess.run(argv, text=True, capture_output=True, check=False, timeout=30)
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


def control(action, unit, scope):
    receipt = {"schema": SCHEMA, "ok": False, "action": action, "unit": unit, "scope": scope,
               "command": None, "returncode": None,
               "readback": {name: None for name in PROPERTIES.values()},
               "mutation_performed": False, "first_missing_signal": None}
    if not isinstance(action, str) or action not in ACTIONS:
        receipt["first_missing_signal"] = "invalid-action"
        return receipt
    if not isinstance(unit, str) or len(unit) > 255 or not UNIT.fullmatch(unit):
        receipt["first_missing_signal"] = "invalid-unit"
        return receipt
    if scope not in ("system", "owner"):
        receipt["first_missing_signal"] = "invalid-scope"
        return receipt
    prefix = ["systemctl"] + (["--user", "-M", f"{OWNER}@.host"] if scope == "owner" else [])
    code, initial = _show(prefix, unit)
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
    command_code = 0
    if action != "status":
        receipt["command"] = [*prefix, action, unit]
        receipt["mutation_performed"] = True
        command_code, _ = _run(receipt["command"])
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


def main(argv=None):
    try:
        request = _envelope.read_fields("action", "unit", "scope")
    except _envelope.EnvelopeError:
        receipt = control(None, None, None)
        receipt["first_missing_signal"] = "invalid-envelope"
    else:
        receipt = control(request.payload.get("action"), request.payload.get("unit"), request.payload.get("scope"))
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

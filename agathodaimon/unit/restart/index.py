"""Restart one system or owner unit."""
import json
from agathodaimon import _envelope
from agathodaimon.unit import _control

def main(argv=None):
    try:
        request = _envelope.read_fields("unit", "scope", "deadline_seconds", "dry-run")
    except _envelope.EnvelopeError:
        receipt = _control.control("restart", None, None)
        receipt["first_missing_signal"] = "invalid-envelope"
    else:
        planned = request.payload.get("dry-run", False)
        if not isinstance(planned, bool):
            receipt = _control.control("restart", None, None)
            receipt["first_missing_signal"] = "invalid-dry-run"
        else:
            receipt = _control.control("restart", request.payload.get("unit"), request.payload.get("scope"), request.payload.get("deadline_seconds", 30), planned=planned)
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "agathodaimon.unit.restart.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

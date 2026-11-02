"""Enable one system or owner unit."""
import json
from agathodaimon import _envelope
from agathodaimon.unit import _control

def main(argv=None):
    try:
        request = _envelope.read_fields("unit", "scope", "deadline_seconds")
    except _envelope.EnvelopeError:
        receipt = _control.control("enable", None, None)
        receipt["first_missing_signal"] = "invalid-envelope"
    else:
        receipt = _control.control("enable", request.payload.get("unit"), request.payload.get("scope"), request.payload.get("deadline_seconds", 30))
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "agathodaimon.unit.enable.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

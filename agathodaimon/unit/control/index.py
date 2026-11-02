"""Alias of the six unit stops until its last caller moves."""
import json
from agathodaimon import _envelope
from agathodaimon.unit import _control

def main(argv=None):
    try:
        request = _envelope.read_fields("action", "unit", "scope")
    except _envelope.EnvelopeError:
        receipt = _control.control(None, None, None)
        receipt["first_missing_signal"] = "invalid-envelope"
    else:
        receipt = _control.control(request.payload.get("action"), request.payload.get("unit"), request.payload.get("scope"))
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

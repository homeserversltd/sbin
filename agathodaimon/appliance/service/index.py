"""Alias of the seven service stops until its last caller moves."""
import json
from agathodaimon import _envelope
from agathodaimon.appliance.service import _service

def main(argv=None):
    try:
        request = _envelope.read_fields("action", "service")
    except _envelope.EnvelopeError:
        receipt = _service._receipt(first_missing_signal="portal-service-payload-invalid")
    else:
        receipt = _service.control(request.payload.get("action"), request.payload.get("service"))
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

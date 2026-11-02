"""Stop one allowlisted appliance service."""
import json
from agathodaimon import _envelope
from agathodaimon.appliance.service import _service

def main(argv=None):
    try:
        request = _envelope.read_fields("service")
    except _envelope.EnvelopeError:
        receipt = _service._receipt(first_missing_signal="portal-service-payload-invalid")
    else:
        receipt = _service.control("stop", request.payload.get("service"))
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.staff.appliance-service.stop.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

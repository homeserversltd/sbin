"""DNS read stop."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns._manager import DnsError, DnsManager


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError as exc:
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    else:
        try:
            receipt = {"actuator": "network.dns.read", "action": "read", "ok": True, "result": DnsManager().read(), "mutationPerformed": False, "firstMissingSignal": "none"}
        except DnsError as exc:
            receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.dns.read.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

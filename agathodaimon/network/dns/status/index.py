"""DNS status stop."""
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
            receipt = DnsManager().read_status()
        except DnsError as exc:
            receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.dns.status.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

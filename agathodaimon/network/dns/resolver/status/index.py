"""DNS resolver/status stop."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns._resolver import resolver_control


def main(argv=None):
    try:
        request = _envelope.read_fields()
        receipt = resolver_control("status")
    except (_envelope.EnvelopeError) as exc:
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    else:
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.dns.resolver.status.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

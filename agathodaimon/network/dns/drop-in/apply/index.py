"""DNS drop-in apply: target, dropIn, dry-run."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns import _mutate
from agathodaimon.network.dns._manager import DnsError, DnsManager


def main(argv=None):
    try:
        request = _envelope.read_fields('target', 'dropIn', 'dry-run')
    except _envelope.EnvelopeError as exc:
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    else:
        try:
            receipt = _mutate.stop_apply(DnsManager(), request.payload.get("target"), request.payload.get("dropIn"), request.payload.get("dry-run", False))
        except (DnsError, OSError) as exc:
            receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.dns.drop-in.apply.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

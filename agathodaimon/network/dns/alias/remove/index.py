"""DNS alias remove: label, hostname."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns import _mutate
from agathodaimon.network.dns._manager import DnsError, DnsManager


def main(argv=None):
    try:
        request = _envelope.read_fields('label', 'hostname')
    except _envelope.EnvelopeError as exc:
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    else:
        try:
            if not all(isinstance(request.payload.get(key), str) for key in ('label', 'hostname')):
                raise DnsError("dns-input-invalid")
            receipt = _mutate.alias(DnsManager(), "remove", request.payload.get('label'), request.payload.get('hostname'))
        except (DnsError, OSError) as exc:
            receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.dns.alias.remove.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

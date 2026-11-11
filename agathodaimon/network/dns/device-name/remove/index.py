"""DNS device-name remove: hostname, ip."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns import _mutate
from agathodaimon.network.dns._manager import DnsError, DnsManager


def main(argv=None):
    try:
        request = _envelope.read_fields('hostname', 'ip')
    except _envelope.EnvelopeError as exc:
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    else:
        try:
            if not all(isinstance(request.payload.get(key), str) for key in ('hostname', 'ip')):
                raise DnsError("dns-input-invalid")
            receipt = _mutate.device_name(DnsManager(), "remove", request.payload.get('hostname'), request.payload.get('ip'))
        except (DnsError, OSError) as exc:
            receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

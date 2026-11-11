"""DNS device-name create: hostname, ip, move, adopt."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns._manager import DnsError, DnsManager


def main(argv=None):
    try:
        request = _envelope.read_fields('hostname', 'ip', 'move', 'adopt')
    except _envelope.EnvelopeError as exc:
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    else:
        try:
            hostname = request.payload.get('hostname')
            ip = request.payload.get('ip')
            move = request.payload.get('move', False)
            adopt = request.payload.get('adopt', False)
            if not isinstance(hostname, str) or not isinstance(move, bool) or not isinstance(adopt, bool):
                raise DnsError("dns-input-invalid")
            if not isinstance(ip, str) and not (adopt and ip is None):
                raise DnsError("dns-input-invalid")
            receipt = DnsManager().create_device_name(hostname, ip, move=move, adopt=adopt)
            receipt |= {"actuator": "network.dns.device_name.create", "ok": True, "firstMissingSignal": "none"}
        except (DnsError, OSError) as exc:
            receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

"""Read the fused identity roster."""
import json
from agathodaimon import _envelope
from agathodaimon._nidus.refusal import named_signal
from agathodaimon.network.dhcp._manager import DhcpError
from agathodaimon.network.dns._manager import DnsError
from agathodaimon.network.identity._claim import IdentityError
from agathodaimon.network.identity._roster import _device_projection


def main(argv=None):
    request = None
    try:
        request = _envelope.read_fields()
        devices, names = _device_projection()
        receipt = {"ok": True, "actuator": "network.identity.device_list", "action": "device_list", "result": devices, "service_names": names, "mutationPerformed": False, "firstMissingSignal": "none"}
    except (DhcpError, DnsError, IdentityError, _envelope.EnvelopeError) as exc:
        signal = named_signal(exc, "identity-device-list")
        receipt = {"ok": False, "mutationPerformed": False, "firstMissingSignal": signal}
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

"""Observe, compare and plan a device identity."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dhcp._manager import DhcpError
from agathodaimon.network.dns._manager import DnsError
from agathodaimon.network.identity._plan import plan_identity


def main(argv=None):
    request = None
    try:
        request = _envelope.read_fields('mac', 'hostname', 'ip', 'move', 'settle')
        result = plan_identity(request.payload)
        signal = result['plan']['signal']
        if signal is None and request.payload['settle'] and not result['diff']['empty']:
            signal = 'identity-did-not-take'
        receipt = {'ok': signal is None, 'actuator': 'network.identity.device_plan', 'action': 'device_plan', 'result': result, 'mutationPerformed': False, 'firstMissingSignal': signal or 'none'}
    except (DhcpError, DnsError, _envelope.EnvelopeError, OSError, ValueError) as exc:
        receipt = {'ok': False, 'mutationPerformed': False, 'firstMissingSignal': str(exc)}
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(',', ':')))
    return 0 if receipt['ok'] else 1

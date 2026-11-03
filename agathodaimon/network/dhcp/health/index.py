"""DHCP health. Fields: none."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        return _stop.invalid('caduceus.network.dhcp.health.v1')
    return _stop.run(request, 'caduceus.network.dhcp.health.v1', lambda manager: manager.health(), (), boundary=False)

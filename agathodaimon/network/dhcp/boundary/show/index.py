"""DHCP boundary show. Fields: none."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        return _stop.invalid('caduceus.network.dhcp.boundary.show.v1')
    return _stop.run(request, 'caduceus.network.dhcp.boundary.show.v1', lambda manager: manager.boundary(), (), boundary=True)

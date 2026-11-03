"""DHCP remove-reservation. Fields: identifier."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('identifier')
    except _envelope.EnvelopeError:
        return _stop.invalid('caduceus.network.dhcp.remove-reservation.v1')
    return _stop.run(request, 'caduceus.network.dhcp.remove-reservation.v1', lambda manager, identifier: manager.remove_reservation(identifier), ('identifier',), boundary=False)

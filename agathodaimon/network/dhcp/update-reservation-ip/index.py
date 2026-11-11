"""DHCP update-reservation-ip. Fields: identifier, new_ip."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('identifier', 'new_ip')
    except _envelope.EnvelopeError:
        return _stop.invalid()
    return _stop.run(request, lambda manager, identifier, new_ip: manager.update_reservation_ip(identifier, new_ip), ('identifier', 'new_ip'), boundary=False)

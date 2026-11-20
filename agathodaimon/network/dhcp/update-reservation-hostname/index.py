"""DHCP update-reservation-hostname. Fields: identifier, hostname."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('identifier', 'hostname')
    except _envelope.EnvelopeError:
        return _stop.invalid()
    return _stop.run(
        request,
        lambda manager, identifier, hostname: manager.update_reservation_hostname(identifier, hostname),
        _stop.RENAME_FIELDS,
    )
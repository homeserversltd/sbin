"""DHCP update-pool-boundary. Fields: max_reservations."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('max_reservations')
    except _envelope.EnvelopeError:
        return _stop.invalid('caduceus.network.dhcp.update-pool-boundary.v1')
    return _stop.run(request, 'caduceus.network.dhcp.update-pool-boundary.v1', lambda manager, max_reservations: manager.update_pool_boundary(max_reservations), ('max_reservations',), boundary=False)

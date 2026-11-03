"""DHCP add-reservation. Fields: hw_address, ip_address, hostname."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('hw_address', 'ip_address', 'hostname')
    except _envelope.EnvelopeError:
        return _stop.invalid('caduceus.network.dhcp.add-reservation.v1')
    return _stop.run(request, 'caduceus.network.dhcp.add-reservation.v1', lambda manager, hw_address, ip_address, hostname: manager.add_reservation(hw_address, ip_address, hostname), ('hw_address', 'ip_address', 'hostname'), boundary=False)

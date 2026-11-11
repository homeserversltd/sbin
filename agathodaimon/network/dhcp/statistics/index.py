"""DHCP statistics. Fields: none."""
from agathodaimon import _envelope
from agathodaimon.network.dhcp import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        return _stop.invalid()
    return _stop.run(request, lambda manager: manager.get_statistics(), (), boundary=False)

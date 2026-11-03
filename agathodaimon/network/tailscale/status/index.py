"""Read the live and declared Tailscale state."""
from agathodaimon import _envelope
from agathodaimon.network.tailscale import _stop, _core


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        request = None
    return _stop.finish("status", _core._status_receipt, request)

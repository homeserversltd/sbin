"""Bring Tailscale down."""
from agathodaimon import _envelope
from agathodaimon.network.tailscale import _stop, _core


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        request = None
    return _stop.finish("down", _core._down_receipt, request)

"""Bring Tailscale up and offer the home network route."""
from agathodaimon import _envelope
from agathodaimon.network.tailscale import _stop, _core


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        request = None
    return _stop.finish("up", _core._up_receipt, request)

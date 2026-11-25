"""Change the tailnet name."""
from agathodaimon import _envelope
from agathodaimon.network.tailscale import _stop, _core


def main(argv=None):
    try:
        request = _envelope.read_fields("name", "dry-run")
    except _envelope.EnvelopeError:
        request = None
    return _stop.finish("tailnet", _core._tailnet, request, request.payload.get("name", "") if request else "", request.payload.get("dry-run", False) if request else False)

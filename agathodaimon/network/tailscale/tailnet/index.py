"""Change the tailnet name; backup-dir optionally names an absolute backup directory."""
from agathodaimon import _envelope
from agathodaimon.network.tailscale import _stop, _core


def main(argv=None):
    try:
        request = _envelope.read_fields("name", "backup-dir")
    except _envelope.EnvelopeError:
        request = None
    return _stop.finish("tailnet", _core._tailnet, request, request.payload.get("name", "") if request else "", request.payload.get("backup-dir") if request else None)

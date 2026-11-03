"""Authenticate using key from the envelope payload; never place a secret in argv."""
from agathodaimon import _envelope
from agathodaimon.network.tailscale import _stop, _core


def main(argv=None):
    try:
        request = _envelope.read_fields("key")
    except _envelope.EnvelopeError:
        request = None
    return _stop.finish("authkey", _core._authkey_receipt, request, request.payload.get("key") if request else None)

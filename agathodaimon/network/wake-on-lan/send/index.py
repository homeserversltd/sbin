"""Send a wake-on-LAN packet to mac using broadcast (default 255.255.255.255)."""
import json

from importlib import import_module
from agathodaimon import _envelope

_wol = import_module("agathodaimon.network.wake-on-lan._wol")


def main(argv=None):
    try:
        request = _envelope.read_fields("mac", "broadcast")
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "error": "invalid-envelope", "firstMissingSignal": "wake-envelope-invalid"}
    else:
        try:
            receipt = _wol.send(request.payload.get("mac"), request.payload.get("broadcast", "255.255.255.255"))
        except ValueError as exc:
            receipt = {"ok": False, "error": str(exc)}
        error = receipt.get("error", "")
        if receipt["ok"]:
            receipt["firstMissingSignal"] = "none"
        elif error in {"invalid MAC", "invalid broadcast"}:
            receipt["firstMissingSignal"] = {"invalid MAC": "wake-mac-invalid", "invalid broadcast": "wake-broadcast-invalid"}[error]
        else:
            receipt["firstMissingSignal"] = "wake-send-failed"
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

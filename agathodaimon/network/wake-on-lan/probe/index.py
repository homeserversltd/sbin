"""Probe the IPv4 address ip for wake-on-LAN reachability."""
import json
import base64
from importlib import import_module
from agathodaimon import _envelope

_wol = import_module("agathodaimon.network.wake-on-lan._wol")


def main(argv=None):
    try:
        request = _envelope.read_fields("ip")
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "error": "invalid-envelope", "firstMissingSignal": "wake-envelope-invalid"}
    else:
        try:
            receipt = _wol.probe(request.payload.get("ip"))
        except ValueError as exc:
            receipt = {"ok": False, "error": str(exc)}
        error = receipt.get("error", "")
        if receipt["ok"]:
            receipt["firstMissingSignal"] = "none"
        elif error == "invalid IP":
            receipt["firstMissingSignal"] = "wake-ip-invalid"
        else:
            encoded = base64.b32encode(error.encode("utf-8", "surrogatepass")).decode("ascii").lower().rstrip("=")
            receipt["firstMissingSignal"] = "wake-helper-x" + encoded
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.wake-on-lan.probe.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

"""Probe the IPv4 address ip for wake-on-LAN reachability."""
import json
from importlib import import_module
from agathodaimon import _envelope

_wol = import_module("agathodaimon.network.wake-on-lan._wol")


def main(argv=None):
    try:
        request = _envelope.read_fields("ip")
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "error": "invalid-envelope"}
    else:
        try:
            receipt = _wol.probe(request.payload.get("ip"))
        except ValueError as exc:
            receipt = {"ok": False, "error": str(exc)}
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.wake-on-lan.probe.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

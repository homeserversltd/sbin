"""Transmission VPN staff face."""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any, Mapping

from agathodaimon.transmission import runtime as rt

SCHEMA = "caduceus.transmission.vpn.v1"


def _hold_transition(request: Any) -> bool:
    if getattr(request, "transition", None) == "hold":
        return True
    value = getattr(request, "value", None)
    if not isinstance(value, Mapping):
        return False
    payload = value.get("payload")
    return (value.get("transition") == "hold"
            or isinstance(payload, Mapping) and payload.get("transition") == "hold")


def _dispatch_hold(request: Any) -> dict[str, Any]:
    path = Path(__file__).resolve().parent / "hold" / "index.py"
    spec = importlib.util.spec_from_file_location(
        "agathodaimon.face_transmission_vpn_hold", path)
    if spec is None or spec.loader is None:
        raise rt.TransmissionError("transmission-hold-band-unreadable", "vpn-hold-load")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "agathodaimon"
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise rt.TransmissionError("transmission-hold-band-unreadable", "vpn-hold-load") from None
    dispatch = getattr(module, "dispatch", None)
    if not callable(dispatch):
        raise rt.TransmissionError("transmission-hold-band-incomplete", "vpn-hold-load")
    result = dispatch(request)
    if not isinstance(result, dict):
        raise rt.TransmissionError("transmission-hold-result-invalid", "vpn-hold")
    return result


def main(argv=None) -> int:
    del argv
    request = rt.read_request(known_fields=("provider", "flags"),
                              declared_flags=("vpn",))
    if _hold_transition(request):
        result = _dispatch_hold(request)
        return rt.print_receipt(rt.finish(result, request))

    providers, default = rt._provider_metadata()
    result = {
        "schema": SCHEMA,
        "ok": True,
        "providers": providers,
        "defaultProvider": default,
    }
    return rt.print_receipt(rt.finish(result, request, successful_read=True))

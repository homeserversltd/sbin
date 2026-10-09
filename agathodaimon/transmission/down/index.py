"""Stop only the native Transmission unit and verify PartOf cleanup."""
from __future__ import annotations

import time
from typing import Any

from agathodaimon.transmission import runtime as rt


_READBACK_TIMEOUT = 180
_TERMINAL_NONACTIVE_STATES = {"inactive", "failed", "unknown", "maintenance"}


def _tunnel_present(provider: str) -> tuple[bool, bool]:
    names = rt.namespace_names()
    present = rt.VPN_NAMESPACE in names
    if not present:
        return False, False
    face = rt.provider_face(provider)
    interface = getattr(face, "TUNNEL_INTERFACE", None)
    if not isinstance(interface, str):
        raise rt.TransmissionError("transmission-provider-interface-invalid", "final-readback")
    return True, bool(rt._link_data(rt.VPN_NAMESPACE, interface))


def dispatch(request: Any) -> dict[str, Any]:
    result = rt.receipt(rt.SCHEMA_DOWN)
    result["rpcPort"] = None
    rung = "provider"
    try:
        provider, _providers = rt.resolve_bound_provider(request)
        result["provider"] = provider
        rt._stamp(result, "provider", {"selected": provider}, False, "resolve", {"provider": provider})

        rung = "daemon"
        native_before = rt.unit_state(rt.NATIVE_UNIT, step="native-preflight")
        hold_unit = rt.HOLD_UNIT.format(provider)
        hold_before = rt.unit_state(hold_unit, step="hold-preflight")
        result["nativeUnit"] = rt.NATIVE_UNIT
        result["holdUnit"] = hold_unit
        result["nativeStateBefore"] = native_before
        result["holdStateBefore"] = hold_before
        stopped = rt.run([rt.SYSTEMCTL, "stop", rt.NATIVE_UNIT],
                         timeout=180, step="native-stop")
        if stopped.returncode != 0:
            raise rt.TransmissionError("transmission-native-stop-failed", "daemon",
                                       {"nativeUnit": rt.NATIVE_UNIT,
                                        "nativeStateBefore": native_before,
                                        "holdUnit": hold_unit,
                                        "holdStateBefore": hold_before})
        rt._stamp(result, "daemon", {"unit": rt.NATIVE_UNIT, "state": native_before},
                  [rt.NATIVE_UNIT, hold_unit], "stop-native-unit-for-PartOf-propagation",
                  {"stopRequested": True, "returnCode": stopped.returncode})

        rung = "hold"
        deadline = time.monotonic() + _READBACK_TIMEOUT
        final: dict[str, Any] = {}
        while True:
            native_state = rt.unit_state(rt.NATIVE_UNIT, step="native-stop-readback")
            hold_state = rt.unit_state(hold_unit, step="hold-PartOf-readback")
            namespace_present, tunnel_present = _tunnel_present(provider)
            final = {"nativeState": native_state, "holdUnit": hold_unit,
                     "holdState": hold_state, "namespacePreserved": namespace_present,
                     "tunnelInterfacePresent": tunnel_present}
            if (native_state in _TERMINAL_NONACTIVE_STATES
                    and hold_state in _TERMINAL_NONACTIVE_STATES
                    and not tunnel_present):
                break
            if time.monotonic() >= deadline:
                raise rt.TransmissionError("transmission-down-readback-timeout", "final-readback", final)
            time.sleep(1)
        result["nativeState"] = native_state
        result["holdState"] = hold_state
        result["namespacePreserved"] = namespace_present
        rt._stamp(result, "hold", {"unit": hold_unit, "stateBefore": hold_before},
                  [hold_unit] if hold_before not in _TERMINAL_NONACTIVE_STATES else [],
                  "read-PartOf-state-without-direct-stop", {"state": hold_state})

        rung = "final-readback"
        rt._stamp(result, "final-readback", {"namespacePresent": namespace_present}, False,
                  "read-native-and-PartOf-hold-terminal-nonactive-and-tunnel-absent", final)
        result["ok"] = True
        result["firstMissingSignal"] = "none"
        return rt.finish(result, request)
    except Exception as failure:
        if isinstance(failure, rt.TransmissionError):
            result["firstMissingSignal"] = failure.signal_name
            result["failedRung"] = failure.step
            if failure.detail:
                result.update(failure.detail)
        else:
            result["firstMissingSignal"] = "transmission-down-failed"
            result["failedRung"] = rung
        result["ok"] = False
        if not result["steps"] or result["steps"][-1].get("step") != result["failedRung"]:
            rt._stamp(result, result["failedRung"], {"completed": False}, False,
                      "failed-before-rung-completion", {"ok": False})
        return rt.finish(result, request)


def main(argv=None) -> int:
    del argv
    request = None
    try:
        request = rt.read_request()
        result = dispatch(request)
    except Exception as failure:
        result = rt.finish(rt.failure_receipt(rt.SCHEMA_DOWN, failure), request)
    return rt.print_receipt(result)


if __name__ == "__main__":
    raise SystemExit(main())

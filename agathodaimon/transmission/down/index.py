"""Stop only the provider hold and Transmission units, in contract order."""
from __future__ import annotations
from typing import Any

from agathodaimon.transmission import runtime as rt


def dispatch(request: Any) -> dict[str, Any]:
    result = rt.receipt(rt.SCHEMA_DOWN)
    provider: str | None = None
    rung = "provider"
    try:
        provider, _providers = rt.resolve_provider(request)
        result["provider"] = provider
        rt._stamp(result, "provider", {"selected": provider}, False, "resolve", {"provider": provider})

        rung = "portal-row"
        rpc_port = rt.portal_port()
        result["rpcPort"] = rpc_port
        daemon_unit = rt.DAEMON_UNIT.format(rpc_port)
        daemon_before = rt.unit_active(daemon_unit, step="daemon-preflight")
        rt.stop_unit(daemon_unit, "daemon-stop")
        daemon_after = rt.unit_active(daemon_unit, step="daemon-stop-readback")
        rt._stamp(result, "daemon", {"unit": daemon_unit, "active": daemon_before},
                  [daemon_unit] if daemon_before else [],
                  "stop-if-active" if daemon_before else "preserve-inactive",
                  {"active": daemon_after})
        if daemon_after:
            raise rt.TransmissionError("transmission-daemon-stop-readback-failed", "daemon")

        rung = "hold"
        hold_unit = rt.HOLD_UNIT.format(provider)
        hold_before = rt.unit_active(hold_unit, step="hold-preflight")
        rt.stop_unit(hold_unit, "hold-stop")
        hold_after = rt.unit_active(hold_unit, step="hold-stop-readback")
        rt._stamp(result, "hold", {"unit": hold_unit, "active": hold_before},
                  [hold_unit] if hold_before else [],
                  "stop-if-active" if hold_before else "preserve-inactive",
                  {"active": hold_after})
        if hold_after:
            raise rt.TransmissionError("transmission-hold-stop-readback-failed", "hold")

        rung = "final-readback"
        names = rt.namespace_names()
        namespace_present = rt.VPN_NAMESPACE in names
        face = rt.provider_face(provider)
        interface = getattr(face, "TUNNEL_INTERFACE", None)
        if not isinstance(interface, str):
            raise rt.TransmissionError("transmission-provider-interface-invalid", "final-readback")
        tunnel_present = False
        if namespace_present:
            rows = rt._link_data(rt.VPN_NAMESPACE, interface)
            tunnel_present = bool(rows)
        hold_final = rt.unit_active(hold_unit, step="final-readback")
        daemon_final = rt.unit_active(daemon_unit, step="final-readback")
        final = {"holdActive": hold_final, "daemonActive": daemon_final,
                 "namespacePreserved": namespace_present, "tunnelInterfacePresent": tunnel_present}
        rt._stamp(result, "final-readback", {"namespacePresent": namespace_present}, False,
                  "read-units-and-tunnel-interface-only", final)
        if hold_final or daemon_final or tunnel_present:
            raise rt.TransmissionError("transmission-down-readback-incomplete", "final-readback")
        result["ok"] = True
        result["firstMissingSignal"] = "none"
        result["namespacePreserved"] = namespace_present
        return rt.finish(result, request)
    except Exception as failure:
        if isinstance(failure, rt.TransmissionError):
            result["firstMissingSignal"] = failure.signal_name
            result["failedRung"] = failure.step
        else:
            result["firstMissingSignal"] = "transmission-down-failed"
            result["failedRung"] = rung
        if result.get("firstMissingSignal") == "provider-unknown":
            try:
                result["providers"] = rt._provider_metadata()[0]
            except Exception:
                pass
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

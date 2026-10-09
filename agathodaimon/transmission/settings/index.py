"""Apply Transmission RPC settings after bounded readiness."""
from __future__ import annotations

from typing import Any

from agathodaimon.transmission import runtime as rt


_RPC_READY_TIMEOUT = 60


def dispatch(request: Any) -> dict[str, Any]:
    provider: str | None = None
    result = rt.receipt(rt.SCHEMA_SETTINGS)
    try:
        provider, _providers = rt.resolve_bound_provider(request)
        result["provider"] = provider
        rt._stamp(result, "provider", {"selected": provider}, False, "resolve-bound-provider",
                  {"provider": provider, "nativeUnit": rt.NATIVE_UNIT})

        rpc_port = rt.portal_port()
        result["rpcPort"] = rpc_port
        ready_state = rt.wait_for_rpc_ready(rpc_port, timeout=_RPC_READY_TIMEOUT)
        rt._stamp(result, "rpc-readiness", {"rpcPort": rpc_port}, False,
                  "bounded-session-get-until-ready", {"ready": True})

        hold_unit = rt.HOLD_UNIT.format(provider)
        hold_state = rt.unit_state(hold_unit, step="forward-state-hold-readback")
        forward_state = rt.read_provider_state(provider)
        peer_port = None
        if (hold_state in {"active", "reloading"}
                and rt.state_is_fresh(forward_state)):
            candidate = forward_state.get("forwardPort") if forward_state is not None else None
            if (isinstance(candidate, int) and not isinstance(candidate, bool)
                    and 1 <= candidate <= 65535):
                peer_port = candidate
        result["holdUnit"] = hold_unit
        result["holdState"] = hold_state
        result["peerPortApplied"] = peer_port is not None
        settings = rt.rpc_set_download_settings(rpc_port, peer_port)
        result["settings"] = settings
        result["peerPort"] = settings.get("peer-port")
        rt._stamp(result, "settings", {
            "rpcPort": rpc_port,
            "holdState": hold_state,
            "forwardStateFresh": peer_port is not None,
        }, ["Transmission directory settings"] + (["peer-port"] if peer_port is not None else []),
           "session-set-then-session-get", settings)
        result["ok"] = True
        result["firstMissingSignal"] = "none"
    except Exception as failure:
        if isinstance(failure, rt.TransmissionError):
            result["firstMissingSignal"] = failure.signal_name
            result["failedRung"] = failure.step
            result["failedCommandError"] = {"signal": failure.signal_name, "step": failure.step}
            if failure.detail:
                result.update(failure.detail)
        else:
            result["firstMissingSignal"] = "transmission-settings-failed"
            result["failedRung"] = "settings"
            result["failedCommandError"] = {
                "signal": result["firstMissingSignal"], "step": "settings"}
        result["ok"] = False
        rt._stamp(result, "error", {"failedRung": result.get("failedRung")},
                  ["Transmission settings"], "report-settings-failure", {"ok": False})
    return rt.finish(result, request)


def main(argv=None) -> int:
    del argv
    request = None
    try:
        request = rt.read_request(known_fields=("provider", "flags"), declared_flags=("vpn",))
        result = dispatch(request)
    except Exception as failure:
        result = rt.finish(rt.failure_receipt(rt.SCHEMA_SETTINGS, failure), request)
    return rt.print_receipt(result)


if __name__ == "__main__":
    raise SystemExit(main())

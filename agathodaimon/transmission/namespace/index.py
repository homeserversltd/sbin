"""Native-unit namespace and firewall preparation step."""
from __future__ import annotations

from typing import Any

from agathodaimon.transmission import runtime as rt


def dispatch(request: Any) -> dict[str, Any]:
    provider: str | None = None
    result = rt.receipt(rt.SCHEMA_NAMESPACE)
    try:
        options, _providers = rt.resolve_vpn(request)
        provider = options["provider"]
        result["provider"] = provider
        result["protocol"] = options["protocol"]
        rt._stamp(result, "provider", {"selected": provider, "protocol": options["protocol"]},
                  False, "compose-vpn-options-from-config-and-envelope", {"provider": provider})
        rpc_port = rt.portal_port()
        result["rpcPort"] = rpc_port
        state = rt.ensure_namespace(provider, rpc_port, options)
        rt._stamp(result, "namespace", state.get("observed"), state.get("could-change"),
                  state.get("attempt"), state.get("finalState"))
        result["nextStartConfigurationSource"] = rt.CONFIG_PATH
        result["unitOverridePropagated"] = False
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
            result["firstMissingSignal"] = "transmission-namespace-setup-failed"
            result["failedRung"] = "namespace"
            result["failedCommandError"] = {"signal": result["firstMissingSignal"], "step": "namespace"}
        result["ok"] = False
        rt._stamp(result, "error", {"failedRung": result.get("failedRung")},
                  ["vpn namespace, veth, host rules, and namespace output chain"],
                  "report-namespace-failure", {"ok": False})
    return rt.finish(result, request)


def main(argv=None) -> int:
    del argv
    request = None
    try:
        request = rt.read_request(known_fields=("provider", "flags"), declared_flags=("vpn",))
        result = dispatch(request)
    except Exception as failure:
        result = rt.finish(rt.failure_receipt(rt.SCHEMA_NAMESPACE, failure), request)
    return rt.print_receipt(result)


if __name__ == "__main__":
    raise SystemExit(main())

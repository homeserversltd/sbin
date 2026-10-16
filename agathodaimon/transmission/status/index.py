"""Read the single five-condition Transmission onness projection."""
from __future__ import annotations
from typing import Any, Mapping

from agathodaimon.transmission import runtime as rt


def dispatch(request: Any) -> dict[str, Any]:
    try:
        options, providers = rt.resolve_vpn(request)
        provider = options["provider"]
        if not isinstance(provider, str):
            raise rt.TransmissionError("transmission-vpn-provider-unknown", "provider-resolution")
        value = rt.status_read(provider, providers, options)
    except rt.TransmissionError as failure:
        try:
            providers = rt._provider_metadata()[0]
        except Exception:
            providers = []
        value = {
            "schema": rt.SCHEMA_STATUS, "ok": False, "on": False,
            "provider": None, "providers": providers,
            "conditions": {"namespace": False, "tunnel": False, "forward": False,
                           "daemon": False, "peerPort": False},
            "forwardPort": None, "peerPort": None, "rpcPort": None,
            "firstMissingSignal": failure.signal_name,
            "failedStep": failure.step, "steps": [],
        }
        if failure.detail:
            value.update(failure.detail)
        if failure.signal_name in {"provider-unknown", "transmission-vpn-provider-unknown"}:
            try:
                _present, vpn_flags = rt._flag_vpn(request)
                if isinstance(vpn_flags, Mapping) and "provider" in vpn_flags:
                    value["unknownProvider"] = vpn_flags.get("provider")
                else:
                    alias_present, alias = rt._provider_alias(request)
                    if alias_present:
                        value["unknownProvider"] = alias
            except rt.TransmissionError:
                pass
    value = rt.finish(value, request, successful_read=value.get("ok") is True)
    return value


def main(argv=None) -> int:
    del argv
    request = None
    try:
        request = rt.read_request()
        result = dispatch(request)
    except Exception as failure:
        result = {
            "schema": rt.SCHEMA_STATUS, "ok": False, "on": False,
            "provider": None,
            "conditions": {"namespace": False, "tunnel": False, "forward": False,
                           "daemon": False, "peerPort": False},
            "forwardPort": None, "peerPort": None, "rpcPort": None,
            "firstMissingSignal": "transmission-request-invalid",
            "steps": [],
        }
        if isinstance(failure, rt.TransmissionError):
            result["firstMissingSignal"] = failure.signal_name
            result["failedStep"] = failure.step
        result = rt.finish(result, request)
    return rt.print_receipt(result)


if __name__ == "__main__":
    raise SystemExit(main())

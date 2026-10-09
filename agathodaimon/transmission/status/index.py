"""Read the single five-condition Transmission onness projection."""
from __future__ import annotations
from typing import Any

from agathodaimon.transmission import runtime as rt


def dispatch(request: Any) -> dict[str, Any]:
    try:
        provider, providers = rt.resolve_provider(request)
        value = rt.status_read(provider, providers)
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
        if failure.signal_name == "provider-unknown":
            raw = getattr(request, "value", {})
            payload = raw.get("payload") if isinstance(raw, dict) else None
            for source in (raw, payload):
                if not isinstance(source, dict):
                    continue
                flags = source.get("flags")
                if isinstance(flags, dict):
                    vpn = flags.get("vpn")
                    if isinstance(vpn, dict) and "provider" in vpn:
                        value["unknownProvider"] = vpn.get("provider")
                        break
                if "provider" in source:
                    value["unknownProvider"] = source.get("provider")
                    break
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

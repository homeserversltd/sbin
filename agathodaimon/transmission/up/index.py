"""Start the native Transmission unit and verify bounded onness."""
from __future__ import annotations

import time
from typing import Any

from agathodaimon.transmission import runtime as rt


_ONNESS_TIMEOUT = 180


def _unknown_provider(request: Any) -> Any:
    raw = getattr(request, "value", {})
    payload = raw.get("payload") if isinstance(raw, dict) else None
    for source in (raw, payload):
        if not isinstance(source, dict):
            continue
        flags = source.get("flags")
        if isinstance(flags, dict):
            vpn = flags.get("vpn")
            if isinstance(vpn, dict) and "provider" in vpn:
                return vpn.get("provider")
        if "provider" in source:
            return source.get("provider")
    return None


def _hold_readback(unit: str) -> tuple[str, str | None]:
    try:
        return rt.unit_state(unit, step="hold-start-readback"), None
    except rt.TransmissionError as failure:
        return "unreadable", failure.signal_name


def dispatch(request: Any) -> dict[str, Any]:
    result = rt.receipt(rt.SCHEMA_UP)
    provider: str | None = None
    native_started_here = False
    native_active_before = False
    rung = "provider"
    try:
        provider, provider_names = rt.resolve_bound_provider(request)
        result["provider"] = provider
        rt._stamp(result, "provider", {"selected": provider}, False, "resolve", {"provider": provider})

        rung = "hold"
        hold_unit = rt.HOLD_UNIT.format(provider)
        result["holdUnit"] = hold_unit
        hold_before = rt.unit_state(hold_unit, step="hold-preflight")
        native_active_before = rt.unit_active(rt.NATIVE_UNIT, step="native-preflight")
        rt._stamp(result, "hold", {"unit": hold_unit, "stateBefore": hold_before},
                  [hold_unit] if hold_before not in {"active", "reloading"} else [],
                  "native-unit-Requires-hold", {"state": hold_before})

        rung = "namespace"
        namespace_present = rt.VPN_NAMESPACE in rt.namespace_names()
        rt._stamp(result, "namespace", {"presentBeforeNativeStart": namespace_present},
                  ["namespace plumbing and kill-switch via native unit ExecStartPre"],
                  "defer-to-native-unit-prestart", {"prestartExpected": True})

        rung = "portal-row"
        rpc_port = rt.portal_port()
        result["rpcPort"] = rpc_port
        rt._stamp(result, "portal-row", {"rpcPort": rpc_port}, False,
                  "read-portal-row-for-native-daemon", {"rpcPort": rpc_port})

        rung = "daemon"
        try:
            started = rt.run([rt.SYSTEMCTL, "start", rt.NATIVE_UNIT],
                              timeout=180, step="native-start")
        except rt.TransmissionError as failure:
            hold_state, hold_state_error = _hold_readback(hold_unit)
            result["holdState"] = hold_state
            detail = {"holdUnit": hold_unit, "holdState": hold_state,
                      "nativeUnit": rt.NATIVE_UNIT}
            if hold_state_error:
                detail["holdStateReadSignal"] = hold_state_error
            if hold_state not in {"active", "reloading"}:
                raise rt.TransmissionError("transmission-hold-start-failed", "hold-start", detail) from None
            raise rt.TransmissionError("transmission-native-start-failed", "native-start", detail) from None

        hold_state, hold_state_error = _hold_readback(hold_unit)
        result["holdState"] = hold_state
        result["holdUnit"] = hold_unit
        result["nativeUnit"] = rt.NATIVE_UNIT
        if hold_state_error:
            result["holdStateReadSignal"] = hold_state_error
        if started.returncode != 0:
            try:
                native_state = rt.unit_state(rt.NATIVE_UNIT, step="native-start-readback")
            except rt.TransmissionError:
                native_state = "unreadable"
            detail = {"holdUnit": hold_unit, "holdState": hold_state,
                      "nativeUnit": rt.NATIVE_UNIT, "nativeState": native_state}
            if hold_state_error:
                detail["holdStateReadSignal"] = hold_state_error
            if hold_state not in {"active", "reloading"}:
                raise rt.TransmissionError("transmission-hold-start-failed", "hold-start", detail)
            raise rt.TransmissionError("transmission-native-start-failed", "native-start", detail)
        native_state = rt.unit_state(rt.NATIVE_UNIT, step="native-start-readback")
        result["nativeState"] = native_state
        if native_state not in {"active", "reloading"}:
            detail = {"holdUnit": hold_unit, "holdState": hold_state,
                      "nativeUnit": rt.NATIVE_UNIT, "nativeState": native_state}
            if hold_state_error:
                detail["holdStateReadSignal"] = hold_state_error
            if hold_state not in {"active", "reloading"}:
                raise rt.TransmissionError("transmission-hold-start-failed", "hold-start", detail)
            raise rt.TransmissionError("transmission-native-start-readback-failed", "native-start", detail)
        native_started_here = not native_active_before
        rt._stamp(result, "daemon", {"unit": rt.NATIVE_UNIT, "activeBefore": native_active_before,
                                      "state": native_state},
                  [rt.NATIVE_UNIT] if native_started_here else [], "systemctl-start-native-unit",
                  {"active": True, "unit": rt.NATIVE_UNIT})

        rung = "settings"
        rt._stamp(result, "settings", {"execStartPostCompleted": True}, False,
                  "native-unit-ExecStartPost-settings-readiness-and-readback",
                  {"completed": True})

        rung = "onness"
        deadline = time.monotonic() + _ONNESS_TIMEOUT
        latest: dict[str, Any] = {}
        while True:
            latest = rt.status_read(provider, provider_names)
            result["onness"] = {
                "on": latest.get("on"), "conditions": latest.get("conditions"),
                "forwardPort": latest.get("forwardPort"), "peerPort": latest.get("peerPort"),
                "rpcPort": latest.get("rpcPort"), "firstMissingSignal": latest.get("firstMissingSignal"),
            }
            result["rpcPort"] = latest.get("rpcPort")
            if latest.get("ok") is True and latest.get("on") is True:
                rt._stamp(result, "onness", {"statusRead": True}, False,
                          "read-five-conditions-until-on", result["onness"])
                result["ok"] = True
                result["firstMissingSignal"] = "none"
                return rt.finish(result, request)
            if time.monotonic() >= deadline:
                rt._stamp(result, "onness", {"statusRead": latest.get("ok") is True}, False,
                          "read-five-conditions-until-on", result["onness"])
                signal_name = latest.get("firstMissingSignal")
                if signal_name in {None, "none"}:
                    conditions = latest.get("conditions")
                    if isinstance(conditions, dict):
                        signal_name = next((name for name, matched in conditions.items()
                                            if matched is not True), "none")
                raise rt.TransmissionError("transmission-onness-not-confirmed", "onness",
                                           {"onnessSignal": signal_name,
                                            "onnessConditions": latest.get("conditions")})
            time.sleep(1)
    except Exception as failure:
        if isinstance(failure, rt.TransmissionError):
            signal_name = failure.signal_name
            command_step = failure.step
            if failure.detail:
                result.update(failure.detail)
        else:
            signal_name = "transmission-operation-failed"
            command_step = rung
        result["ok"] = False
        result["firstMissingSignal"] = signal_name
        result["failedRung"] = "hold" if signal_name == "transmission-hold-start-failed" else rung
        result["failedCommandError"] = {"signal": signal_name, "step": command_step}
        if signal_name == "provider-unknown":
            try:
                result["providers"] = rt._provider_metadata()[0]
                result["unknownProvider"] = _unknown_provider(request)
            except Exception:
                pass
        rt._stamp(result, "error",
                  {"failedRung": result["failedRung"], "commandError": command_step},
                  [rt.NATIVE_UNIT] if native_started_here else [],
                  "report-native-unit-start-or-onness-failure", {"ok": False})
        if native_started_here and rung == "onness":
            try:
                before_stop = rt.unit_state(rt.NATIVE_UNIT, step="rollback-preflight")
                if before_stop != "inactive":
                    stop = rt.run([rt.SYSTEMCTL, "stop", rt.NATIVE_UNIT],
                                  timeout=180, step="rollback-native-stop")
                    after_stop = rt.unit_state(rt.NATIVE_UNIT, step="rollback-readback")
                    result["rollback"] = [{
                        "step": "rollback-stop", "ok": stop.returncode == 0 and after_stop == "inactive",
                        "observed": {"unit": rt.NATIVE_UNIT, "state": before_stop},
                        "could-change": [rt.NATIVE_UNIT],
                        "attempt": "stop-only-native-unit-started-by-this-invocation",
                        "finalState": {"state": after_stop},
                    }]
            except Exception:
                result["rollback"] = [{
                    "step": "rollback-stop", "ok": False,
                    "observed": {"unit": rt.NATIVE_UNIT},
                    "could-change": [rt.NATIVE_UNIT],
                    "attempt": "stop-only-native-unit-started-by-this-invocation",
                    "finalState": {"state": None},
                }]
        return rt.finish(result, request)


def main(argv=None) -> int:
    del argv
    request = None
    try:
        request = rt.read_request()
        result = dispatch(request)
    except Exception as failure:
        result = rt.finish(rt.failure_receipt(rt.SCHEMA_UP, failure), request)
    return rt.print_receipt(result)


if __name__ == "__main__":
    raise SystemExit(main())

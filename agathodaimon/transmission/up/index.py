"""Instantiate Transmission behind the selected provider and verify onness."""
from __future__ import annotations

import time
from typing import Any

from agathodaimon.transmission import runtime as rt


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


def dispatch(request: Any) -> dict[str, Any]:
    result = rt.receipt(rt.SCHEMA_UP)
    started: list[str] = []
    rung = "provider"
    provider: str | None = None
    try:
        provider, provider_names = rt.resolve_provider(request)
        result["provider"] = provider
        rt._stamp(result, "provider", {"selected": provider}, False, "resolve", {"provider": provider})

        rung = "namespace"
        namespace_state = rt.ensure_namespace()
        result["steps"].append({"step": "namespace", **namespace_state})

        rung = "hold"
        hold_unit = rt.HOLD_UNIT.format(provider)
        hold_was_active = rt.unit_active(hold_unit, step="hold-preflight")
        if not hold_was_active:
            started.append(hold_unit)
            rt.start_unit(hold_unit, "hold-start")
        deadline = time.monotonic() + 180
        hold_state = None
        while time.monotonic() < deadline:
            if not rt.unit_active(hold_unit, step="hold-state-readback"):
                time.sleep(1)
                continue
            hold_state = rt.read_provider_state(provider)
            if hold_state is not None and rt.state_is_fresh(hold_state):
                break
            time.sleep(1)
        if (hold_state is None or not rt.state_is_fresh(hold_state)
                or hold_state.get("provider") != provider
                or not isinstance(hold_state.get("forwardPort"), int)
                or isinstance(hold_state.get("forwardPort"), bool)
                or not 1 <= hold_state["forwardPort"] <= 65535
                or not isinstance(hold_state.get("tunnelInterface"), str)):
            raise rt.TransmissionError("transmission-forward-state-not-ready", "hold")
        rt._stamp(result, "hold", {"activeBefore": hold_was_active},
                  [hold_unit] if not hold_was_active else [],
                  "start-and-wait" if not hold_was_active else "observe-and-wait",
                  {"active": True, "fresh": True,
                   "forwardPort": hold_state["forwardPort"],
                   "tunnelInterface": hold_state["tunnelInterface"]})

        rung = "portal-row"
        rpc_port = rt.portal_port()
        lan_interfaces = rt.ensure_rpc_lan_rules(rpc_port)
        result["rpcPort"] = rpc_port
        rt._stamp(result, "portal-row", {"portalsMap": "readable", "rpcPort": rpc_port},
                  ["narrow LAN/RPC forwarding rules"], "read-portal-row-and-ensure-rules",
                  {"rpcPort": rpc_port, "lanInterfaces": lan_interfaces})

        rung = "daemon"
        daemon_unit = rt.DAEMON_UNIT.format(rpc_port)
        daemon_was_active = rt.unit_active(daemon_unit, step="daemon-preflight")
        if not daemon_was_active:
            started.append(daemon_unit)
            rt.start_unit(daemon_unit, "daemon-start")
        rt._stamp(result, "daemon", {"activeBefore": daemon_was_active},
                  [daemon_unit] if not daemon_was_active else [],
                  "start" if not daemon_was_active else "preserve-active",
                  {"active": True, "unit": daemon_unit})

        rung = "settings"
        settings = rt.rpc_set_download_settings(rpc_port, hold_state["forwardPort"])
        rt._stamp(result, "settings", {"rpcPort": rpc_port, "peerPort": hold_state["forwardPort"]},
                  ["peer-port", "download-dir", "incomplete-dir", "watch-dir", "enabled flags"],
                  "session-set-then-session-get", settings)

        rung = "onness"
        onness = rt.status_read(provider, provider_names)
        result["onness"] = {
            "on": onness.get("on"), "conditions": onness.get("conditions"),
            "forwardPort": onness.get("forwardPort"), "peerPort": onness.get("peerPort"),
            "rpcPort": onness.get("rpcPort"), "firstMissingSignal": onness.get("firstMissingSignal"),
        }
        rt._stamp(result, "onness", {"statusRead": onness.get("ok") is True}, False,
                  "read-five-conditions", result["onness"])
        if onness.get("ok") is not True or onness.get("on") is not True:
            raise rt.TransmissionError("transmission-onness-not-confirmed", "onness")
        result["ok"] = True
        result["firstMissingSignal"] = "none"
        return rt.finish(result, request)
    except Exception as failure:
        if isinstance(failure, rt.TransmissionError):
            signal_name = failure.signal_name
            command_step = failure.step
        else:
            signal_name = "transmission-operation-failed"
            command_step = rung
        failed_rung = rung
        if signal_name == "provider-unknown":
            try:
                result["providers"] = rt._provider_metadata()[0]
                result["unknownProvider"] = _unknown_provider(request)
            except Exception:
                pass
        result["ok"] = False
        result["firstMissingSignal"] = signal_name
        result["failedRung"] = failed_rung
        result["failedCommandError"] = {"signal": signal_name, "step": command_step}
        rt._stamp(result, "error",
                  {"failedRung": failed_rung, "commandError": command_step},
                  ["only resources started by this invocation"],
                  "report-failure-before-rung-completion", {"ok": False})
        rollback: list[dict[str, Any]] = []
        for unit in reversed(started):
            try:
                was_active = rt.unit_active(unit, step="rollback-preflight")
                if was_active:
                    rt.stop_unit(unit, "rollback-stop")
                rollback.append({"step": "rollback-stop", "ok": True,
                                 "observed": {"unit": unit, "active": was_active},
                                 "could-change": [unit], "attempt": "stop-only-run-started-unit",
                                 "finalState": {"active": False}})
            except Exception:
                rollback.append({"step": "rollback-stop", "ok": False,
                                 "observed": {"unit": unit}, "could-change": [unit],
                                 "attempt": "stop-only-run-started-unit",
                                 "finalState": {"active": None}})
        if rollback:
            result["rollback"] = rollback
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

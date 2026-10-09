"""Keep the selected provider tunnel and its forwarded peer port alive."""
from __future__ import annotations

import signal
import time
import threading
from typing import Any

from agathodaimon.transmission import runtime as rt

_DAEMON_START_TIMEOUT = 180
_POLL_INTERVAL = 1


def _tunnel_alive(tunnel: Any) -> None:
    process = getattr(tunnel, "process", None)
    poll = getattr(process, "poll", None)
    if callable(poll) and poll() is not None:
        raise rt.TransmissionError("transmission-vpn-tunnel-exited", "vpn-tunnel")


def _wait_for_peer_port(stop: threading.Event, tunnel: Any,
                        forward: dict[str, Any]) -> tuple[int, int] | None:
    deadline = time.monotonic() + _DAEMON_START_TIMEOUT
    last_port_error: rt.TransmissionError | None = None
    last_rpc_error: rt.TransmissionError | None = None
    while not stop.is_set():
        _tunnel_alive(tunnel)
        try:
            rpc_port = rt.portal_port()
            last_port_error = None
        except rt.TransmissionError as failure:
            last_port_error = failure
            if time.monotonic() >= deadline:
                raise failure
            stop.wait(_POLL_INTERVAL)
            continue

        daemon_unit = rt.NATIVE_UNIT
        if rt.unit_active(daemon_unit, step="daemon-readback"):
            # An active unit is not yet a listening RPC; retry until the deadline.
            peer_port = forward.get("port")
            try:
                rt.rpc_call(rpc_port, "session-set", {"peer-port": peer_port})
                readback = rt.rpc_get_peer_port(rpc_port)
                if readback != peer_port:
                    raise rt.TransmissionError("transmission-peer-port-readback-mismatch",
                                               "peer-port-readback")
                return rpc_port, readback
            except rt.TransmissionError as failure:
                last_rpc_error = failure
        if time.monotonic() >= deadline:
            if last_rpc_error is not None:
                raise last_rpc_error
            if last_port_error is not None:
                raise last_port_error
            raise rt.TransmissionError("transmission-daemon-start-timeout", "daemon")
        stop.wait(_POLL_INTERVAL)
    return None


def _failure(value: dict[str, Any], failure: Exception, rung: str) -> None:
    if isinstance(failure, rt.TransmissionError):
        signal_name = failure.signal_name
        command_step = failure.step
    else:
        signal_name = "transmission-hold-failed"
        command_step = rung
    value["ok"] = False
    value["firstMissingSignal"] = signal_name
    value["failedRung"] = rung
    value["failedCommandError"] = {"signal": signal_name, "step": command_step}
    if isinstance(failure, rt.TransmissionError) and failure.detail:
        value.update(failure.detail)
    rt._stamp(value, "error", {"failedRung": rung, "commandError": command_step},
              ["provider tunnel", "provider state"], "report-hold-failure", {"ok": False})


def dispatch(request: Any) -> dict[str, Any]:
    result = rt.receipt(rt.SCHEMA_HOLD)
    stop = threading.Event()
    signal_seen: list[str | None] = [None]
    previous_handlers: dict[int, Any] = {}
    provider: str | None = None
    face = None
    tunnel = None
    state_identity: tuple[int, int] | None = None
    rung = "provider"
    failed = False
    notify_address = rt.claim_notify_socket()

    def request_stop(signum: int, _frame: Any) -> None:
        signal_seen[0] = signal.Signals(signum).name
        stop.set()

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)

    try:
        provider, _providers = rt.resolve_provider(request)
        result["provider"] = provider
        rt._stamp(result, "provider", {"selected": provider}, False,
                  "resolve", {"provider": provider})

        rung = "tunnel"
        face = rt.provider_face(provider)
        tunnel = face.connect(rt.VPN_NAMESPACE)
        tunnel.wait_ready(timeout=60)
        interface = getattr(face, "TUNNEL_INTERFACE", None)
        if not isinstance(interface, str):
            raise rt.TransmissionError("transmission-provider-interface-invalid", "tunnel")
        result["tunnelInterface"] = interface
        rt._stamp(result, "tunnel", {"namespace": rt.VPN_NAMESPACE},
                  ["provider tunnel"], "connect-and-wait-ready",
                  {"ready": True, "interface": interface})

        rung = "forward"
        forward = face.forward()
        bound_monotonic = time.monotonic()
        bound_at = rt.now_utc()
        state_identity = rt.write_provider_state(
            provider, forward, interface, bound_at=bound_at)
        state_readback = rt.read_provider_state(provider)
        if (state_readback is None or state_readback.get("forwardPort") != forward.get("port")
                or state_readback.get("tunnelInterface") != interface
                or not rt.state_is_fresh(state_readback)):
            raise rt.TransmissionError("transmission-forward-state-readback-mismatch", "forward-state-readback")
        result["forwardPort"] = forward.get("port")
        result["keepaliveInterval"] = forward.get("keepaliveInterval")
        result["peerPortApplied"] = False
        result["peerPortReadback"] = None
        result["rpcPort"] = None
        rt._stamp(result, "forward-state", {"forwardPort": forward.get("port")},
                  ["private provider state"], "publish-before-daemon-readiness",
                  {"written": True, "readback": True, "mode": "0600"})

        rung = "notify-ready"
        rt.notify_ready(notify_address)
        result["ready"] = True
        rt._stamp(result, "ready", {"notifySocketPresent": True}, False,
                  "send-READY=1-after-bind-and-state-write", {"ready": True})

        rung = "daemon"
        peer_state = _wait_for_peer_port(stop, tunnel, forward)
        if peer_state is not None:
            rpc_port, readback = peer_state
            state_identity = rt.write_provider_state(
                provider, forward, interface, peer_port_applied=True,
                peer_port_readback=readback, rpc_port=rpc_port, bound_at=bound_at)
            result["rpcPort"] = rpc_port
            result["peerPortApplied"] = True
            result["peerPortReadback"] = readback
            rt._stamp(result, "peer-port", {"daemonActive": True, "rpcPort": rpc_port},
                      ["Transmission peer-port setting"],
                      "session-set-then-session-get",
                      {"peerPortApplied": True, "peerPortReadback": readback})

        if stop.is_set():
            result["ok"] = True
            result["firstMissingSignal"] = "none"
            result["stopped"] = True
            result["stopSignal"] = signal_seen[0]
            rt._stamp(result, "stop", {"signal": signal_seen[0]},
                      ["provider tunnel", "provider state"],
                      "teardown-on-worker-exit", {"stopped": True})
        else:
            interval = forward["keepaliveInterval"]
            keepalive_due = bound_monotonic + interval * 0.8
            while not stop.is_set():
                _tunnel_alive(tunnel)
                remaining = max(0.0, keepalive_due - time.monotonic())
                if stop.wait(min(_POLL_INTERVAL, remaining)):
                    break
                if time.monotonic() < keepalive_due:
                    continue

                rung = "keepalive"
                previous_port = forward.get("port")
                renewed = face.keepalive(forward)
                bound_monotonic = time.monotonic()
                bound_at = rt.now_utc()
                state_identity = rt.write_provider_state(
                    provider, renewed, interface, bound_at=bound_at)
                forward = renewed
                result["forwardPort"] = forward.get("port")
                result["keepaliveInterval"] = forward.get("keepaliveInterval")
                result["peerPortApplied"] = False
                result["peerPortReadback"] = None
                rt._stamp(result, "keepalive", {"previousForwardPort": previous_port},
                          ["private provider state", "Transmission peer-port setting"],
                          "provider-keepalive-and-publish-bind",
                          {"forwardPort": forward.get("port"), "stateWritten": True})

                rung = "daemon"
                peer_state = _wait_for_peer_port(stop, tunnel, forward)
                if peer_state is not None:
                    rpc_port, readback = peer_state
                    state_identity = rt.write_provider_state(
                        provider, forward, interface, peer_port_applied=True,
                        peer_port_readback=readback, rpc_port=rpc_port, bound_at=bound_at)
                    result["rpcPort"] = rpc_port
                    result["peerPortApplied"] = True
                    result["peerPortReadback"] = readback
                    rt._stamp(result, "peer-port", {"daemonActive": True, "rpcPort": rpc_port},
                              ["Transmission peer-port setting"],
                              "session-set-then-session-get",
                              {"peerPortApplied": True, "peerPortReadback": readback})
                if stop.is_set():
                    break
                rung = "keepalive"
                keepalive_due = bound_monotonic + forward["keepaliveInterval"] * 0.8

            result["ok"] = True
            result["firstMissingSignal"] = "none"
            result["stopped"] = True
            result["stopSignal"] = signal_seen[0]
            rt._stamp(result, "stop", {"signal": signal_seen[0]},
                      ["provider tunnel", "provider state"],
                      "teardown-on-worker-exit", {"stopped": True})
    except Exception as failure:
        failed = True
        _failure(result, failure, rung)
    finally:
        cleanup_failures: list[dict[str, str]] = []
        if face is not None:
            try:
                face.teardown()
            except Exception as failure:
                signal_name = failure.signal_name if isinstance(failure, rt.TransmissionError) else "transmission-vpn-teardown-failed"
                command_step = failure.step if isinstance(failure, rt.TransmissionError) else "vpn-teardown"
                cleanup_failures.append({"signal": signal_name, "step": command_step})
        if provider is not None and state_identity is not None:
            try:
                if not rt.remove_provider_state(provider, state_identity):
                    cleanup_failures.append({"signal": "transmission-forward-state-cleanup-failed",
                                             "step": "forward-state-remove"})
            except Exception as failure:
                signal_name = failure.signal_name if isinstance(failure, rt.TransmissionError) else "transmission-forward-state-cleanup-failed"
                command_step = failure.step if isinstance(failure, rt.TransmissionError) else "forward-state-remove"
                cleanup_failures.append({"signal": signal_name, "step": command_step})
        if cleanup_failures:
            result["cleanupFailures"] = cleanup_failures
            if not failed:
                result["ok"] = False
                result["firstMissingSignal"] = cleanup_failures[0]["signal"]
                result["failedRung"] = "cleanup"
                result["failedCommandError"] = cleanup_failures[0]
                rt._stamp(result, "cleanup", {"failures": len(cleanup_failures)},
                          ["provider tunnel", "provider state"],
                          "report-cleanup-failure", {"ok": False})
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)

    return rt.finish(result, request)


def main(argv=None) -> int:
    del argv
    request = None
    try:
        request = rt.read_request()
        result = dispatch(request)
    except Exception as failure:
        result = rt.finish(rt.failure_receipt(rt.SCHEMA_HOLD, failure), request)
    return rt.print_receipt(result)


if __name__ == "__main__":
    raise SystemExit(main())

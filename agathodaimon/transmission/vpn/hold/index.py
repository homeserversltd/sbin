"""Keep the selected provider tunnel and forwarded peer port alive."""
from __future__ import annotations

import signal
import threading
import time
from typing import Any, Mapping

from agathodaimon.transmission import runtime as rt

_POLL_INTERVAL = 1
_PEER_RETRY_INTERVAL = 10


def _tunnel_alive(protocol_face: Any, tunnel: Any) -> None:
    try:
        alive = bool(protocol_face.is_alive(tunnel))
    except Exception:
        alive = False
    if not alive:
        diagnostic = getattr(tunnel, "last_diagnostic", None)
        detail = ({"tunnelDiagnostic": rt._safe_diagnostic(diagnostic)[:160]}
                  if isinstance(diagnostic, str) and diagnostic else {})
        raise rt.TransmissionError("transmission-vpn-tunnel-exited", "vpn-tunnel", detail)


def _attempt_peer_port(forward: Mapping[str, Any]) -> tuple[int, int, str] | None:
    """Best-effort RPC synchronization; absence never takes down the hold."""
    try:
        rpc_port = rt.portal_port()
        if not rt.unit_active(rt.NATIVE_UNIT, step="daemon-readback"):
            return None
        peer_port = forward.get("port")
        if isinstance(peer_port, bool) or not isinstance(peer_port, int):
            return None
        rt.rpc_call(rpc_port, "session-set", {"peer-port": peer_port})
        readback = rt.rpc_get_peer_port(rpc_port)
        if readback != peer_port:
            return None
        return rpc_port, readback, rt.now_utc()
    except rt.TransmissionError:
        return None


def _write_state(provider: str, protocol: str, forward: Mapping[str, Any],
                 interface: str, bound_at: str,
                 peer_state: tuple[int, int, str] | None) -> tuple[int, int]:
    rpc_port = peer_state[0] if peer_state is not None else None
    readback = peer_state[1] if peer_state is not None else None
    timestamp = peer_state[2] if peer_state is not None else None
    return rt.write_provider_state(
        provider, forward, interface, protocol=protocol,
        peer_port_applied=peer_state is not None,
        peer_port_readback=readback, peer_port_readback_at=timestamp,
        rpc_port=rpc_port, bound_at=bound_at)


def _publish_peer_state(result: dict[str, Any], peer_state: tuple[int, int, str] | None) -> None:
    result["peerPortApplied"] = peer_state is not None
    result["rpcPort"] = peer_state[0] if peer_state is not None else None
    result["peerPortReadback"] = peer_state[1] if peer_state is not None else None
    result["peerPortReadbackAt"] = peer_state[2] if peer_state is not None else None
    rt._stamp(
        result, "peer-port",
        {"daemonRpcAvailable": peer_state is not None,
         "rpcPort": peer_state[0] if peer_state is not None else None},
        ["Transmission peer-port setting"],
        "best-effort-session-set-then-session-get",
        {"peerPortApplied": peer_state is not None,
         "peerPortReadback": peer_state[1] if peer_state is not None else None})


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
    protocol_face = None
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
        options, providers = rt.resolve_bound_vpn(request)
        provider = options["provider"]
        protocol = options["protocol"]
        if not isinstance(provider, str) or not isinstance(protocol, str):
            raise rt.TransmissionError("transmission-vpn-options-invalid", "vpn-options")
        result["provider"] = provider
        result["protocol"] = protocol
        result["unitOverridePropagated"] = False
        result["nextStartConfigurationSource"] = rt.CONFIG_PATH
        rt._stamp(result, "provider", {"selected": provider, "protocol": protocol}, False,
                  "compose-config-and-envelope-vpn-fields", {"provider": provider})

        rung = "tunnel"
        face = rt.provider_face(provider, protocol)
        protocol_face = face.select_protocol(protocol)
        tunnel = face.connect(rt.VPN_NAMESPACE, options)
        tunnel.wait_ready(timeout=60)
        interface = protocol_face.interface_name()
        if not isinstance(interface, str):
            raise rt.TransmissionError("transmission-provider-interface-invalid", "tunnel")
        result["tunnelInterface"] = interface
        rt._stamp(result, "tunnel", {"namespace": rt.VPN_NAMESPACE, "protocol": protocol},
                  ["provider tunnel"], "connect-and-wait-ready",
                  {"ready": True, "interface": interface})

        rung = "forward"
        forward = face.forward()
        bound_monotonic = time.monotonic()
        bound_at = rt.now_utc()
        peer_state: tuple[int, int, str] | None = None
        peer_retry_at = bound_monotonic
        state_identity = _write_state(provider, protocol, forward, interface, bound_at, peer_state)
        state_readback = rt.read_provider_state(provider)
        if (state_readback is None or state_readback.get("forwardPort") != forward.get("port")
                or state_readback.get("protocol") != protocol
                or state_readback.get("tunnelInterface") != interface
                or not rt.state_is_fresh(state_readback)):
            raise rt.TransmissionError("transmission-forward-state-readback-mismatch", "forward-state-readback")
        result["forwardPort"] = forward.get("port")
        result["keepaliveInterval"] = forward.get("keepaliveInterval")
        _publish_peer_state(result, None)
        rt._stamp(result, "forward-state", {"forwardPort": forward.get("port")},
                  ["private provider state"], "publish-bind-before-daemon-rpc",
                  {"written": True, "readback": True, "mode": "0600"})

        rung = "notify-ready"
        rt.notify_ready(notify_address)
        result["ready"] = True
        rt._stamp(result, "ready", {"notifySocketPresent": True}, False,
                  "send-READY=1-after-bind-and-state-write", {"ready": True})

        rung = "daemon"
        peer_state = _attempt_peer_port(forward)
        state_identity = _write_state(provider, protocol, forward, interface, bound_at, peer_state)
        _publish_peer_state(result, peer_state)
        peer_retry_at = time.monotonic() + (_PEER_RETRY_INTERVAL if peer_state is None else forward["keepaliveInterval"])
        rt._stamp(result, "peer-port", {"daemonRpcAvailable": peer_state is not None,
                                         "rpcPort": peer_state[0] if peer_state else None},
                  ["Transmission peer-port setting"], "initial-best-effort-rpc-readback",
                  {"peerPortApplied": peer_state is not None})

        keepalive_due = bound_monotonic + forward["keepaliveInterval"] * 0.8
        while not stop.is_set():
            _tunnel_alive(protocol_face, tunnel)
            now = time.monotonic()
            if now >= peer_retry_at and now < keepalive_due:
                rung = "daemon"
                peer_state = _attempt_peer_port(forward)
                state_identity = _write_state(provider, protocol, forward, interface, bound_at, peer_state)
                _publish_peer_state(result, peer_state)
                peer_retry_at = time.monotonic() + (
                    _PEER_RETRY_INTERVAL if peer_state is None else forward["keepaliveInterval"])
            next_due = min(keepalive_due, peer_retry_at)
            if stop.wait(min(_POLL_INTERVAL, max(0.0, next_due - time.monotonic()))):
                break
            if time.monotonic() < keepalive_due:
                continue

            rung = "keepalive"
            previous_port = forward.get("port")
            renewed = face.keepalive(forward)
            bound_monotonic = time.monotonic()
            bound_at = rt.now_utc()
            forward = renewed
            peer_state = _attempt_peer_port(forward)
            state_identity = _write_state(provider, protocol, forward, interface, bound_at, peer_state)
            result["forwardPort"] = forward.get("port")
            result["keepaliveInterval"] = forward.get("keepaliveInterval")
            _publish_peer_state(result, peer_state)
            rt._stamp(result, "keepalive", {"previousForwardPort": previous_port},
                      ["private provider state", "Transmission peer-port setting"],
                      "renew-provider-bind-and-reconcile-daemon-peer-port",
                      {"forwardPort": forward.get("port"), "stateWritten": True,
                       "peerPortApplied": peer_state is not None})
            peer_retry_at = time.monotonic() + (
                _PEER_RETRY_INTERVAL if peer_state is None else forward["keepaliveInterval"])
            keepalive_due = bound_monotonic + forward["keepaliveInterval"] * 0.8

        result["ok"] = True
        result["firstMissingSignal"] = "none"
        result["stopped"] = True
        result["stopSignal"] = signal_seen[0]
        rt._stamp(result, "stop", {"signal": signal_seen[0]},
                  ["provider tunnel", "provider state"], "teardown-on-worker-exit",
                  {"stopped": True})
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

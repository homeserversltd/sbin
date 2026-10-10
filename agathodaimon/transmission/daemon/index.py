"""Replace the staff process with Transmission inside the prepared namespace."""
from __future__ import annotations

import json
import os
from typing import Any

from agathodaimon.transmission import runtime as rt
from agathodaimon.transmission.keys._credentials import seed_daemon_credentials

_RUNUSER = "/usr/sbin/runuser"


def _scratch_attempt(request: Any, provider: str, rpc_port: int,
                     logical_argv: list[str], root: Any,
                     seed_metadata: dict[str, Any]) -> dict[str, Any]:
    return rt.finish({
        "schema": rt.SCHEMA_DAEMON,
        "ok": True,
        "provider": provider,
        "nativeUnit": rt.NATIVE_UNIT,
        "namespace": rt.VPN_NAMESPACE,
        "rpcPort": rpc_port,
        "scratchObservation": {
            "scratchRoot": str(root),
            "namespacePresent": True,
            "portalPort": rpc_port,
        },
        "scratchLogicalArgv": list(logical_argv),
        "credentialSeed": dict(seed_metadata),
        "interimDebt": "staff-writes-daemon-rpc-credential-seat",
        "execReplacementAttempted": True,
        "pid": os.getpid(),
        "firstMissingSignal": "none",
        "steps": [{
            "step": "daemon-exec-attempt",
            "observed": {"portalPort": rpc_port, "namespacePresent": True,
                         "scratchRoot": str(root)},
            "could-change": [rt.NATIVE_UNIT + " process"],
            "attempt": "exec-ip-netns-runuser-transmission-daemon",
            "finalState": {"execReplacementAttempted": True, "pid": os.getpid()},
        }],
    }, request)


def _daemon_argv(rpc_port: int) -> list[str]:
    return [
        rt.IP, "netns", "exec", rt.VPN_NAMESPACE,
        _RUNUSER, "-u", "debian-transmission", "--",
        "transmission-daemon", "--foreground", "--config-dir", "/etc/transmission-daemon",
        "--watch-dir", "/mnt/nas/downloads/objectives/",
        "--port", str(rpc_port),
    ]


def main(argv=None) -> int:
    del argv
    request = None
    provider: str | None = None
    seed_metadata: dict[str, Any] = {
        "attempted": False, "outcome": "not-attempted",
        "published": False, "firstMissingSignal": "none",
    }
    try:
        request = rt.read_request(known_fields=("provider", "flags"), declared_flags=("vpn",))
        provider, _providers = rt.resolve_bound_provider(request)
        rpc_port = rt.portal_port()
        namespace_present = rt.VPN_NAMESPACE in rt.namespace_names()
        if not namespace_present:
            raise rt.TransmissionError("transmission-namespace-absent", "daemon-namespace")
        logical_argv = _daemon_argv(rpc_port)
        command = rt.command_argv(logical_argv)
        root = rt._scratch_root()
        environment = os.environ.copy()
        try:
            seed_metadata = seed_daemon_credentials()
        except rt.TransmissionError as failure:
            published = isinstance(failure.detail, dict) and failure.detail.get("published") is True
            seed_metadata = {
                "attempted": True, "outcome": "unconfirmed" if published else "failed",
                "published": published, "firstMissingSignal": failure.signal_name,
            }
            raise
        except Exception:
            seed_metadata = {
                "attempted": True, "outcome": "failed", "published": False,
                "firstMissingSignal": "transmission-daemon-credential-seed-failed",
            }
            raise rt.TransmissionError(
                "transmission-daemon-credential-seed-failed", "daemon-credential-seed",
            ) from None
        if root is not None:
            environment["PATH"] = str(root / "bin")
            attempt = _scratch_attempt(
                request, provider, rpc_port, logical_argv, root, seed_metadata,
            )
            print(json.dumps(attempt, sort_keys=True, separators=(",", ":")), flush=True)
        try:
            os.execvpe(command[0], command, environment)
        except OSError:
            raise rt.TransmissionError("transmission-daemon-exec-failed", "daemon-exec") from None
    except Exception as failure:
        failed = rt.failure_receipt(rt.SCHEMA_DAEMON, failure, provider)
        failed["credentialSeed"] = dict(seed_metadata)
        failed["interimDebt"] = "staff-writes-daemon-rpc-credential-seat"
        if isinstance(failure, rt.TransmissionError):
            failed["failedRung"] = failure.step
        print(json.dumps(rt.finish(failed, request), sort_keys=True, separators=(",", ":")), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

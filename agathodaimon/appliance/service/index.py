"""Allowlisted appliance service control through systemd."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "caduceus.staff.appliance-service.v1"
CONFIG_PATH = Path("/etc/appliance/config.json")
ACTIONS = {"start", "stop", "restart", "reload", "enable", "disable", "status"}
CERT_DEPENDENTS = {"forgejo.service": "restart", "nginx.service": "reload"}


def safe_service_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and ".." not in value
        and value.isascii()
        and all(char.isalnum() or char in "-_.@" for char in value)
    )


def normalize_systemd_service(service: str) -> str:
    return service if service.endswith(".service") else f"{service}.service"


def _portal_service_allowlist() -> list[str]:
    try:
        with CONFIG_PATH.open("r", encoding="utf-8") as source:
            registry = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("portal-service-registry-unreadable") from error

    tabs = registry.get("tabs") if isinstance(registry, dict) else None
    portals_root = tabs.get("portals") if isinstance(tabs, dict) else None
    data = portals_root.get("data") if isinstance(portals_root, dict) else None
    portals = data.get("portals") if isinstance(data, dict) else None
    if not isinstance(portals, list):
        raise ValueError("portal-service-registry-unreadable")

    services: list[str] = []
    for portal in portals:
        entries = portal.get("services") if isinstance(portal, dict) else None
        if not isinstance(entries, list):
            continue
        for service in entries:
            if safe_service_name(service):
                services.append(normalize_systemd_service(service))
    return sorted(set(services))


def _receipt(
    *,
    ok: bool = False,
    active: bool | None = None,
    output: str = "",
    first_missing_signal: str,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "active": active,
        "output": output,
        "firstMissingSignal": first_missing_signal,
    }


def _emit(receipt: dict[str, Any]) -> int:
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


def _command_output(stdout: bytes, stderr: bytes) -> str:
    selected = stdout if stdout else stderr
    return selected.decode("utf-8", errors="replace").strip()


def _run_systemctl(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["/usr/bin/systemctl", *args], capture_output=True, check=False)


def main(argv: list[str] | None = None) -> int:
    del argv  # This actuator's request contract is stdin JSON only.
    try:
        raw = sys.stdin.read()
        envelope = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _emit(_receipt(first_missing_signal="portal-service-payload-invalid"))

    if not isinstance(envelope, dict):
        return _emit(_receipt(first_missing_signal="portal-service-payload-invalid"))
    payload = envelope.get("payload") if "schema" in envelope else envelope
    # Unknown keys, such as the scrubbed flags room, are skipped, never fatal.
    if not isinstance(payload, dict):
        return _emit(_receipt(first_missing_signal="portal-service-payload-invalid"))

    action = payload.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        return _emit(_receipt(first_missing_signal="portal-service-action-invalid"))
    service = payload.get("service")
    if not safe_service_name(service):
        return _emit(_receipt(first_missing_signal="portal-service-name-invalid"))
    assert isinstance(service, str)
    systemd_service = normalize_systemd_service(service)
    if systemd_service.startswith("-"):
        return _emit(_receipt(first_missing_signal="portal-service-name-invalid"))

    if CERT_DEPENDENTS.get(systemd_service) != action:
        try:
            allowed = _portal_service_allowlist()
        except ValueError:
            return _emit(_receipt(first_missing_signal="portal-service-registry-unreadable"))
        if systemd_service not in allowed:
            return _emit(_receipt(first_missing_signal="portal-service-not-allowed"))

    try:
        command = _run_systemctl(action, "--", systemd_service)
    except (OSError, subprocess.SubprocessError) as error:
        return _emit(
            _receipt(
                output=str(error),
                first_missing_signal="portal-service-systemctl-failed",
            )
        )

    output = _command_output(command.stdout, command.stderr)
    try:
        active_result = _run_systemctl("is-active", "--", systemd_service)
    except (OSError, subprocess.SubprocessError):
        return _emit(
            _receipt(
                output=output,
                first_missing_signal="portal-service-systemctl-failed",
            )
        )

    active = (
        active_result.returncode == 0
        and active_result.stdout.decode("utf-8", errors="replace").strip() == "active"
    )
    ok = command.returncode == 0
    return _emit(
        _receipt(
            ok=ok,
            active=active,
            output=output,
            first_missing_signal="none" if ok else "portal-service-systemctl-failed",
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())

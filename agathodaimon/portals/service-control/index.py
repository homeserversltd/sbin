"""Caduceus service-control door caller.

Owns the bounded SSH, Samba, power, and website service-control actions. It
never reads or writes Keyman/Vault materials, SSH keys, or authorized_keys.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "caduceus.service.door.v1"
MAX_INPUT_BYTES = 64 * 1024
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SSHD = "/usr/sbin/sshd"
SSH_CONFIG = Path("/etc/ssh/sshd_config")
SSH_UNITS = ("ssh.service", "sshd.service")
SAMBA_UNITS = ("smbd.service", "nmbd.service", "avahi-daemon.service", "wsdd2.service")
PASSWORD_AUTH_LINE = re.compile(
    r"^(?P<prefix>\s*)PasswordAuthentication\s+(?:yes|no)\s*(?:#.*)?$",
    re.IGNORECASE,
)


class Refusal(ValueError):
    pass


def _receipt(action: str, ok: bool, *, planned: bool, commands: list[list[str]], signal: str = "none", mutation_performed: bool | None = None, **extra: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "action": action,
        "planned": planned,
        "mutationPerformed": False if mutation_performed is False or planned or action in {"ssh-password-authentication-status", "ssh-service-status", "samba-service-status"} else ok,
        "commands": commands,
        "firstMissingSignal": signal,
        **extra,
    }


def _sudo(argv: Sequence[str]) -> list[str]:
    return ["sudo", "-n", *argv]


def _redacted(argv: Sequence[str]) -> list[str]:
    return list(argv)


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, text=True, capture_output=True, check=False)


def _must(result: subprocess.CompletedProcess[str], signal: str) -> None:
    if result.returncode != 0:
        raise Refusal(signal)


def _unit_state(unit: str) -> tuple[dict[str, Any], list[list[str]]]:
    commands = [
        [SYSTEMCTL, "is-active", unit],
        [SYSTEMCTL, "is-enabled", unit],
        [SYSTEMCTL, "show", "--property=LoadState", "--value", unit],
    ]
    active, enabled, load = (_run(command) for command in commands)
    load_state = load.stdout.strip() or "not-found"
    present = load.returncode == 0 and load_state != "not-found"
    return {
        "unit": unit,
        "present": present,
        "active": active.stdout.strip() == "active",
        "enabled": enabled.stdout.strip() == "enabled",
        "activeState": active.stdout.strip() or "unknown",
        "enabledState": enabled.stdout.strip() or "unknown",
        "loadState": load_state,
    }, commands


def _units_status(units: Sequence[str]) -> tuple[list[dict[str, Any]], list[list[str]]]:
    states: list[dict[str, Any]] = []
    commands: list[list[str]] = []
    for unit in units:
        state, observed = _unit_state(unit)
        states.append(state)
        commands.extend(observed)
    return states, commands


def _desired_enabled(payload: dict[str, Any]) -> bool:
    value = payload.get("enabled")
    if not isinstance(value, bool):
        raise Refusal("agathodaimon-service-enabled-required")
    return value


def ssh_password_authentication_status(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    del payload, planned
    command = _sudo([SSHD, "-T"])
    result = _run(command)
    _must(result, "agathodaimon-service-ssh-config-read-refused")
    value = next(
        (line.split(None, 1)[1] for line in result.stdout.splitlines() if line.lower().startswith("passwordauthentication ")),
        None,
    )
    if value not in {"yes", "no"}:
        raise Refusal("agathodaimon-service-ssh-password-authentication-missing")
    return _receipt("ssh-password-authentication-status", True, planned=False, commands=[_redacted(command)], passwordAuthentication=value, enabled=value == "yes")


def ssh_password_authentication_toggle(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    enabled = _desired_enabled(payload)
    desired = "yes" if enabled else "no"
    script = f"s/^[[:space:]]*PasswordAuthentication[[:space:]]+(yes|no)[[:space:]]*(#.*)?$/PasswordAuthentication {desired}/I"
    edit = _sudo(["/usr/bin/sed", "-i", "-E", script, str(SSH_CONFIG)])
    validate = _sudo([SSHD, "-t"])
    reload_commands = [_sudo([SYSTEMCTL, "reload", unit]) for unit in SSH_UNITS]
    commands = [_redacted(edit), _redacted(validate), *(_redacted(command) for command in reload_commands)]
    if planned:
        return _receipt("ssh-password-authentication-toggle", True, planned=True, commands=commands, enabled=enabled)
    try:
        lines = SSH_CONFIG.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise Refusal("agathodaimon-service-ssh-config-read-refused") from exc
    if sum(1 for line in lines if PASSWORD_AUTH_LINE.fullmatch(line)) != 1:
        raise Refusal("agathodaimon-service-ssh-password-authentication-line-ambiguous")
    _must(_run(edit), "agathodaimon-service-ssh-password-authentication-write-refused")
    _must(_run(validate), "agathodaimon-service-ssh-config-invalid")
    if all(_run(command).returncode != 0 for command in reload_commands):
        raise Refusal("agathodaimon-service-ssh-reload-refused")
    return _receipt("ssh-password-authentication-toggle", True, planned=False, commands=commands, enabled=enabled)


def service_status(payload: dict[str, Any], *, planned: bool, action: str) -> dict[str, Any]:
    del payload, planned
    units = SSH_UNITS if action == "ssh-service-status" else SAMBA_UNITS
    states, commands = _units_status(units)
    return _receipt(action, True, planned=False, commands=commands, services=states)


def service_toggle(payload: dict[str, Any], *, planned: bool, action: str) -> dict[str, Any]:
    enabled = _desired_enabled(payload)
    units = SSH_UNITS if action == "ssh-service-toggle" else SAMBA_UNITS
    states, observed = _units_status(units)
    present_units = [state["unit"] for state in states if state["present"]]
    if not present_units:
        raise Refusal("agathodaimon-service-unit-missing")
    command_action = "enable" if enabled else "disable"
    commands = [_redacted(_sudo([SYSTEMCTL, command_action, "--now", unit])) for unit in present_units]
    if planned:
        return _receipt(action, True, planned=True, commands=[*observed, *commands], enabled=enabled, services=states)
    failures = [_run(_sudo([SYSTEMCTL, command_action, "--now", unit])).returncode for unit in present_units]
    if any(failures):
        raise Refusal("agathodaimon-service-control-refused")
    states, observed = _units_status(units)
    return _receipt(action, True, planned=False, commands=[*commands, *observed], enabled=enabled, services=states)


def portal_service(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    service = payload.get("systemdService", payload.get("service"))
    service_action = payload.get("serviceAction")
    if not isinstance(service, str) or not re.fullmatch(r"[A-Za-z0-9@_.-]+\.service", service):
        raise Refusal("agathodaimon-service-portal-unit-invalid")
    if service_action not in {"start", "stop", "restart", "status", "enable", "disable"}:
        raise Refusal("agathodaimon-service-portal-action-invalid")
    before, observed_before = _unit_state(service)
    if not before["present"]:
        raise Refusal("agathodaimon-service-unit-missing")
    if service_action == "status":
        return _receipt(
            "portal-service", True, planned=planned, commands=observed_before,
            mutation_performed=False, serviceAction=service_action, service=before,
        )
    command = _sudo([SYSTEMCTL, str(service_action), service])
    commands = [*observed_before, _redacted(command)]
    if planned:
        return _receipt("portal-service", True, planned=True, commands=commands, serviceAction=service_action, service=before)
    _must(_run(command), "agathodaimon-service-control-refused")
    after, observed_after = _unit_state(service)
    if service_action in {"start", "stop", "restart"}:
        expected_active = service_action != "stop"
        if after["active"] != expected_active:
            raise Refusal("agathodaimon-service-portal-readback-mismatch")
    return _receipt("portal-service", True, planned=False, commands=[*commands, *observed_after], serviceAction=service_action, service=after)


def system_power(payload: dict[str, Any], *, planned: bool, action: str) -> dict[str, Any]:
    del payload
    verb = "reboot" if action == "system-restart" else "poweroff"
    command = _sudo([SYSTEMCTL, verb])
    if planned:
        return _receipt(action, True, planned=True, commands=[_redacted(command)])
    _must(_run(command), "agathodaimon-service-system-power-refused")
    return _receipt(action, True, planned=False, commands=[_redacted(command)])


def website_hard_reset(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    del payload
    commands = [
        _redacted(_sudo([SYSTEMD_RUN, "--no-block", "--on-active=2", SYSTEMCTL, "restart", "coronatio.service"])),
        _redacted(_sudo([SYSTEMD_RUN, "--no-block", "--on-active=2", SYSTEMCTL, "restart", "nginx.service"])),
    ]
    if planned:
        return _receipt("website-hard-reset", True, planned=True, commands=commands, delayedSeconds=2)
    for command in commands:
        _must(_run(command), "agathodaimon-service-hard-reset-refused")
    return _receipt("website-hard-reset", True, planned=False, commands=commands, delayedSeconds=2)


def dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) - {"actuator", "metadata"}:
        raise Refusal("agathodaimon-service-envelope-invalid")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise Refusal("agathodaimon-service-request-invalid")
    action = metadata.get("action")
    planned = metadata.get("dryRun", False)
    if not isinstance(planned, bool):
        raise Refusal("agathodaimon-service-dry-run-invalid")
    if action == "ssh-password-authentication-status": return ssh_password_authentication_status(metadata, planned=planned)
    if action == "ssh-password-authentication-toggle": return ssh_password_authentication_toggle(metadata, planned=planned)
    if action in {"ssh-service-status", "samba-service-status"}: return service_status(metadata, planned=planned, action=action)
    if action in {"ssh-service-toggle", "samba-service-toggle"}: return service_toggle(metadata, planned=planned, action=action)
    if action == "portal-service": return portal_service(metadata, planned=planned)
    if action in {"system-restart", "system-shutdown"}: return system_power(metadata, planned=planned, action=action)
    if action == "website-hard-reset": return website_hard_reset(metadata, planned=planned)
    raise Refusal("agathodaimon-service-action-invalid")


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    try:
        if len(raw) > MAX_INPUT_BYTES:
            raise Refusal("agathodaimon-service-request-too-large")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise Refusal("agathodaimon-service-request-invalid")
        receipt = dispatch(value)
    except (UnicodeDecodeError, json.JSONDecodeError, Refusal):
        signal = "agathodaimon-service-request-invalid"
        if isinstance(sys.exc_info()[1], Refusal):
            signal = str(sys.exc_info()[1])
        receipt = _receipt("unknown", False, planned=False, commands=[], signal=signal)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

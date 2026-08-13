"""Literal, generic SSH exposure on/off control for Caduceus staff.

The actuator owns no identity material. It changes only the two named
``sshd_config`` directives below, validates the resulting configuration, and
uses ordinary systemctl service lifecycle commands. SSH exposure is secure
key-only when on: PasswordAuthentication remains disabled while
PubkeyAuthentication is enabled.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from typing import Any, Sequence

SCHEMA = "caduceus.ssh.exposure.v1"
SYSTEMCTL = "/usr/bin/systemctl"
SSHD = "/usr/sbin/sshd"
TEE = "/usr/bin/tee"
INSTALL = "/usr/bin/install"
SSH_CONFIG = "/etc/ssh/sshd_config"
SSH_UNIT = "sshd.service"
SSH_UNITS = ("sshd.service", "ssh.service")
DIRECTIVES = ("PasswordAuthentication", "PubkeyAuthentication")
DIRECTIVE_LINE = re.compile(
    r"^(?P<indent>[ \t]*)(?P<name>PasswordAuthentication|PubkeyAuthentication)"
    r"[ \t]+(?P<value>yes|no)(?P<comment>[ \t]*(?:#.*)?)?(?P<ending>\n?)$",
    re.IGNORECASE,
)


class Refusal(ValueError):
    """A bounded refusal signal for an unchanged or restored host."""


def _sudo(argv: Sequence[str]) -> list[str]:
    return ["sudo", "-n", *argv]


def _run(argv: Sequence[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(argv), input=input_text, text=True, capture_output=True, check=False)


def _must(result: subprocess.CompletedProcess[str], signal: str) -> None:
    if result.returncode != 0:
        raise Refusal(signal)


def _receipt(state: str, *, ok: bool, changed: list[dict[str, str]], unchanged: list[dict[str, str]], readback: dict[str, Any] | None, commands: list[list[str]], signal: str = "none") -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": ok, "state": state, "changed": changed, "unchanged": unchanged, "readback": readback, "commands": commands, "firstMissingSignal": signal}


def _read_config() -> tuple[str, list[list[str]]]:
    command = _sudo(["/usr/bin/cat", SSH_CONFIG])
    result = _run(command)
    _must(result, "agathodaimon-ssh-exposure-config-read-refused")
    return result.stdout, [command]


def _directive_values(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in raw.splitlines():
        match = DIRECTIVE_LINE.fullmatch(line)
        if match is None:
            continue
        name = next(item for item in DIRECTIVES if item.lower() == match.group("name").lower())
        if name in values:
            raise Refusal("agathodaimon-ssh-exposure-directive-ambiguous")
        values[name] = match.group("value").lower()
    return values


def _replace_directive(raw: str, directive: str, desired: str) -> tuple[str, dict[str, str] | None]:
    """Perform one literal string replacement, or append the named missing line."""
    matches: list[tuple[int, str, re.Match[str]]] = []
    offset = 0
    for line in raw.splitlines(keepends=True):
        match = DIRECTIVE_LINE.fullmatch(line)
        if match is not None and match.group("name").lower() == directive.lower():
            matches.append((offset, line, match))
        offset += len(line)
    if len(matches) > 1:
        raise Refusal("agathodaimon-ssh-exposure-directive-ambiguous")
    if not matches:
        separator = "" if not raw or raw.endswith("\n") else "\n"
        inserted = f"{directive} {desired}\n"
        return raw + separator + inserted, {"directive": directive, "from": "absent", "to": desired, "operation": "inserted"}
    position, original, match = matches[0]
    before = match.group("value").lower()
    if before == desired:
        return raw, None
    replacement = f"{match.group('indent')}{directive} {desired}{match.group('comment') or ''}{match.group('ending')}"
    return raw[:position] + replacement + raw[position + len(original):], {"directive": directive, "from": before, "to": desired, "operation": "replaced"}


def _write_config(raw: str) -> list[list[str]]:
    command = _sudo([TEE, SSH_CONFIG])
    _must(_run(command, input_text=raw), "agathodaimon-ssh-exposure-config-write-refused")
    return [command]


def _validate() -> list[list[str]]:
    command = _sudo([SSHD, "-t"])
    result = _run(command)
    commands = [command]
    if result.returncode != 0 and "Missing privilege separation directory: /run/sshd" in result.stderr:
        runtime = _sudo([INSTALL, "-d", "-m", "0755", "/run/sshd"])
        commands.append(runtime)
        _must(_run(runtime), "agathodaimon-ssh-exposure-runtime-directory-refused")
        result = _run(command)
        commands.append(command)
    _must(result, "agathodaimon-ssh-exposure-config-invalid")
    return commands


def _service_unit() -> tuple[str, list[list[str]]]:
    # Debian's sshd.service alias can vanish when ssh.service is disabled.
    # Probe the two standard concrete unit files directly; never mutate an
    # alias merely because `systemctl status sshd` accepts it.
    commands: list[list[str]] = []
    for candidate in ("ssh.service", "sshd.service"):
        command = [SYSTEMCTL, "show", "--property=FragmentPath", "--value", candidate]
        commands.append(command)
        result = _run(command)
        if result.returncode == 0 and result.stdout.strip().startswith("/"):
            return candidate, commands
    raise Refusal("agathodaimon-ssh-exposure-service-missing")


def _service_readback(unit: str | None = None) -> tuple[dict[str, Any], list[list[str]]]:
    resolution: list[list[str]] = []
    if unit is None:
        unit, resolution = _service_unit()
    active_command = [SYSTEMCTL, "is-active", unit]
    enabled_command = [SYSTEMCTL, "is-enabled", unit]
    active = _run(active_command)
    enabled = _run(enabled_command)
    return {"requestedUnit": SSH_UNIT, "unit": unit, "active": active.stdout.strip() == "active", "activeState": active.stdout.strip() or "unknown", "enabled": enabled.stdout.strip() == "enabled", "enabledState": enabled.stdout.strip() or "unknown"}, [*resolution, active_command, enabled_command]


def status() -> dict[str, Any]:
    commands: list[list[str]] = []
    try:
        raw, read_commands = _read_config()
        commands.extend(read_commands)
        directives = _directive_values(raw)
        service, service_commands = _service_readback()
        commands.extend(service_commands)
        return _receipt("status", ok=True, changed=[], unchanged=[], readback={"directives": directives, "service": service}, commands=commands)
    except Refusal as exc:
        return _receipt("status", ok=False, changed=[], unchanged=[], readback=None, commands=commands, signal=str(exc))


def toggle(state: str) -> dict[str, Any]:
    desired = {"PasswordAuthentication": "no", "PubkeyAuthentication": "yes" if state == "on" else "no"}
    commands: list[list[str]] = []
    changed: list[dict[str, str]] = []
    unchanged: list[dict[str, str]] = []
    original: str | None = None
    config_written = False
    try:
        original, read_commands = _read_config()
        commands.extend(read_commands)
        _directive_values(original)
        updated = original
        for directive in DIRECTIVES:
            updated, transition = _replace_directive(updated, directive, desired[directive])
            if transition is None:
                unchanged.append({"directive": directive, "value": desired[directive]})
            else:
                changed.append(transition)
        commands.extend(_validate())
        if updated != original:
            commands.extend(_write_config(updated))
            config_written = True
            try:
                commands.extend(_validate())
            except Refusal:
                commands.extend(_write_config(original))
                commands.extend(_validate())
                raise
        service_before, service_before_commands = _service_readback()
        commands.extend(service_before_commands)
        unit = service_before["unit"]
        for action in (("enable", "start") if state == "on" else ("disable", "stop")):
            command = _sudo([SYSTEMCTL, action, unit])
            commands.append(command)
            _must(_run(command), f"agathodaimon-ssh-exposure-service-{action}-refused")
        final_raw, final_read_commands = _read_config()
        commands.extend(final_read_commands)
        directives = _directive_values(final_raw)
        service, service_commands = _service_readback(unit)
        commands.extend(service_commands)
        expected_active = state == "on"
        if service["active"] != expected_active or service["enabled"] != expected_active:
            raise Refusal("agathodaimon-ssh-exposure-service-readback-mismatch")
        if directives != desired:
            raise Refusal("agathodaimon-ssh-exposure-config-readback-mismatch")
        return _receipt(state, ok=True, changed=changed, unchanged=unchanged, readback={"directives": directives, "service": service}, commands=commands)
    except Refusal as exc:
        if config_written and original is not None:
            try:
                commands.extend(_write_config(original))
                commands.extend(_validate())
            except Refusal:
                return _receipt(state, ok=False, changed=changed, unchanged=unchanged, readback=None, commands=commands, signal="agathodaimon-ssh-exposure-config-restore-refused")
        return _receipt(state, ok=False, changed=changed, unchanged=unchanged, readback=None, commands=commands, signal=str(exc))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-ssh-exposure")
    parser.add_argument("state", choices=("on", "off", "status"))
    args = parser.parse_args(argv)
    receipt = status() if args.state == "status" else toggle(args.state)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

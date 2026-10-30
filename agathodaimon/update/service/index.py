"""Allowlisted update timer control through systemd."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any

SCHEMA = "caduceus.staff.update-service.v1"
TIMER_UNIT = "harmonia.timer"


ACTIONS = {"on", "off", "status"}
ENABLED_ZERO_STATES = frozenset(
    {"enabled", "enabled-runtime", "alias", "static", "indirect", "generated", "transient"}
)
ENABLED_POSITIVE_STATES = frozenset(
    {"linked", "linked-runtime", "masked", "masked-runtime", "disabled"}
)
ACTIVE_STATES = {
    "active": 0,
    "reloading": 0,
    "refreshing": 0,
    "inactive": 3,
    "failed": 3,
    "activating": 3,
    "deactivating": 3,
    "maintenance": 3,
}


def _receipt(
    *,
    timer: str | None = None,
    enabled: str | None = None,
    active: bool = False,
    ok: bool = False,
    output: str = "",
    first_missing_signal: str = "none",
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "timer": timer,
        "enabled": enabled,
        "active": active,
        "output": output,
        "firstMissingSignal": first_missing_signal,
    }


def _emit(receipt: dict[str, Any]) -> int:
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


def _text(value: bytes | str | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    if isinstance(value, str):
        return value.strip()
    return ""


def _record_result(lines: list[str], name: str, result: subprocess.CompletedProcess[bytes]) -> None:
    lines.append(f"{name} exit={result.returncode}")
    stdout = _text(result.stdout)
    stderr = _text(result.stderr)
    if stdout:
        lines.append(f"{name} stdout: {stdout}")
    if stderr:
        lines.append(f"{name} stderr: {stderr}")
    if not stdout and not stderr:
        lines.append(f"{name} output: (empty)")


def _run_systemctl(*args: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["/usr/bin/systemctl", *args], capture_output=True, check=False)


def _first_word(value: bytes | str | None) -> str | None:
    words = _text(value).split()
    return words[0] if words else None


def _observe_enabled(result: subprocess.CompletedProcess[bytes]) -> tuple[str | None, bool]:
    enabled = _first_word(result.stdout)
    if enabled in ENABLED_ZERO_STATES:
        valid = result.returncode == 0
    elif enabled in ENABLED_POSITIVE_STATES:
        valid = result.returncode > 0
    else:
        valid = False
    return enabled, valid


def _observe_active(result: subprocess.CompletedProcess[bytes]) -> tuple[bool, bool]:
    state = _first_word(result.stdout)
    active = state == "active" and result.returncode == ACTIVE_STATES["active"]
    valid = state in ACTIVE_STATES and ACTIVE_STATES[state] == result.returncode
    return active, valid


def _mark_failure(current: str, signal: str) -> str:
    return signal if current == "none" else current


def main(argv: list[str] | None = None) -> int:
    del argv  # This actuator's request contract is stdin JSON only.
    try:
        envelope = json.loads(sys.stdin.read())
    except (OSError, UnicodeError, json.JSONDecodeError):
        return _emit(_receipt(first_missing_signal="update-service-payload-invalid"))

    if not isinstance(envelope, dict):
        return _emit(_receipt(first_missing_signal="update-service-payload-invalid"))
    payload = envelope.get("payload") if "schema" in envelope else envelope
    # Unknown keys, such as the scrubbed flags room, are skipped, never fatal.
    if not isinstance(payload, dict):
        return _emit(_receipt(first_missing_signal="update-service-payload-invalid"))

    action = payload.get("action")
    if not isinstance(action, str) or action not in ACTIONS:
        return _emit(_receipt(first_missing_signal="update-service-action-invalid"))

    timer = TIMER_UNIT

    output: list[str] = []
    try:
        cat_result = _run_systemctl("cat", "--", timer)
    except (OSError, subprocess.SubprocessError) as error:
        output.append(f"cat error: {error}")
        return _emit(
            _receipt(
                timer=timer,
                output="\n".join(output),
                first_missing_signal="update-service-systemctl-failed",
            )
        )

    _record_result(output, "cat", cat_result)
    if cat_result.returncode != 0:
        return _emit(
            _receipt(
                timer=timer,
                output="\n".join(output),
                first_missing_signal="update-service-unit-missing",
            )
        )

    cat_output_present = bool(_text(cat_result.stdout))
    if not cat_output_present:
        return _emit(
            _receipt(
                timer=timer,
                output="\n".join(output),
                first_missing_signal="update-service-systemctl-failed",
            )
        )

    first_missing_signal = "none"
    action_ok = True
    if action in {"on", "off"}:
        command = "enable" if action == "on" else "disable"
        try:
            action_result = _run_systemctl(command, "--now", "--", timer)
        except (OSError, subprocess.SubprocessError) as error:
            output.append(f"{command} --now error: {error}")
            action_ok = False
        else:
            _record_result(output, f"{command} --now", action_result)
            action_ok = action_result.returncode == 0
        if not action_ok:
            first_missing_signal = _mark_failure(first_missing_signal, "update-service-systemctl-failed")

    enabled: str | None = None
    enabled_valid = False
    try:
        enabled_result = _run_systemctl("is-enabled", "--", timer)
    except (OSError, subprocess.SubprocessError) as error:
        output.append(f"is-enabled error: {error}")
        first_missing_signal = _mark_failure(first_missing_signal, "update-service-systemctl-failed")
    else:
        _record_result(output, "is-enabled", enabled_result)
        enabled, enabled_valid = _observe_enabled(enabled_result)
        if not enabled_valid:
            first_missing_signal = _mark_failure(first_missing_signal, "update-service-systemctl-failed")

    active = False
    active_valid = False
    active_state: str | None = None
    try:
        active_result = _run_systemctl("is-active", "--", timer)
    except (OSError, subprocess.SubprocessError) as error:
        output.append(f"is-active error: {error}")
        first_missing_signal = _mark_failure(first_missing_signal, "update-service-systemctl-failed")
    else:
        _record_result(output, "is-active", active_result)
        active_state = _first_word(active_result.stdout)
        active, active_valid = _observe_active(active_result)
        if not active_valid:
            first_missing_signal = _mark_failure(first_missing_signal, "update-service-systemctl-failed")

    desired_state_observed = (
        action == "status"
        or (action == "on" and enabled == "enabled" and active)
        or (action == "off" and enabled == "disabled" and active_state == "inactive")
    )
    if not desired_state_observed:
        first_missing_signal = _mark_failure(first_missing_signal, "update-service-systemctl-failed")

    ok = (
        first_missing_signal == "none"
        and action_ok
        and cat_output_present
        and enabled_valid
        and active_valid
        and bool("\n".join(output).strip())
    )
    return _emit(
        _receipt(
            timer=timer,
            enabled=enabled,
            active=active,
            ok=ok,
            output="\n".join(output),
            first_missing_signal=first_missing_signal,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())

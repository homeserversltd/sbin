"""Allowlisted update timer control through systemd."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "caduceus.staff.update-service.v1"


def _root() -> Path:
    return Path(os.environ.get("CADUCEUS_ROOT", "/"))


def _path(env: str, absolute: str) -> Path:
    value = os.environ.get(env)
    return Path(value) if value else _root() / absolute.lstrip("/")


def _profile_paths() -> tuple[Path, ...]:
    override = os.environ.get("CADUCEUS_PROFILE_PATH")
    if override:
        return (Path(override),)
    return tuple(
        _path("CADUCEUS_PROFILE_PATH", absolute)
        for absolute in (
            "/etc/caduceus/profile.yaml",
            "/etc/caduceus/profile.yml",
            "/etc/caduceus/profile.json",
        )
    )


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


def safe_timer_unit(value: Any) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.isascii()
        and value[0].isalnum()
        and value.endswith(".timer")
        and ".." not in value
        and all(char.isalnum() or char in "-_.@" for char in value)
    )


_YAML_KEY = re.compile(r"^([A-Za-z0-9_-]+):(.*)$")


def _without_yaml_comment(line: str) -> str:
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote == "'":
            if char == "'":
                if index + 1 < len(line) and line[index + 1] == "'":
                    index += 2
                    continue
                quote = None
        elif quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace()):
            return line[:index]
        index += 1
    if quote is not None:
        raise ValueError("malformed YAML quote")
    return line


def _yaml_timer_scalar(value: str) -> str:
    if not value:
        raise ValueError("missing YAML timer")
    if value[0] not in {"'", '"'}:
        return value
    quote = value[0]
    if len(value) < 2 or value[-1] != quote:
        raise ValueError("malformed YAML timer quote")
    scalar = value[1:-1]
    if quote == '"' and ("\\" in scalar or '"' in scalar):
        raise ValueError("unsupported YAML timer escape")
    if quote == "'" and "'" in scalar:
        raise ValueError("unsupported YAML timer quote")
    return scalar


def _fallback_yaml_timer(text: str) -> str:
    """Resolve only the simple services.update.timer block used on the house."""
    stack: list[tuple[int, str | None]] = []
    services_count = 0
    update_count = 0
    timer_values: list[str] = []

    for raw_line in text.splitlines():
        line = _without_yaml_comment(raw_line)
        if not line.strip():
            continue
        prefix = line[: len(line) - len(line.lstrip(" " + chr(9)))]
        if any(char == chr(9) for char in prefix):
            raise ValueError("tab indentation in YAML")
        indent = len(prefix)
        body = line[indent:]
        if body in {"---", "..."}:
            raise ValueError("multiple YAML document markers")

        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = tuple(key for _, key in stack)

        if body == "-" or body.startswith("- "):
            if parent == ("services",):
                raise ValueError("services is not a YAML mapping")
            stack.append((indent, None))
            continue

        match = _YAML_KEY.match(body)
        if match is None:
            if parent in {("services",), ("services", "update")} or not parent:
                raise ValueError("malformed YAML mapping")
            continue

        key, remainder = match.groups()
        if remainder and not remainder[0].isspace():
            if (
                (parent == () and key == "services")
                or (parent == ("services",) and key == "update")
                or (parent == ("services", "update") and key == "timer")
                or not parent
            ):
                raise ValueError("malformed YAML mapping entry")
            continue
        value = remainder.strip()

        if parent == () and key == "services":
            services_count += 1
            if services_count != 1 or indent != 0 or value:
                raise ValueError("ambiguous or shapeless services mapping")
        elif parent == ("services",) and key == "update":
            update_count += 1
            if update_count != 1 or indent != 2 or value:
                raise ValueError("ambiguous or shapeless update mapping")
        elif parent == ("services", "update") and key == "timer":
            if indent != 4 or timer_values:
                raise ValueError("ambiguous or shapeless timer declaration")
            timer_values.append(_yaml_timer_scalar(value))

        if not value:
            stack.append((indent, key))

    if services_count != 1 or update_count != 1 or len(timer_values) != 1:
        raise ValueError("shapeless services.update.timer declaration")
    return timer_values[0]


def _yaml_profile(text: str) -> Any:
    try:
        import yaml
    except ImportError:
        timer = _fallback_yaml_timer(text)
        return {"services": {"update": {"timer": timer}}}
    try:
        return yaml.safe_load(text)
    except Exception as error:
        raise ValueError("invalid Caduceus YAML profile") from error


def _profile_timer(profile: Any) -> str:
    services = profile.get("services") if isinstance(profile, dict) else None
    update = services.get("update") if isinstance(services, dict) else None
    timer = update.get("timer") if isinstance(update, dict) else None
    if not isinstance(timer, str) or not safe_timer_unit(timer):
        raise ValueError("update-service-timer-undeclared")
    return timer


def declared_timer() -> str:
    for profile_path in _profile_paths():
        try:
            with profile_path.open("r", encoding="utf-8") as source:
                text = source.read()
        except OSError:
            continue
        except UnicodeError as error:
            raise ValueError("update-service-timer-undeclared") from error

        try:
            profile = json.loads(text) if profile_path.suffix == ".json" else _yaml_profile(text)
            return _profile_timer(profile)
        except Exception as error:
            raise ValueError("update-service-timer-undeclared") from error
    raise ValueError("update-service-timer-undeclared")


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

    try:
        timer = declared_timer()
    except ValueError:
        return _emit(_receipt(first_missing_signal="update-service-timer-undeclared"))

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

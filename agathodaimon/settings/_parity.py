"""Keyboard, region and power settings exposed through the staff crossing."""
from __future__ import annotations

import grp
import json
import math
import os
import pwd
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from agathodaimon._nidus.refusal import named_signal
from agathodaimon._nidus.write import WriteError, write
from agathodaimon.settings import _options, _shared, _sway_overrides
from agathodaimon.settings.display import backends
from agathodaimon.settings.energy import _hardware, screen_idle
from agathodaimon.settings._sway import _sway_reload


def _command(argv: list[str], receipt: _shared.Receipt | None = None) -> tuple[bool, str]:
    ok, output, result = _shared.command(argv)
    if receipt is not None:
        receipt.commands.append({"argv": argv, "returncode": result.returncode})
    return ok, output


def _etc() -> Path:
    return Path(os.environ.get("CADUCEUS_SETTINGS_ETC", "/etc"))


def _keyboard_path() -> Path:
    return _sway_overrides.path()


def _keyboard_values() -> dict[str, Any]:
    values: dict[str, Any] = {key: None for key in _shared.FIELDS["keyboard"]}
    paths = [_shared.home() / ".config/sway/conf.d/input.conf", _keyboard_path()]
    for path in paths:
        for line in _shared.ini_read(path):
            match = re.match(r'^\s*(?:input\s+type:keyboard\s+)?(xkb_layout|repeat_rate|repeat_delay)\s+([\w,.-]+)\s*(?:#.*)?$', line)
            if not match:
                continue
            name = "keyboard_layout" if match.group(1) == "xkb_layout" else match.group(1)
            value = match.group(2)
            values[name] = int(value) if name != "keyboard_layout" and value.isdigit() else value
    selected = backends.select_backend()
    if selected:
        socket = str(selected["socket"])
        argv, runtime, _ = backends._sway_argv(socket, ["-t", "get_inputs"])
        result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
        try:
            devices = json.loads(result.get("stdout", "")) if result.get("ok") else []
            keyboards = [item for item in devices if isinstance(item, dict) and item.get("type") == "keyboard"]
            for key in ("repeat_rate", "repeat_delay"):
                seen = [item.get(key) for item in keyboards if isinstance(item.get(key), int) and not isinstance(item.get(key), bool)]
                if seen and all(item == seen[0] for item in seen): values[key] = seen[0]
        except (TypeError, ValueError):
            pass
    return values


def _region_values() -> dict[str, Any]:
    values: dict[str, Any] = {"locale": None, "measurement_units": None}
    assignments: dict[str, str] = {}
    for line in _shared.ini_read(_etc() / "locale.conf"):
        match = re.match(r"^\s*(LANG|LC_MEASUREMENT)\s*=\s*(.*?)\s*$", line)
        if not match:
            continue
        try:
            parsed = shlex.split(match.group(2), comments=True)
        except ValueError:
            continue
        if len(parsed) == 1:
            assignments[match.group(1)] = parsed[0]
    values["locale"] = assignments.get("LANG")
    measurement = assignments.get("LC_MEASUREMENT") or assignments.get("LANG")
    if measurement and re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", measurement):
        try:
            environment = os.environ.copy()
            environment["LC_ALL"] = measurement
            result = subprocess.run(["locale", "-k", "LC_MEASUREMENT"], capture_output=True, text=True, timeout=3, env=environment, check=False)
            match = re.search(r"^measurement=([12])$", result.stdout, re.MULTILINE)
            if result.returncode == 0 and not result.stderr and match:
                values["measurement_units"] = "metric" if match.group(1) == "1" else "imperial"
        except (OSError, subprocess.SubprocessError):
            pass
    return values


_POWER_BUTTON_ACTIONS = {"poweroff", "suspend", "ignore"}


def _logind_action(key: str) -> str | None:
    if _etc() == Path("/etc"):
        ok, out = _command(["busctl", "--system", "get-property", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", key])
        if ok:
            try:
                items = shlex.split(out)
                if len(items) == 2 and items[0] == "s" and re.fullmatch(r"[a-z][a-z0-9-]*", items[1]):
                    return items[1]
            except ValueError:
                pass
        return None
    value = None
    systemd = _etc() / "systemd"
    for path in [systemd / "logind.conf", *sorted((systemd / "logind.conf.d").glob("*.conf"))]:
        active = False
        for line in _shared.ini_read(path):
            stripped = line.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                active = stripped == "[Login]"
            if active:
                match = re.fullmatch(rf"{key}\s*=\s*([a-z][a-z0-9-]*)\s*(?:#.*)?", stripped)
                if match:
                    value = match.group(1)
    return value


def _screen_environment() -> dict[str, str] | None:
    from agathodaimon.face import _shared as face
    try:
        environment, _ = face.owner_session_environment(
            home=_shared.home(), require_sway=True, require_wayland=True,
            prefer_direct_keys=("SWAYSOCK", "WAYLAND_DISPLAY"),
        )
    except face.FaceError:
        return None
    return environment


def read_energy() -> dict[str, Any]:
    readonly: dict[str, str] = {}
    screen_off = None
    if _screen_environment() is not None:
        try:
            screen_off = screen_idle.read_seconds(_shared.home())
        except ValueError:
            pass
    else:
        readonly["screen_off_seconds"] = _shared.SWAY_SESSION_UNAVAILABLE
        if backends._owner_processes("hypridle"):
            screen_off = _hardware.hypridle_screen_off(_shared.home())
    power_key = _logind_action("HandlePowerKey")
    values: dict[str, Any] = {"screen_off_seconds": screen_off, "sleep_seconds": None,
                              "power_button_action": power_key if power_key in _POWER_BUTTON_ACTIONS else None}
    battery = _hardware.battery_values()
    if battery:
        values.update(battery, lid_action=_logind_action("HandleLidSwitch"))
        readonly.update(dict.fromkeys(_hardware.SYSTEM_FIELDS, "system-owned"))
    conservation_mode = _hardware.conservation_mode()
    if conservation_mode is not None:
        values["charge_limit"] = _hardware.charge_limit(conservation_mode)
    result: dict[str, Any] = {"values": values}
    profile, choices = _options.power_profiles()
    if profile is not None:
        values["power_profile"] = profile
        result["options"] = {"power_profile": choices}
    if readonly:
        result["readonly"] = readonly
    return result


def get_values(kind: str) -> dict[str, Any]:
    if kind == "energy":
        return read_energy()["values"]
    return {"keyboard": _keyboard_values, "region": _region_values}[kind]()




def _set_keyboard(field: str, value: Any, receipt: _shared.Receipt) -> None:
    if field == "keyboard_layout":
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_,.-]{1,128}", value):
            raise ValueError("invalid:keyboard_layout")
        text, key = value, "xkb_layout"
    else:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 10000:
            raise ValueError(f"invalid:{field}")
        text, key = str(value), field
    if not backends.select_backend() and os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") != "1":
        raise ValueError("sway-session-unavailable")
    begin = f"# settings-keyboard-{key}-begin\n"
    end = f"# settings-keyboard-{key}-end\n"
    _sway_overrides.replace_block(begin, end, [f"input type:keyboard {key} {text}\n"], receipt, "keyboard-override-invalid")


def _scroll_factor(raw: Any) -> float | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, float, str)):
        return None
    try:
        number = float(raw)
    except (ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and number >= 0 else None


def _input_scalar(field: str, raw: Any) -> Any:
    if field == "scroll_factor":
        return _scroll_factor(raw)
    if field in {"left_handed", "disable_while_typing", "natural_scroll", "tap_to_click"}:
        if isinstance(raw, bool): return raw
        if raw in ("enabled", "disabled"): return raw == "enabled"
    elif field == "pointer_speed":
        try:
            if isinstance(raw, bool): return None
            value = float(raw)
            if -1 <= value <= 1: return value
        except (TypeError, ValueError):
            pass
    elif field == "accel_profile" and raw in ("flat", "adaptive"):
        return raw
    return None


def _declared_input(lines: Iterable[str]) -> dict[tuple[str, str], Any]:
    keys = {"pointer_accel": "pointer_speed", "accel_profile": "accel_profile",
            "left_handed": "left_handed", "dwt": "disable_while_typing",
            "natural_scroll": "natural_scroll", "tap": "tap_to_click", "scroll_factor": "scroll_factor"}
    result: dict[tuple[str, str], Any] = {}
    active = None
    for line in lines:
        code = line.split("#", 1)[0].strip()
        opening = re.fullmatch(r"input\s+type:(pointer|touchpad)\s*\{\s*", code)
        if opening:
            active = opening.group(1)
            continue
        if code == "}":
            active = None
            continue
        inline = re.fullmatch(r"input\s+type:(pointer|touchpad)\s+(\w+)\s+(\S+)", code)
        item = re.fullmatch(r"(\w+)\s+(\S+)", code) if active else None
        if inline:
            kind, key, raw = inline.groups()
        elif item:
            kind, (key, raw) = active, item.groups()
        else:
            continue
        field = keys.get(key)
        value = _input_scalar(field, raw) if field else None
        if field is not None and isinstance(kind, str) and value is not None:
            result[(kind, field)] = value
    return result


def sway_input_values(selected: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    values: dict[str, Any] = {key: None for key in _shared.FIELDS["input"]}
    sources = {key: "none" for key in values}
    base = _declared_input(_shared.ini_read(_shared.home() / ".config/sway/conf.d/input.conf"))
    override = _declared_input(_shared.ini_read(_keyboard_path()))
    devices: list[Any] = []
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, ["-t", "get_inputs"])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    try:
        raw_devices = json.loads(result.get("stdout", "")) if result.get("ok") else []
        if isinstance(raw_devices, list): devices = raw_devices
    except (TypeError, ValueError):
        pass
    fields = (("accel_profile", "accel_profile"), ("left_handed", "left_handed"),
              ("disable_while_typing", "dwt"), ("natural_scroll", "natural_scroll"),
              ("tap_to_click", "tap"), ("pointer_speed", "accel_speed"))
    for field, raw_key in fields:
        kinds = ("touchpad",) if field in {"tap_to_click", "disable_while_typing"} else ("pointer", "touchpad")
        live = [_input_scalar(field, d["libinput"].get(raw_key)) for kind in kinds for d in devices
                if isinstance(d, dict) and d.get("type") == kind and isinstance(d.get("libinput"), dict)]
        live = [value for value in live if value is not None]
        if live:
            values[field], sources[field] = live[0], "device"
            continue
        for mapping, source in ((override, "override"), (base, "declared")):
            value = next((mapping[(kind, field)] for kind in kinds if (kind, field) in mapping), None)
            if value is not None:
                values[field], sources[field] = value, source
                break

    begin, end = _input_markers("scroll_factor")
    scroll_override = _declared_input(_sway_overrides.read_block(begin, end) or [])
    scroll_key = ("pointer", "scroll_factor")
    for device in devices:
        if isinstance(device, dict) and device.get("type") == "pointer":
            raw = device.get("scroll_factor")
            value = _scroll_factor(raw) if isinstance(raw, (int, float)) else None
            if value is not None:
                values["scroll_factor"], sources["scroll_factor"] = value, "device"
                break
    else:
        for mapping, source in ((scroll_override, "override"), (base, "declared")):
            if scroll_key in mapping:
                values["scroll_factor"], sources["scroll_factor"] = mapping[scroll_key], source
                break
    return values, sources


def sway_cursor_override() -> tuple[str, int] | None:
    begin, end = "# settings-appearance-cursor-begin\n", "# settings-appearance-cursor-end\n"
    lines = _sway_overrides.read_block(begin, end)
    if lines is None:
        return None
    for line in lines:
        try:
            parts = shlex.split(line, comments=True)
            if len(parts) == 5 and parts[:3] == ["seat", "*", "xcursor_theme"]:
                size = int(parts[4])
                if 8 <= size <= 256: return parts[3], size
        except ValueError:
            continue
    return None


def _sway_cursor(theme: str, size: int, receipt: _shared.Receipt) -> None:
    selected = backends.select_backend()
    if not selected: raise ValueError("sway-session-unavailable")
    sway_command(selected, f"seat * xcursor_theme {json.dumps(theme)} {size}", receipt, "sway-cursor-failed")


def sway_command(selected: dict[str, Any], command: str, receipt: _shared.Receipt, failure: str) -> None:
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, [command])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    receipt.commands.append({"argv": argv, "returncode": result.get("returncode")})
    try:
        replies = json.loads(result.get("stdout", ""))
    except (TypeError, ValueError):
        replies = []
    if not result.get("ok") or not isinstance(replies, list) or not replies or any(not isinstance(x, dict) or x.get("success") is not True for x in replies):
        raise ValueError(failure)


def set_sway_cursor(theme: str, size: int, receipt: _shared.Receipt) -> None:
    if not theme or len(theme) > 256 or any(ord(c) < 32 for c in theme):
        raise ValueError("invalid:cursor_theme")
    begin, end = "# settings-appearance-cursor-begin\n", "# settings-appearance-cursor-end\n"
    _sway_overrides.replace_block(begin, end, [f"seat * xcursor_theme {json.dumps(theme)} {size}\n"], receipt, "cursor-override-invalid", strict_order=True)
    if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
        receipt.commands.append({"argv": ["swaymsg", "seat", "*", "xcursor_theme", theme, str(size)], "dryRun": True})
    else:
        _sway_cursor(theme, size, receipt)


def _input_markers(field: str) -> tuple[str, str]:
    return f"# settings-input-{field}-begin\n", f"# settings-input-{field}-end\n"


def input_block(field: str, value: Any) -> tuple[str, str, list[str]]:
    if field == "scroll_factor":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("invalid:scroll_factor:number-required")
        if not 0.1 <= value <= 10:
            raise ValueError("invalid:scroll_factor:range")
        settings = [("pointer", "scroll_factor", str(value))]
    elif field == "accel_profile":
        if not isinstance(value, str) or value not in {"flat", "adaptive"}: raise ValueError("invalid:accel_profile")
        settings = [("pointer", "accel_profile", value), ("touchpad", "accel_profile", value)]
    elif field == "pointer_speed":
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not -1 <= value <= 1: raise ValueError("invalid:pointer_speed")
        settings = [("pointer", "pointer_accel", str(value)), ("touchpad", "pointer_accel", str(value))]
    elif field in {"left_handed", "disable_while_typing", "natural_scroll", "tap_to_click"}:
        if not isinstance(value, bool): raise ValueError("invalid:" + field)
        rendered = "enabled" if value else "disabled"
        key = {"left_handed": "left_handed", "disable_while_typing": "dwt", "natural_scroll": "natural_scroll", "tap_to_click": "tap"}[field]
        kinds = ("touchpad",) if field in {"disable_while_typing", "tap_to_click"} else ("pointer", "touchpad")
        settings = [(kind, key, rendered) for kind in kinds]
    else:
        raise ValueError("unsupported:" + field)
    begin, end = _input_markers(field)
    return begin, end, [f"input type:{kind} {key} {val}\n" for kind, key, val in settings]


def _set_region(field: str, value: Any, receipt: _shared.Receipt) -> None:
    if field == "locale":
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", value):
            raise ValueError("invalid:locale")
        assignment = "LANG=" + value
    else:
        if value not in ("metric", "imperial"):
            raise ValueError("invalid:measurement_units")
        assignment = "LC_MEASUREMENT=" + ("C.UTF-8" if value == "metric" else "en_US.UTF-8")
    path = _etc() / "locale.conf"
    receipt.backup(path)
    argv = ["localectl", "set-locale", assignment]
    if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
        receipt.commands.append({"argv": argv, "dryRun": True})
        return
    ok, _ = _command(argv, receipt)
    if not ok:
        raise ValueError("localectl-failed")
    receipt.changed = True


_SCREEN_IDLE_LAUNCHER = str(Path(__file__).resolve().parent.parent / "caduceus-screen-idle")


def _screen_idle_running(environment: dict[str, str]) -> bool:
    from agathodaimon.face import _shared as face
    uid = str(pwd.getpwnam(_shared.OWNER_USER).pw_uid)
    result = face.owner_run(["pgrep", "-u", uid, "-x", "swayidle"], environment)
    if result.returncode not in (0, 1):
        raise ValueError("swayidle-observation-failed")
    return result.returncode == 0


def _restart_screen_idle(seconds: int, environment: dict[str, str], receipt: _shared.Receipt) -> None:
    from agathodaimon.face import _shared as face
    uid = str(pwd.getpwnam(_shared.OWNER_USER).pw_uid)
    stop = ["pkill", "-u", uid, "-x", "swayidle"]
    result = face.owner_run(stop, environment)
    receipt.commands.append({"argv": stop, "returncode": result.returncode})
    if result.returncode not in (0, 1): raise ValueError("swayidle-stop-failed")
    deadline = time.monotonic() + 3
    while _screen_idle_running(environment):
        if time.monotonic() >= deadline: raise ValueError("swayidle-stop-timeout")
        time.sleep(0.05)
    if seconds:
        face.owner_spawn([_SCREEN_IDLE_LAUNCHER], environment)
        receipt.commands.append({"argv": [_SCREEN_IDLE_LAUNCHER], "spawned": True})
        deadline = time.monotonic() + 3
        while not _screen_idle_running(environment):
            if time.monotonic() >= deadline: raise ValueError("swayidle-start-timeout")
            time.sleep(0.05)


def _set_power_profile(value: str, receipt: _shared.Receipt) -> None:
    ok, _ = _command(["powerprofilesctl", "set", value], receipt)
    if not ok:
        raise ValueError("power-profile-set-failed")
    ok, current = _command(["powerprofilesctl", "get"], receipt)
    if not ok or current != value:
        raise ValueError("power-profile-readback-mismatch")


def _restore_power_profile(value: str, receipt: _shared.Receipt) -> None:
    ok, current = _command(["powerprofilesctl", "get"], receipt)
    if not ok or current != value:
        _set_power_profile(value, receipt)


def _restore_charge_limit(path: Path, value: bool) -> None:
    if _hardware.charge_limit(path) is not value:
        _hardware.write_charge_limit(path, value)


def _reload_logind(receipt: _shared.Receipt) -> None:
    ok, _ = _command(["systemctl", "kill", "-s", "HUP", "systemd-logind"], receipt)
    if not ok:
        raise ValueError("logind-reload-failed")


def _confirm_power_key(expected: str) -> str:
    # HUP dispatch can return before logind has parsed the new file.
    deadline = time.monotonic() + 2
    while True:
        observed = _logind_action("HandlePowerKey")
        if observed is not None and observed == expected:
            return observed
        if time.monotonic() >= deadline:
            raise ValueError("logind-power-key-observation-failed" if observed is None else "logind-power-key-shadowed")
        time.sleep(0.05)


@dataclass
class _EnergyFile:
    edit: dict[str, Any]
    apply: Callable[[], None]
    restore: Callable[[], None]
    readback: Callable[[], Any]
    reconcile: bool = False


def _plan_power_profile(value: Any) -> tuple[str, str] | None:
    if not isinstance(value, str):
        raise ValueError("invalid:power_profile")
    active, choices = _options.power_profiles()
    if active is None:
        raise ValueError("unsupported:power-profiles-daemon-unavailable")
    if not any(choice["value"] == value for choice in choices):
        raise ValueError("invalid:power_profile")
    return (active, value) if active != value else None


def _plan_energy_file(field: str, value: Any, environment: dict[str, str] | None,
                      receipt: _shared.Receipt | None, preview: list[dict[str, Any]]) -> _EnergyFile | None:
    if field == "screen_off_seconds":
        if environment is None:
            raise ValueError("unsupported:" + _shared.SWAY_SESSION_UNAVAILABLE)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 86400:
            raise ValueError("invalid:screen_off_seconds")
        path = _shared.home() / ".config/sway/screen-idle.json"
        payload = (json.dumps({"screen_off_seconds": value}) + "\n").encode()
        if receipt is None:
            preview.extend([{"write": str(path), "contents": payload.decode(), "dryRun": True},
                            {"argv": ["pkill", "-u", _shared.OWNER_USER, "-x", "swayidle"], "dryRun": True},
                            {"argv": [_SCREEN_IDLE_LAUNCHER], "dryRun": True, "spawn": value > 0}])
            return
        owner = pwd.getpwnam(_shared.OWNER_USER)
        edit = {"path": path, "candidate": payload, "mode": 0o644,
                "owner": (owner.pw_name, grp.getgrgid(owner.pw_gid).gr_name)}

        def read_screen():
            seconds = screen_idle.read_seconds(_shared.home())
            running = _screen_idle_running(environment)
            if seconds != value or running != bool(seconds):
                raise ValueError("screen-idle-readback-mismatch")
            return {"seconds": seconds, "swayidle": running}

        return _EnergyFile(edit, lambda: _restart_screen_idle(value, environment, receipt),
                           lambda: _restart_screen_idle(screen_idle.read_seconds(_shared.home()), environment, receipt),
                           read_screen, reconcile=True)
    if field == "charge_limit":
        enabled = _shared.boolean(value, field)
        sysfs = _hardware.conservation_mode()
        if sysfs is None:
            raise ValueError("unsupported:charge_limit")
        original = _hardware.charge_limit(sysfs)
        if original is None:
            raise ValueError("charge-limit-unreadable")
        mode = "1" if enabled else "0"
        drop_in = _etc() / _hardware.CHARGE_LIMIT_DROP_IN
        rule = f"w {sysfs} - - - - {mode}\n"
        if drop_in.is_symlink():
            raise ValueError("charge-limit-drop-in-is-symlink")
        if receipt is None:
            preview.extend([{"write": str(drop_in), "contents": rule, "dryRun": True},
                            {"write": str(sysfs), "contents": mode, "dryRun": True}])
            return
        def apply_charge():
            if original is not enabled:
                _hardware.write_charge_limit(sysfs, enabled)
                receipt.changed = True

        def read_charge():
            observed = _hardware.charge_limit(sysfs)
            if observed is not enabled:
                raise ValueError("charge-limit-readback-mismatch")
            return observed

        return _EnergyFile({"path": drop_in, "candidate": rule.encode()}, apply_charge,
                           lambda: _restore_charge_limit(sysfs, original), read_charge,
                           reconcile=original is not enabled)
    if field != "power_button_action":
        raise ValueError("unsupported:" + field)
    if not isinstance(value, str) or value not in _POWER_BUTTON_ACTIONS:
        raise ValueError("invalid:power_button_action")
    path = _etc() / "systemd/logind.conf.d/60-appliance-power.conf"
    text = f"[Login]\nHandlePowerKey={value}\n"
    if receipt is None:
        preview.extend([{"write": str(path), "contents": text, "dryRun": True},
                        {"argv": ["systemctl", "kill", "-s", "HUP", "systemd-logind"], "dryRun": True}])
        return
    original_key = _logind_action("HandlePowerKey")

    def restore_key():
        _reload_logind(receipt)
        if original_key is not None:
            _confirm_power_key(original_key)

    return _EnergyFile({"path": path, "candidate": text.encode()}, lambda: _reload_logind(receipt),
                       restore_key, lambda: _confirm_power_key(value))


def _write_energy(changes: dict[str, Any]) -> dict[str, Any]:
    for field in changes:
        if field in _hardware.SYSTEM_FIELDS:
            raise ValueError("unsupported:system-owned")
        if field == "sleep_seconds":
            raise ValueError("energy-idle-consumer-absent")
    environment = _screen_environment() if "screen_off_seconds" in changes else None
    if "screen_off_seconds" in changes and environment is None:
        raise ValueError("unsupported:" + _shared.SWAY_SESSION_UNAVAILABLE)
    preview: list[dict[str, Any]] = []
    dry_run = os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1"
    receipt = None if dry_run else _shared.Receipt("energy", list(changes))
    files: dict[str, _EnergyFile] = {}
    profile = None
    try:
        for field, value in changes.items():
            if field == "power_profile":
                profile = _plan_power_profile(value)
                if dry_run and profile is not None:
                    preview.append({"argv": ["powerprofilesctl", "set", profile[1]], "dryRun": True})
            else:
                plan = _plan_energy_file(field, value, environment, receipt, preview)
                if plan is not None:
                    files[field] = plan
    except Exception as error:
        if receipt is not None:
            failed = receipt.finish(False, error=str(error))
            raise _shared.ReceiptFailure(str(error), failed["receipt"]) from error
        raise
    if receipt is None:
        return {"ok": True, "changed": False, "mutationPerformed": False, "dryRun": True, "commands": preview,
                "receipt": {"kind": "energy", "fields": list(changes), "ok": True,
                            "changed": False, "backups": [], "commands": preview}}

    undo: list[Callable[[], None]] = []
    parts: dict[str, Any] = {}
    result: dict[str, Any] = {}
    live: dict[str, Any] = {}
    apply_pending = replaced = False

    def check():
        for plan in files.values():
            plan.edit["path"].parent.mkdir(parents=True, exist_ok=True)

    def verify():
        nonlocal apply_pending
        for field, plan in files.items():
            if plan.edit["path"].read_bytes() != plan.edit["candidate"]:
                signal = "charge-limit-drop-in-readback-mismatch" if field == "charge_limit" else f"energy-file-readback-mismatch:{field}"
                raise ValueError(signal)
        apply_pending = True

    def reload():
        nonlocal apply_pending, replaced
        if apply_pending:
            apply_pending = False
            replaced = True
            for plan in files.values():
                plan.apply()
            return
        # Nidus restores the original files before calling us again, even if
        # verify failed before the first reload. Try every live restoration.
        failures = []
        for plan in reversed(list(files.values())):
            try:
                plan.restore()
            except Exception as error:
                failures.append(named_signal(error, "settings-energy"))
        if failures:
            raise ValueError(":".join(failures))

    def readback():
        if not replaced:
            # The nidus skips reload for identical bytes. Reconcile the sysfs
            # value and the swayidle consumer even when their files agree.
            for plan in files.values():
                if plan.reconcile:
                    undo.append(plan.restore)
                    plan.apply()
        for field, plan in files.items():
            live[field] = plan.readback()
        result.update(receipt.finish(True, replaced or receipt.changed))

    try:
        if profile is not None:
            old, new = profile
            undo.append(lambda: _restore_power_profile(old, receipt))
            _set_power_profile(new, receipt)
            receipt.changed = True
        if files:
            parts = write([plan.edit for plan in files.values()], check=check, verify=verify,
                          reload=reload, readback=readback)
            parts["attempt"]["attempted"] |= bool(undo)
            parts["attempt"]["readback"] = live
        else:
            readback()
        return {**parts, **result}
    except Exception as error:
        cause = error.cause if isinstance(error, WriteError) else error
        if isinstance(error, WriteError):
            parts = error.parts
            parts["attempt"]["attempted"] |= bool(undo)
        failures = [named_signal(item, "settings-energy") for item in error.restore_errors] if isinstance(error, WriteError) else []
        for restore in reversed(undo):
            try:
                restore()
            except Exception as rollback_error:
                failures.append(named_signal(rollback_error, "settings-energy"))
        signal = named_signal(cause, "settings-energy")
        if failures:
            signal = ":".join(["rollback-failed", *failures, signal])
        if parts:
            parts["final_receipt"] = {"ok": False, "firstMissingSignal": signal}
        failure = receipt.finish(False, error=signal)
        return {**parts, **failure, "changed": False, "mutationPerformed": bool(failures)}


def _set(kind: str, changes: dict[str, Any]) -> dict[str, Any]:
    if not changes:
        raise ValueError("no-fields-supplied")
    for field in changes:
        if field not in _shared.FIELDS[kind]:
            raise ValueError("unsupported:" + field)
    if kind == "energy":
        return _write_energy(changes)
    receipt = _shared.Receipt(kind, list(changes))
    reload_attempted = False
    try:
        for field, value in changes.items():
            {"keyboard": _set_keyboard, "region": _set_region}[kind](field, value, receipt)
        if kind == "keyboard" and receipt.changed:
            if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
                receipt.commands.append({"argv": ["swaymsg", "reload"], "dryRun": True})
            else:
                reload_attempted = True
                _sway_reload(receipt)
        answer = receipt.finish(True, receipt.changed)
        if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
            answer.update(dryRun=True, commands=receipt.commands)
        return answer
    except Exception as error:
        mutated = receipt.changed
        signal = str(error)
        try:
            receipt.restore_backups()
            if reload_attempted:
                _sway_reload(receipt)
            uncertain = False
        except Exception as rollback_error:
            signal = "rollback-failed:" + str(rollback_error) + ":" + signal
            uncertain = mutated
        failure = receipt.finish(False, error=signal)
        raise _shared.ReceiptFailure(signal, failure["receipt"], uncertain) from error

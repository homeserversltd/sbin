"""Keyboard, region and power settings exposed through the staff crossing."""
from __future__ import annotations

import json
import os
import pwd
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared
from agathodaimon.settings.display import backends


def _command(argv: list[str], receipt: _shared.Receipt | None = None) -> tuple[bool, str]:
    ok, output, result = _shared.command(argv)
    if receipt is not None:
        receipt.commands.append({"argv": argv, "returncode": result.returncode})
    return ok, output


def _etc() -> Path:
    return Path(os.environ.get("CADUCEUS_SETTINGS_ETC", "/etc"))


def _keyboard_path() -> Path:
    return _shared.home() / ".config/sway/input-overrides.conf"


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


def _energy_values() -> dict[str, Any]:
    from agathodaimon.settings.energy.screen_idle import read_seconds
    try:
        screen_off = read_seconds(_shared.home())
    except ValueError:
        screen_off = None
    values: dict[str, Any] = {"screen_off_seconds": screen_off, "sleep_seconds": None, "power_button_action": None}
    if _etc() == Path("/etc"):
        ok, out = _command(["busctl", "--system", "get-property", "org.freedesktop.login1", "/org/freedesktop/login1", "org.freedesktop.login1.Manager", "HandlePowerKey"])
        if ok:
            try:
                items = shlex.split(out)
                if len(items) == 2 and items[0] == "s" and items[1] in {"poweroff", "suspend", "ignore"}:
                    values["power_button_action"] = items[1]
            except ValueError:
                pass
        return values
    candidates = sorted((_etc() / "systemd/logind.conf.d").glob("*.conf"))
    lines = []
    for path in [_etc() / "systemd/logind.conf", *candidates]:
        lines += _shared.ini_read(path)
    active = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            active = stripped == "[Login]"
        if active:
            match = re.match(r"^\s*HandlePowerKey\s*=\s*(\w+)\s*(?:#.*)?$", line)
            if match:
                values["power_button_action"] = match.group(1)
    return values


def get_values(kind: str) -> dict[str, Any]:
    return {"keyboard": _keyboard_values, "region": _region_values, "energy": _energy_values}[kind]()


def _sway_reload(receipt: _shared.Receipt) -> None:
    selected = backends.select_backend()
    if not selected:
        raise ValueError("sway-session-unavailable")
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, ["reload"])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    receipt.commands.append({"argv": argv, "returncode": result.get("returncode")})
    try:
        responses = json.loads(result.get("stdout", ""))
    except (TypeError, json.JSONDecodeError):
        responses = []
    if not result.get("ok") or not isinstance(responses, list) or not responses or any(not isinstance(x, dict) or x.get("success") is not True for x in responses):
        raise ValueError("sway-reload-failed")


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
    path = _keyboard_path()
    lines = _shared.ini_read(path)
    begin = f"# settings-keyboard-{key}-begin\n"
    end = f"# settings-keyboard-{key}-end\n"
    if begin in lines and end in lines:
        first, last = lines.index(begin), lines.index(end)
        if last < first:
            raise ValueError("keyboard-override-invalid")
        del lines[first:last + 1]
    elif begin in lines or end in lines:
        raise ValueError("keyboard-override-invalid")
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines += [begin, f"input type:keyboard {key} {text}\n", end]
    receipt.replace(path, "".join(lines).encode())
    if os.geteuid() == 0 and _shared.home() == _shared.OWNER_HOME:
        owner = pwd.getpwnam(_shared.OWNER_USER)
        os.chown(path, owner.pw_uid, owner.pw_gid)


def sway_input_values() -> dict[str, Any]:
    values: dict[str, Any] = {key: None for key in _shared.FIELDS["input"]}
    selected = backends.select_backend()
    if not selected:
        return values
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, ["-t", "get_inputs"])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    try:
        devices = json.loads(result.get("stdout", "")) if result.get("ok") else []
        if not isinstance(devices, list): return values
    except (TypeError, ValueError):
        return values
    fields = (("accel_profile", "accel_profile"), ("left_handed", "left_handed"), ("disable_while_typing", "dwt"), ("natural_scroll", "natural_scroll"), ("tap_to_click", "tap"), ("pointer_speed", "accel_speed"))
    for field, raw_key in fields:
        seen = [d.get("libinput", {}).get(raw_key) for d in devices if isinstance(d, dict) and d.get("type") == "pointer" and isinstance(d.get("libinput"), dict)]
        seen = [x for x in seen if x is not None]
        if seen and all(x == seen[0] for x in seen):
            raw = seen[0]
            if field in {"left_handed", "disable_while_typing", "natural_scroll", "tap_to_click"}:
                if isinstance(raw, bool): values[field] = raw
                elif raw in {"enabled", "disabled"}: values[field] = raw == "enabled"
            elif field == "pointer_speed":
                if isinstance(raw, (int, float)) and not isinstance(raw, bool): values[field] = raw
            elif raw in {"flat", "adaptive"}: values[field] = raw
    return values


def _set_input(field: str, value: Any, receipt: _shared.Receipt) -> None:
    if field == "accel_profile":
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
    if not backends.select_backend() and os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") != "1":
        raise ValueError("sway-session-unavailable")
    path = _keyboard_path()
    lines = _shared.ini_read(path)
    begin, end = f"# settings-input-{field}-begin\n", f"# settings-input-{field}-end\n"
    if begin in lines and end in lines:
        start, stop = lines.index(begin), lines.index(end)
        if stop < start: raise ValueError("input-override-invalid")
        del lines[start:stop + 1]
    elif begin in lines or end in lines: raise ValueError("input-override-invalid")
    if lines and not lines[-1].endswith("\n"): lines[-1] += "\n"
    lines += [begin, *(f"input type:{kind} {key} {val}\n" for kind, key, val in settings), end]
    receipt.replace(path, "".join(lines).encode())
    if os.geteuid() == 0 and _shared.home() == _shared.OWNER_HOME:
        owner = pwd.getpwnam(_shared.OWNER_USER); os.chown(path, owner.pw_uid, owner.pw_gid)


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


def _restart_screen_idle(seconds: int, receipt: _shared.Receipt) -> str:
    launcher = str(Path(__file__).resolve().parent.parent / "caduceus-screen-idle")
    if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
        receipt.commands.extend([{"argv": ["pkill", "-u", _shared.OWNER_USER, "-x", "swayidle"], "dryRun": True},
                                 {"argv": [launcher], "dryRun": True, "spawn": seconds > 0}])
        return "dry-run"
    from agathodaimon.face import _shared as face
    try:
        environment, _ = face.owner_session_environment(require_sway=True, require_wayland=True)
    except face.FaceError as error:
        if error.signal in {"owner-sway-socket-unavailable", "owner-wayland-socket-unavailable"}:
            return "runner-starts-next-sway-session"
        raise
    uid = str(pwd.getpwnam(_shared.OWNER_USER).pw_uid)
    check = ["pgrep", "-u", uid, "-x", "swayidle"]
    stop = ["pkill", "-u", uid, "-x", "swayidle"]
    result = face.owner_run(stop, environment)
    receipt.commands.append({"argv": stop, "returncode": result.returncode})
    if result.returncode not in (0, 1): raise ValueError("swayidle-stop-failed")
    def observed() -> bool:
        result = face.owner_run(check, environment)
        if result.returncode not in (0, 1): raise ValueError("swayidle-observation-failed")
        return result.returncode == 0
    deadline = time.monotonic() + 3
    while observed():
        if time.monotonic() >= deadline: raise ValueError("swayidle-stop-timeout")
        time.sleep(0.05)
    if seconds:
        face.owner_spawn([launcher], environment)
        receipt.commands.append({"argv": [launcher], "spawned": True})
        deadline = time.monotonic() + 3
        while not observed():
            if time.monotonic() >= deadline: raise ValueError("swayidle-start-timeout")
            time.sleep(0.05)
    return "runner-restarted" if seconds else "runner-stopped"


def _set_energy(field: str, value: Any, receipt: _shared.Receipt) -> str | None:
    if field == "sleep_seconds":
        raise ValueError("energy-idle-consumer-absent")
    if field == "screen_off_seconds":
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 86400:
            raise ValueError("invalid:screen_off_seconds")
        path = _shared.home() / ".config/sway/screen-idle.json"
        payload = (json.dumps({"screen_off_seconds": value}) + "\n").encode()
        receipt.backup(path)
        receipt.replace(path, payload)
        if path.stat().st_mode & 0o777 != 0o644:
            os.chmod(path, 0o644)
            receipt.changed = True
        if os.geteuid() == 0 and _shared.home() == _shared.OWNER_HOME:
            owner = pwd.getpwnam(_shared.OWNER_USER)
            if (path.stat().st_uid, path.stat().st_gid) != (owner.pw_uid, owner.pw_gid):
                os.chown(path, owner.pw_uid, owner.pw_gid)
                receipt.changed = True
        return _restart_screen_idle(value, receipt)
    if not isinstance(value, str) or value not in {"poweroff", "suspend", "ignore"}:
        raise ValueError("invalid:power_button_action")
    path = _etc() / "systemd/logind.conf.d/60-appliance-power.conf"
    changed = receipt.replace(path, f"[Login]\nHandlePowerKey={value}\n".encode())
    argv = ["systemctl", "kill", "-s", "HUP", "systemd-logind"]
    if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
        if changed: receipt.commands.append({"argv": argv, "dryRun": True})
        if _energy_values()["power_button_action"] != value: raise ValueError("logind-power-key-shadowed")
        return
    if changed:
        ok, _ = _command(argv, receipt)
        if not ok:
            raise ValueError("logind-reload-failed")
    observed = _energy_values()["power_button_action"]
    if observed is None: raise ValueError("logind-power-key-observation-failed")
    if observed != value: raise ValueError("logind-power-key-shadowed")


def _set(kind: str, changes: dict[str, Any]) -> dict[str, Any]:
    if not changes:
        raise ValueError("no-fields-supplied")
    for field in changes:
        if field not in _shared.FIELDS[kind]:
            raise ValueError("unsupported:" + field)
        if kind == "energy" and field == "sleep_seconds":
            raise ValueError("energy-idle-consumer-absent")
    receipt = _shared.Receipt(kind, list(changes))
    reload_attempted = False
    screen_attempted = False
    note = None
    try:
        for field, value in changes.items():
            if kind == "energy" and field == "screen_off_seconds": screen_attempted = True
            result = {"keyboard": _set_keyboard, "region": _set_region, "energy": _set_energy}[kind](field, value, receipt)
            if isinstance(result, str): note = result
        if kind == "keyboard" and receipt.changed:
            if os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1":
                receipt.commands.append({"argv": ["swaymsg", "reload"], "dryRun": True})
            else:
                reload_attempted = True
                _sway_reload(receipt)
        answer = receipt.finish(True, receipt.changed)
        if note is not None:
            answer["note"] = note
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
            if kind == "energy" and mutated and "power_button_action" in changes and os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") != "1":
                ok, _ = _command(["systemctl", "kill", "--signal=HUP", "systemd-logind"], receipt)
                if not ok: raise ValueError("logind-rollback-reload-failed")
            if screen_attempted and any(cmd.get("argv", [None])[0] == "pkill" for cmd in receipt.commands) and os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") != "1":
                from agathodaimon.settings.energy.screen_idle import read_seconds
                _restart_screen_idle(read_seconds(_shared.home()), receipt)
            uncertain = False
        except Exception as rollback_error:
            signal = "rollback-failed:" + str(rollback_error) + ":" + signal
            runtime_attempted = screen_attempted and any(cmd.get("argv", [None])[0] == "pkill" and not cmd.get("dryRun") for cmd in receipt.commands)
            uncertain = mutated or runtime_attempted
        failure = receipt.finish(False, error=signal)
        raise _shared.ReceiptFailure(signal, failure["receipt"], uncertain) from error


def main(kind: str, argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    request = None
    if not args:
        try:
            request = read(known_fields=tuple(_shared.FIELDS[kind]) + ("args",))
            crossing = request.payload.get("args")
            if isinstance(crossing, list):
                args = crossing
            elif request.verb in {"read", "get", "state"}:
                args = ["get", "--json"]
            else:
                changes = {field: value for field, value in request.payload.items() if field in _shared.FIELDS[kind]}
                reply = _set(kind, changes)
                print(json.dumps(attach(reply, request), sort_keys=True))
                return 0
        except (EnvelopeError, ValueError, OSError) as error:
            reply = error.reply() if isinstance(error, _shared.ReceiptFailure) else {"ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": str(error)}
            print(json.dumps(attach(reply, request) if request else reply, sort_keys=True))
            return 1
    try:
        if args == ["get", "--json"]:
            reply = {"ok": True, "values": get_values(kind), "mutationPerformed": False}
        elif args and args[0] == "set":
            changes = {}
            i = 1
            while i < len(args):
                if i + 3 >= len(args) or args[i] != "--field" or args[i + 2] != "--value-json":
                    raise ValueError("cli-parse-failure")
                changes[args[i + 1]] = json.loads(args[i + 3])
                i += 4
            reply = _set(kind, changes)
        else:
            raise ValueError("cli-parse-failure")
        print(json.dumps(attach(reply, request) if request else reply, sort_keys=True))
        return 0
    except (ValueError, OSError, TypeError) as error:
        reply = error.reply() if isinstance(error, _shared.ReceiptFailure) else {"ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": str(error)}
        print(json.dumps(attach(reply, request) if request else reply, sort_keys=True))
        return 1

"""Caduceus desktop settings actuator.

The module deliberately keeps file edits surgical and command results authoritative.
It supports the direct launcher grammar used by the seven settings launchers.
"""
from __future__ import annotations

import configparser
import json
import os
import pwd
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence


FIELDS: dict[str, tuple[str, ...]] = {
    "display": ("resolution", "refresh_rate", "scale", "orientation", "brightness", "night_light", "hdr", "adaptive_sync", "overscan"),
    "appearance": ("color_scheme", "accent_color", "wallpaper", "icon_theme", "cursor_theme", "font", "cursor_size", "font_size", "text_scale"),
    "sound": ("output_device", "input_device", "volume", "input_volume", "muted", "card_profile", "test_tone"),
    "input": ("keyboard_layout", "keyboard_variant", "key_repeat", "repeat_delay_ms", "repeat_interval_ms", "natural_scroll", "tap_to_click", "pointer_speed", "accel_profile", "left_handed", "disable_while_typing", "scroll_factor"),
    "keyboard": ("keyboard_layout", "repeat_rate", "repeat_delay"),
    "region": ("locale", "measurement_units"),
    "energy": ("screen_off_seconds", "sleep_seconds", "power_button_action", "power_profile",
               "charge_limit", "battery_level", "battery_state", "lid_action"),
    "notifications": ("enabled", "do_not_disturb", "show_banners", "show_on_lock_screen", "sound_enabled"),
    "default-apps": ("browser", "mail", "calendar", "music", "video", "photos", "text_editor", "terminal", "file_manager"),
    "datetime": ("timezone", "ntp_enabled", "automatic_timezone", "time_format", "local_time"),
}

MIME_KEYS = {
    "browser": ("x-scheme-handler/http", "x-scheme-handler/https"),
    "mail": ("x-scheme-handler/mailto",),
    "calendar": ("text/calendar",),
    "music": ("audio/mpeg", "audio/ogg", "audio/*"),
    "video": ("video/mp4", "video/*"),
    "photos": ("image/jpeg", "image/png", "image/*"),
    "text_editor": ("text/plain",),
    "terminal": ("application/x-terminal",),
    "file_manager": ("inode/directory",),
}


OWNER_USER = "owner"
OWNER_HOME = Path("/home/owner")
OWNER_SESSION_TOOLS = {"pactl", "wpctl", "hyprctl", "dunstctl", "xdg-settings", "gsettings", "pw-play", "paplay"}
SWAY_SESSION_UNAVAILABLE = "sway-session-unavailable"
CURSOR_FIELDS = {"cursor_size", "cursor_theme"}


def home() -> Path:
    return Path(os.environ.get("CADUCEUS_SETTINGS_HOME", str(OWNER_HOME)))




def paths() -> dict[str, Path]:
    root = home() / ".config"
    return {
        "display": root / "hypr/monitors.conf",
        "appearance": root / "gtk-3.0/settings.ini",
        "notifications": root / "dunst/dunstrc",
        "default-apps": root / "mimeapps.list",
    }




def command(argv: Sequence[str]) -> tuple[bool, str, subprocess.CompletedProcess[str]]:
    result = run_command(argv)
    output = (result.stdout or "").strip()
    return result.returncode == 0, output, result


def scalar(value: Any, field: str) -> Any:
    if isinstance(value, dict):
        raise ValueError(f"invalid:{field}:type")
    return value


def boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"invalid:{field}:boolean-required")
    return value


def percentage(value: Any, field: str) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"invalid:{field}:percentage-required")
    text = str(value).strip()
    if text.endswith("%"):
        number = text[:-1]
    else:
        number = text
    try:
        amount = float(number)
    except ValueError as exc:
        raise ValueError(f"invalid:{field}:percentage-required") from exc
    if not 0 <= amount <= 100:
        raise ValueError(f"invalid:{field}:percentage-range")
    return f"{amount:g}%"










class ReceiptFailure(ValueError):
    def __init__(self, signal: str, receipt: dict[str, Any], mutation_performed: bool = False):
        super().__init__(signal)
        self.receipt = receipt
        self.mutation_performed = mutation_performed

    def reply(self) -> dict[str, Any]:
        return {"ok": False, "changed": False, "mutationPerformed": self.mutation_performed,
                "firstMissingSignal": str(self), "receipt": self.receipt}


def hypr_json(name: str) -> Any:
    ok, text, _ = command(["hyprctl", name, "-j"])
    if not ok:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def require(tool: str, field: str) -> None:
    if shutil.which(tool) is None: raise ValueError(f"unsupported:{field}")

TRANSFORMS = {"normal":0,"90":1,"180":2,"270":3,"flipped":4,"flipped90":5,"flipped180":6,"flipped270":7}
def monitor_orientation(value: Any) -> int:
    text=str(value).strip().lower().replace("°","")
    text={"0":"normal","1":"90","2":"180","3":"270","4":"flipped","5":"flipped90","6":"flipped180","7":"flipped270","flipped-90":"flipped90","flipped-180":"flipped180","flipped-270":"flipped270"}.get(text,text)
    if text not in TRANSFORMS: raise ValueError("invalid:orientation")
    return TRANSFORMS[text]



def hypr_lua_lines(path: Path) -> list[str]:
    # Strip Lua comments, not comment-like text inside quoted strings.
    tokens = r'''--\[(=*)\[.*?\]\1\]|--[^\n]*|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*' '''.strip()
    text = re.sub(tokens, lambda match: (" " + "\n" * match[0].count("\n")) if match[0].startswith("--") else match[0],
                  "".join(ini_read(path)), flags=re.DOTALL)
    return text.splitlines()


def _hypr_cursor_size() -> int | None:
    directory = home() / ".config/hypr"
    lua = re.compile(r'''\s*hl\.env\(\s*(["'])XCURSOR_SIZE\1\s*,\s*(["'])([0-9]{1,9})\2\s*\)\s*;?\s*''')
    env = re.compile(r"\s*env\s*=\s*XCURSOR_SIZE\s*,\s*([0-9]{1,9})\s*(?:#.*)?")
    for lines, pattern, group in ((hypr_lua_lines(directory / "hyprland.lua"), lua, 3),
                                  (ini_read(directory / "envs.conf"), env, 1)):
        for line in reversed(lines):
            match = pattern.fullmatch(line.rstrip("\r\n"))
            if match and int(match[group]) > 0:
                return int(match[group])
    return None


def get_values(kind: str) -> dict[str, Any]:
    values: dict[str, Any] = {field: None for field in FIELDS[kind]}
    p = paths()
    if kind == "display":
        monitors = hypr_json("monitors")
        monitor = monitors[0] if isinstance(monitors, list) and monitors else {}
        if monitor:
            values.update(resolution=f"{monitor.get('width')}x{monitor.get('height')}", refresh_rate=monitor.get("refreshRate"), scale=monitor.get("scale"), orientation=monitor.get("transform"))
        else:
            for line in ini_read(p[kind]):
                match = re.match(r"^\s*monitor\s*=\s*(.*?)(?:\r?\n)?$", line)
                if not match or line.lstrip().startswith("#"):
                    continue
                parts = [part.strip() for part in match.group(1).split(",")]
                if len(parts) < 4 or any(part.lower() == "disable" for part in parts):
                    continue
                mode = parts[1].split("@", 1)
                values["resolution"] = mode[0]
                values["refresh_rate"] = mode[1] if len(mode) == 2 else None
                values["scale"] = parts[3]
                transform = 0
                for index in range(4, len(parts) - 1):
                    if parts[index] == "transform":
                        transform = int(parts[index + 1])
                        break
                values["orientation"] = next((name for name, number in TRANSFORMS.items() if number == transform), "normal")
                break
        ok, text, _ = command(["brightnessctl", "g"])
        values["brightness"] = text if ok else None
    elif kind == "appearance":
        import ast
        for field, key in (("color_scheme", "color-scheme"), ("icon_theme", "icon-theme"),
                           ("cursor_theme", "cursor-theme"), ("font", "font-name")):
            good, text, _ = command(["gsettings", "get", "org.gnome.desktop.interface", key])
            if good:
                try:
                    value = ast.literal_eval(text)
                    if isinstance(value, str):
                        values[field] = ("dark" if value == "prefer-dark" else "light") if field == "color_scheme" else value
                except (ValueError, SyntaxError): pass
        for field, key in (("cursor_size", "cursor-size"), ("text_scale", "text-scaling-factor")):
            good, text, _ = command(["gsettings", "get", "org.gnome.desktop.interface", key])
            if good:
                try: values[field] = int(text) if field == "cursor_size" else float(text)
                except ValueError: pass
        from agathodaimon.settings import _parity
        if _parity.backends.select_backend():
            cursor = _parity.sway_cursor_override()
            if cursor is not None: values["cursor_theme"], values["cursor_size"] = cursor
        else:
            cursor_size = _hypr_cursor_size()
            if cursor_size is not None:
                values["cursor_size"] = cursor_size
        if isinstance(values["font"], str):
            match = re.search(r"\s+(\d+(?:\.\d+)?)$", values["font"])
            if match: values["font_size"] = float(match.group(1))
    elif kind == "sound":
        ok, text, _ = command(["pactl", "info"])
        if ok:
            for line in text.splitlines():
                if line.startswith("Default Sink:"): values["output_device"] = line.split(":", 1)[1].strip()
                if line.startswith("Default Source:"): values["input_device"] = line.split(":", 1)[1].strip()
        for field, sub, target in (("volume", "get-sink-volume", "@DEFAULT_SINK@"), ("input_volume", "get-source-volume", "@DEFAULT_SOURCE@")):
            good, out, _ = command(["pactl", sub, target])
            values[field] = out.split("/")[1].strip() if good and "/" in out else (out or None if good else None)
        good, out, _ = command(["pactl", "get-sink-mute", "@DEFAULT_SINK@"]) ; values["muted"] = ("yes" in out.lower()) if good else None
        _, values["card_profile"] = _default_card()
    elif kind == "input":
        from agathodaimon.settings.input._acts import read_values
        return read_values()["values"]
    elif kind == "notifications":
        lines = ini_read(p[kind]); values["enabled"] = p[kind].is_file()
        good, out, _ = command(["dunstctl", "is-paused"]); values["do_not_disturb"] = ("true" in out.lower()) if good else None
        for field in FIELDS[kind][2:]: values[field] = ini_get(lines, field)
    elif kind == "default-apps":
        lines = ini_read(p[kind]); mapping = {}; active = False
        for line in lines:
            if line.strip().startswith("["): active = line.strip() == "[Default Applications]"
            elif active and "=" in line and not line.lstrip().startswith("#"):
                key, val = line.split("=", 1); mapping[key.strip()] = val.strip().rstrip(";")
        for field, mime_types in MIME_KEYS.items(): values[field] = next((mapping.get(mime) for mime in mime_types if mime in mapping), None)
    elif kind == "datetime":
        from agathodaimon.settings.datetime._acts import read_values
        return read_values()
    return {key: values.get(key) for key in FIELDS[kind]}




def monitor_edit(receipt: Receipt, field: str, value: Any) -> None:
    path=paths()["display"]; require("hyprctl",field); lines=ini_read(path); found=None
    for i,line in enumerate(lines):
        m=re.match(r"^(\s*monitor\s*=\s*)(.*?)(\r?\n)?$",line)
        if not m or line.lstrip().startswith("#"): continue
        parts=[x.strip() for x in m.group(2).split(",")]
        if len(parts)>=4 and not any(x.lower()=="disable" for x in parts): found=(i,m,parts); break
    if found is None: raise ValueError("unsupported:"+field)
    i,m,parts=found
    if field=="resolution":
        q=parts[1].split("@",1); parts[1]=str(value)+("@"+q[1] if len(q)==2 else "")
    elif field=="refresh_rate": parts[1]=parts[1].split("@",1)[0]+"@"+str(value)
    elif field=="scale": parts[3]=str(value)
    elif field=="orientation":
        val=str(monitor_orientation(value))
        for j in range(4,len(parts)-1):
            if parts[j]=="transform": parts[j+1]=val; break
        else: parts.extend(["transform",val])
    else: raise ValueError("unsupported:"+field)
    spec=", ".join(parts); argv=["hyprctl","keyword","monitor",spec]; good,_,result=command(argv)
    receipt.commands.append({"argv":argv,"returncode":result.returncode})
    if not good: raise ValueError("command-failed:"+field)
    lines[i]=m.group(1)+spec+(m.group(3) or ""); receipt.replace(path,"".join(lines).encode())

def set_value(kind: str, field: str, value: Any, receipt: Receipt) -> None:
    if field not in FIELDS[kind]: raise ValueError("unsupported:"+field)
    if kind == "display":
        if field in {"hdr", "adaptive_sync", "overscan"}: raise ValueError("unsupported:" + field)
        if field == "night_light": raise ValueError("unsupported:night_light")
        if field == "brightness":
            if shutil.which("brightnessctl") is None: raise ValueError("unsupported:brightness")
            cmd=["brightnessctl","set",percentage(value,field)]; good,_,result=command(cmd); receipt.commands.append({"argv":cmd,"returncode":result.returncode})
            if not good: raise ValueError("command-failed:brightness")
        else: monitor_edit(receipt,field,scalar(value,field))
        return
    if kind == "appearance":
        if field in {"cursor_size", "font_size", "text_scale"}:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError("invalid:" + field)
            if field == "cursor_size":
                if int(value) != value or not 8 <= value <= 256: raise ValueError("invalid:cursor_size")
                require("gsettings", field)
                import ast
                from agathodaimon.settings import _parity
                dry_run = os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1"
                theme = get_values("appearance").get("cursor_theme")
                if not isinstance(theme, str) or not theme:
                    good_theme, raw_theme, _ = command(["gsettings", "get", "org.gnome.desktop.interface", "cursor-theme"])
                    try:
                        theme = ast.literal_eval(raw_theme) if good_theme else None
                    except (SyntaxError, ValueError):
                        theme = None
                if not isinstance(theme, str) or not theme:
                    theme = "default"
                good_old, old_size, _ = command(["gsettings", "get", "org.gnome.desktop.interface", "cursor-size"])
                if not dry_run and (not good_old or not old_size.isdigit()):
                    raise ValueError("cursor-size-observation-failed")
                cmd = ["gsettings", "set", "org.gnome.desktop.interface", "cursor-size", str(int(value))]
                if dry_run:
                    receipt.commands.append({"argv": cmd, "dryRun": True})
                else:
                    good, _, result = command(cmd)
                    receipt.commands.append({"argv": cmd, "returncode": result.returncode})
                    if not good: raise ValueError("command-failed:cursor_size")
                try:
                    _parity.set_sway_cursor(theme, int(value), receipt)
                except Exception as error:
                    receipt.restore_backups()
                    if not dry_run:
                        rollback = ["gsettings", "set", "org.gnome.desktop.interface", "cursor-size", old_size]
                        restored, _, result = command(rollback)
                        receipt.commands.append({"argv": rollback, "returncode": result.returncode})
                        if not restored: raise ValueError("cursor-gsettings-rollback-failed") from error
                    raise
                receipt.changed = True
                return
            elif field == "text_scale":
                if not 0.5 <= value <= 3: raise ValueError("invalid:text_scale")
                gkey, gval = "text-scaling-factor", str(float(value))
            else:
                if not 6 <= value <= 72: raise ValueError("invalid:font_size")
                font = get_values("appearance").get("font")
                if not font or not re.search(r"\s+\d+(?:\.\d+)?$", font): raise ValueError("unsupported:font_size")
                gkey, gval = "font-name", re.sub(r"\s+\d+(?:\.\d+)?$", " " + str(value), font)
            require("gsettings", field)
            cmd = ["gsettings", "set", "org.gnome.desktop.interface", gkey, gval]
            good, _, result = command(cmd); receipt.commands.append({"argv": cmd, "returncode": result.returncode})
            if not good: raise ValueError("command-failed:" + field)
            receipt.changed = True
            return
        if field in ("accent_color","wallpaper"): raise ValueError("unsupported:"+field)
        if field == "color_scheme":
            if isinstance(value,bool): val="1" if value else "0"
            elif isinstance(value,str) and value.lower() in ("dark","light"): val="1" if value.lower()=="dark" else "0"
            else: raise ValueError("invalid:color_scheme:type")
        else: val=str(scalar(value,field))
        gkey={"color_scheme":"color-scheme","icon_theme":"icon-theme","cursor_theme":"cursor-theme","font":"font-name"}[field]; gval=("prefer-dark" if val=="1" else "prefer-light") if field=="color_scheme" else val
        require("gsettings", field)
        from agathodaimon.settings import _parity
        set_cursor = field == "cursor_theme"
        if set_cursor:
            import ast
            good_old, old_theme, _ = command(["gsettings", "get", "org.gnome.desktop.interface", "cursor-theme"])
            try:
                previous_theme = ast.literal_eval(old_theme) if good_old else None
            except (SyntaxError, ValueError):
                previous_theme = None
            size = get_values("appearance").get("cursor_size")
            if not isinstance(previous_theme, str) or not isinstance(size, int):
                raise ValueError("cursor-theme-observation-failed")
        cmd=["gsettings","set","org.gnome.desktop.interface",gkey,gval]; good,_,result=command(cmd); receipt.commands.append({"argv":cmd,"returncode":result.returncode})
        if not good: raise ValueError("command-failed:"+field)
        if set_cursor:
            try:
                _parity.set_sway_cursor(gval, size, receipt)
            except Exception as error:
                receipt.restore_backups()
                rollback = ["gsettings", "set", "org.gnome.desktop.interface", "cursor-theme", previous_theme]
                restored, _, result = command(rollback)
                receipt.commands.append({"argv": rollback, "returncode": result.returncode})
                if not restored: raise ValueError("cursor-gsettings-rollback-failed") from error
                raise
        receipt.changed = True
        return
    if kind == "sound":
        if field == "test_tone":
            if value is not True: raise ValueError("invalid:test_tone")
            sounds = [Path("/usr/share/sounds/freedesktop/stereo/audio-test-signal.oga"), Path("/usr/share/sounds/freedesktop/stereo/audio-volume-change.oga")]
            sample = next((path for path in sounds if path.is_file()), None)
            player = shutil.which("pw-play") or shutil.which("paplay")
            if sample is None or player is None: raise ValueError("unsupported:test_tone")
            cmd = [Path(player).name, str(sample)]
            good, _, result = command(cmd); receipt.commands.append({"argv": cmd, "returncode": result.returncode})
            if not good: raise ValueError("command-failed:test_tone")
            receipt.changed = True
            return
        if field == "card_profile":
            card, _ = _default_card()
            if not card: raise ValueError("unsupported:card_profile")
            if not isinstance(value, str) or not value or len(value) > 256 or any(ord(c) < 32 for c in value): raise ValueError("invalid:card_profile")
            cmd = ["pactl", "set-card-profile", card, value]
            good, _, result = command(cmd); receipt.commands.append({"argv": cmd, "returncode": result.returncode})
            if not good: raise ValueError("command-failed:card_profile")
            receipt.changed = True
            return
        require("pactl",field); val=percentage(value,field) if field in ("volume","input_volume") else ("1" if boolean(value,field) else "0") if field=="muted" else str(scalar(value,field))
        commands={"volume":["pactl","set-sink-volume","@DEFAULT_SINK@",val],"input_volume":["pactl","set-source-volume","@DEFAULT_SOURCE@",val],"muted":["pactl","set-sink-mute","@DEFAULT_SINK@",val],"output_device":["pactl","set-default-sink",val],"input_device":["pactl","set-default-source",val]}; cmd=commands[field]; good,_,result=command(cmd); receipt.commands.append({"argv":cmd,"returncode":result.returncode})
        if not good: raise ValueError("command-failed:"+field)
        return
    if kind == "notifications":
        if field != "do_not_disturb": raise ValueError("unsupported:"+field)
        require("dunstctl",field); val="true" if boolean(value,field) else "false"; cmd=["dunstctl","set-paused",val]; good,_,result=command(cmd); receipt.commands.append({"argv":cmd,"returncode":result.returncode})
        if not good: raise ValueError("command-failed:do_not_disturb")
        return
    if kind == "default-apps":
        app=str(scalar(value,field)); path=paths()[kind]
        if field=="browser":
            require("xdg-settings",field)
            for scheme in ("http","https"):
                cmd=["xdg-settings","set","default-url-scheme-handler",scheme,app]; good,_,result=command(cmd); receipt.commands.append({"argv":cmd,"returncode":result.returncode})
                if not good: raise ValueError("command-failed:browser")
        lines=ini_read(path); lines="".join(lines).splitlines(keepends=True)
        try: start=next(i for i,line in enumerate(lines) if line.strip()=="[Default Applications]")
        except StopIteration:
            if lines and not lines[-1].endswith("\n"): lines[-1]+="\n"
            lines.extend(["\n","[Default Applications]\n"]); start=len(lines)-1
        end=start+1
        while end<len(lines) and not lines[end].lstrip().startswith("["): end+=1
        section=lines[start:end]
        for i,line in enumerate(section):
            for mime in MIME_KEYS[field]:
                if line.startswith(mime+"="): section[i]=f"{mime}={app};\n"
        present={line.split("=",1)[0] for line in section if "=" in line}
        for mime in MIME_KEYS[field]:
            if mime not in present: section.append(f"{mime}={app};\n")
        lines[start:end]=section; receipt.replace(path,"".join(lines).encode()); return
    raise ValueError("unsupported:"+field)


from agathodaimon.settings._receipt import Receipt as _SettingsReceipt


class Receipt(_SettingsReceipt):
    def __init__(self, kind: str, fields: list[str]) -> None:
        # Refuse the whole non-Sway cursor request before allocating a legacy
        # settings receipt or changing another field in a mixed request.
        if kind == "appearance" and CURSOR_FIELDS.intersection(fields):
            from agathodaimon.settings import _parity
            if not _parity.backends.select_backend():
                raise ValueError("unsupported:" + SWAY_SESSION_UNAVAILABLE)
        super().__init__(kind, fields)

    def restore_backups(self) -> None:
        from agathodaimon.settings import _sway_overrides
        target = _sway_overrides.path()
        if target in self._saved:
            metadata = next(item for item in self.backups if item["path"] == str(target))
            _sway_overrides.restore_backup(target, self._saved[target], metadata)
            del self._saved[target]
        super().restore_backups()


from agathodaimon.settings._ini import ini_read, ini_get, ini_set, set_file_value
from agathodaimon.settings._cmd import run_command, owner_session_command, _default_card

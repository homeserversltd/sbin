"""Caduceus desktop settings actuator.

The module deliberately keeps file edits surgical and command results authoritative.
It supports the direct launcher grammar used by the seven settings launchers.
"""
from __future__ import annotations

import argparse
import configparser
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable, Sequence
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _options

FIELDS: dict[str, tuple[str, ...]] = {
    "display": ("resolution", "refresh_rate", "scale", "orientation", "brightness", "night_light", "hdr", "adaptive_sync", "overscan"),
    "appearance": ("color_scheme", "accent_color", "wallpaper", "icon_theme", "cursor_theme", "font", "cursor_size", "font_size", "text_scale"),
    "sound": ("output_device", "input_device", "volume", "input_volume", "muted", "card_profile", "test_tone"),
    "input": ("keyboard_layout", "keyboard_variant", "key_repeat", "repeat_delay_ms", "repeat_interval_ms", "natural_scroll", "tap_to_click", "pointer_speed", "accel_profile", "left_handed", "disable_while_typing"),
    "keyboard": ("keyboard_layout", "repeat_rate", "repeat_delay"),
    "region": ("locale", "measurement_units"),
    "energy": ("screen_off_seconds", "sleep_seconds", "power_button_action"),
    "notifications": ("enabled", "do_not_disturb", "show_banners", "show_on_lock_screen", "sound_enabled"),
    "default-apps": ("browser", "mail", "calendar", "music", "video", "photos", "text_editor", "terminal", "file_manager"),
    "datetime": ("timezone", "ntp_enabled", "automatic_timezone", "date_format", "time_format"),
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


def home() -> Path:
    return Path(os.environ.get("CADUCEUS_SETTINGS_HOME", str(OWNER_HOME)))




def paths() -> dict[str, Path]:
    root = home() / ".config"
    return {
        "display": root / "hypr/monitors.conf",
        "input": root / "hypr/input.conf",
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
        lines = ini_read(p[kind]); dark = ini_get(lines, "gtk-application-prefer-dark-theme", "Settings")
        values.update(color_scheme=("dark" if dark == "1" else "light" if dark == "0" else None), icon_theme=ini_get(lines, "gtk-icon-theme-name", "Settings"), cursor_theme=ini_get(lines, "gtk-cursor-theme-name", "Settings"), font=ini_get(lines, "gtk-font-name", "Settings"))
        for field, key in (("cursor_size", "cursor-size"), ("text_scale", "text-scaling-factor")):
            good, text, _ = command(["gsettings", "get", "org.gnome.desktop.interface", key])
            if good:
                try: values[field] = int(text) if field == "cursor_size" else float(text)
                except ValueError: pass
        from agathodaimon.settings import _parity
        if _parity.backends.select_backend():
            cursor = _parity.sway_cursor_override()
            if cursor is not None: values["cursor_size"] = cursor[1]
        good, text, _ = command(["gsettings", "get", "org.gnome.desktop.interface", "font-name"])
        if good:
            import ast
            try:
                font = ast.literal_eval(text)
                if isinstance(font, str): values["font"] = font
            except (ValueError, SyntaxError): pass
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
        devices = hypr_json("devices") or {}
        keyboard = (devices.get("keyboards") or [{}])[0]
        lines = ini_read(p[kind])
        block = _brace_block(lines, "input")
        values["keyboard_layout"] = keyboard.get("active_keymap") or keyboard.get("xkb_layout")
        values["keyboard_variant"] = keyboard.get("xkb_variant")
        if block is not None:
            values["keyboard_layout"] = values["keyboard_layout"] or _brace_get(lines, block, "kb_layout")
            values["keyboard_variant"] = values["keyboard_variant"] or _brace_get(lines, block, "kb_variant")
            for field, key, nested in (("key_repeat", "repeat_rate", None), ("repeat_delay_ms", "repeat_delay", None), ("natural_scroll", "natural_scroll", "touchpad"), ("tap_to_click", "tap-to-click", "touchpad"), ("pointer_speed", "sensitivity", None), ("scroll_factor", "scroll_factor", None)):
                values[field] = _brace_get(lines, block, key, nested)
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
        good, out, _ = command(["timedatectl", "show", "-p", "Timezone", "-p", "NTP"])
        if good:
            properties = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
            values["timezone"] = properties.get("Timezone")
            values["ntp_enabled"] = properties["NTP"] == "yes" if "NTP" in properties else None
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

def _brace_block(lines: list[str], name: str, start: int = 0) -> tuple[int, int] | None:
    depth = 0; begin = None
    for i in range(start, len(lines)):
        code = lines[i].split("#", 1)[0]
        if begin is None:
            if re.search(r"^\s*" + re.escape(name) + r"\s*\{", code):
                begin, depth = i, code.count("{") - code.count("}")
        else:
            depth += code.count("{") - code.count("}")
            if depth <= 0: return begin, i
    return (begin, begin) if begin is not None and depth <= 0 else None

def _brace_set(lines: list[str], bounds: tuple[int,int], keys: tuple[str,...], value: str, nested: str | None = None) -> bool:
    first,last = bounds
    if nested:
        child = _brace_block(lines, nested, first+1)
        if child is None or child[1] > last: return False
        first,last = child
    for i in range(first+1,last):
        m=re.match(r"^(\s*)([-\w]+)(\s*=\s*)(.*?)(\r?\n)?$",lines[i])
        if m and m.group(2) in keys:
            lines[i]=f"{m.group(1)}{m.group(2)}{m.group(3)}{value}{m.group(5) or ''}"
            return True
    indent=re.match(r"^(\s*)",lines[last]).group(1)+"    "
    nl="\r\n" if lines[last].endswith("\r\n") else "\n"
    lines.insert(last,f"{indent}{keys[0]} = {value}{nl}")
    return True

def _brace_get(lines: list[str], bounds: tuple[int,int], key: str, nested: str | None = None) -> str | None:
    first,last=bounds
    if nested:
        child=_brace_block(lines,nested,first+1)
        if child is None or child[1] > last: return None
        first,last=child
    for line in lines[first+1:last]:
        code=line.split("#",1)[0]
        match=re.match(r"^\s*"+re.escape(key)+r"\s*=\s*(.*?)\s*$",code)
        if match: return match.group(1).strip()
    return None

def hypr_set(receipt: Receipt, field: str, value: str) -> None:
    require("hyprctl", field); path=paths()["input"]; original=path.read_bytes() if path.exists() else b""
    lines=ini_read(path); block=_brace_block(lines,"input")
    keymap={"keyboard_layout":("kb_layout",),"keyboard_variant":("kb_variant",),"key_repeat":("repeat_rate",),"repeat_delay_ms":("repeat_delay",),"pointer_speed":("sensitivity",),"scroll_factor":("scroll_factor",)}
    if block is None: raise ValueError("unsupported:"+field)
    if field in keymap: ok=_brace_set(lines,block,keymap[field],value)
    elif field == "natural_scroll": ok=_brace_set(lines,block,("natural_scroll",),value,"touchpad")
    elif field == "tap_to_click": ok=_brace_set(lines,block,("tap-to-click",),value,"touchpad")
    else: raise ValueError("unsupported:"+field)
    if not ok: raise ValueError("unsupported:"+field)
    if not receipt.replace(path,"".join(lines).encode()): return
    argv=["hyprctl","reload"]; good,_,result=command(argv); receipt.commands.append({"argv":argv,"returncode":result.returncode})
    if not good:
        receipt.rollback(path,original); receipt.commands.append({"argv":["rollback",str(path)],"returncode":0})
        raise ValueError("command-failed:"+field)

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
                from agathodaimon.settings import _parity
                if _parity.backends.select_backend():
                    import ast
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
                gkey, gval = "cursor-size", str(int(value))
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
        key={"color_scheme":"gtk-application-prefer-dark-theme","icon_theme":"gtk-icon-theme-name","cursor_theme":"gtk-cursor-theme-name","font":"gtk-font-name"}[field]
        if field == "color_scheme":
            if isinstance(value,bool): val="1" if value else "0"
            elif isinstance(value,str) and value.lower() in ("dark","light"): val="1" if value.lower()=="dark" else "0"
            else: raise ValueError("invalid:color_scheme:type")
        else: val=str(scalar(value,field))
        gkey={"color_scheme":"color-scheme","icon_theme":"icon-theme","cursor_theme":"cursor-theme","font":"font-name"}[field]; gval=("prefer-dark" if val=="1" else "prefer-light") if field=="color_scheme" else val
        if shutil.which("gsettings"):
            cmd=["gsettings","set","org.gnome.desktop.interface",gkey,gval]; good,_,result=command(cmd); receipt.commands.append({"argv":cmd,"returncode":result.returncode})
            if not good: raise ValueError("command-failed:"+field)
        set_file_value(receipt,paths()[kind],key,val,"Settings"); return
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
    if kind == "input":
        if field == "repeat_interval_ms": raise ValueError("unsupported:repeat_interval_ms")
        val=("true" if boolean(value,field) else "false") if field in ("natural_scroll","tap_to_click") else str(scalar(value,field)); hypr_set(receipt,field,val); return
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
    if kind == "datetime":
        if field not in ("timezone","ntp_enabled"): raise ValueError("unsupported:"+field)
        require("timedatectl",field); val=("yes" if boolean(value,field) else "no") if field=="ntp_enabled" else str(scalar(value,field)); argv=["timedatectl","set-ntp",val] if field=="ntp_enabled" else ["timedatectl","set-timezone",val]; good,_,result=command(argv); receipt.commands.append({"argv":argv,"returncode":result.returncode})
        if not good: raise ValueError("privilege:"+field)
        return
    raise ValueError("unsupported:"+field)


def emit(data: dict[str, Any], code: int) -> int:
    print(json.dumps(data, sort_keys=True)); return code


class StrictParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError("cli-parse-failure")


def parser() -> argparse.ArgumentParser:
    p = StrictParser(add_help=False); p.add_argument("kind", choices=sorted(FIELDS)); sub = p.add_subparsers(dest="op", required=True, parser_class=StrictParser)
    g = sub.add_parser("get", add_help=False); g.add_argument("--json", action="store_true", required=True)
    s = sub.add_parser("set", add_help=False); s.add_argument("--field", action="append", required=True); s.add_argument("--value-json", action="append", required=True)
    return p


def family_main(kind: str, argv: Sequence[str] | None = None) -> int:
    """Adapt the fixed crossing's args envelope to the family CLI grammar."""
    original = list(sys.argv[1:] if argv is None else argv)
    if original:
        return main([kind, *original])
    try:
        request = read(known_fields=FIELDS[kind] + ("args",))
        args = request.payload.get("args")
        if isinstance(args, list):
            return main([kind, *args])
        changes = {field: value for field, value in request.payload.items() if field in FIELDS[kind]}
        if request.verb in {"read", "get", "state"} or (request.verb in {kind, "settings"} and not changes):
            return emit(attach({"ok": True, "values": get_values(kind), **({"options": _options.options(kind)} if kind in {"appearance", "sound", "default-apps", "datetime"} else {}), "mutationPerformed": False}, request), 0)
        if not changes:
            return emit(attach({"ok": False, "firstMissingSignal": "no-fields-supplied", "mutationPerformed": False}, request), 1)
        receipt = Receipt(kind, list(changes))
        try:
            for field, value in changes.items():
                set_value(kind, field, value, receipt)
            return emit(attach(receipt.finish(True, receipt.changed), request), 0)
        except Exception as error:
            receipt.restore_backups()
            return emit(attach(receipt.finish(False, False, str(error)), request), 1)
    except (EnvelopeError, ValueError) as error:
        return emit({"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}, 1)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # cli.py invokes a slash target with an empty argv and delivers the staff
    # envelope on stdin.  Keep the ordinary command-line grammar unchanged.
    if not argv:
        try:
            request = read(known_fields=tuple(field for fields in FIELDS.values() for field in fields))
            transition = request.transition if isinstance(request.transition, str) else ""
            parts = [part for part in re.split(r"[./:]", transition) if part]
            kind = next((name for name in FIELDS if name in parts or (name == "default-apps" and "default-apps" in transition)), None)
            if kind is None:
                raise ValueError("unknown settings family")
            operation = request.verb
            if operation == kind or operation in {"settings", "exousia"}:
                operation = "set" if any(k in FIELDS[kind] for k in request.payload) else "read"
            if operation in {"read", "get", "state"}:
                return emit(attach({"ok": True, "values": get_values(kind), **({"options": _options.options(kind)} if kind in {"appearance", "sound", "default-apps", "datetime"} else {})}, request), 0)
            if operation not in {"set", "change", "apply", "mutate"}:
                return emit(attach({"ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": f"unsupported-operation:{operation}"}, request), 1)
            changes = {field: value for field, value in request.payload.items() if field in FIELDS[kind]}
            if not changes:
                return emit(attach({"ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": "no-fields-supplied"}, request), 1)
            receipt = Receipt(kind, list(changes))
            try:
                for field, value in changes.items():
                    set_value(kind, field, value, receipt)
                return emit(attach(receipt.finish(True, receipt.changed), request), 0)
            except Exception as exc:
                return emit(attach(receipt.finish(False, False, str(exc)), request), 1)
        except (EnvelopeError, ValueError) as exc:
            return emit({"ok": False, "firstMissingSignal": str(exc), "mutationPerformed": False}, 1)
    try:
        args = parser().parse_args(argv)
        if args.op == "get": return emit({"ok": True, "values": get_values(args.kind), **({"options": _options.options(args.kind)} if args.kind in {"appearance", "sound", "default-apps", "datetime"} else {})}, 0)
        if len(args.field) != len(args.value_json): return emit({"ok": False, "firstMissingSignal": "field-value-count-mismatch"}, 1)
        receipt = Receipt(args.kind, list(args.field))
        try:
            for field, raw in zip(args.field, args.value_json): set_value(args.kind, field, json.loads(raw), receipt)
            return emit(receipt.finish(True, receipt.changed), 0)
        except Exception as exc:
            receipt.restore_backups()
            return emit(receipt.finish(False, False, str(exc)), 1)
    except SystemExit:
        return emit({"ok": False, "firstMissingSignal": "cli-parse-failure"}, 2)
    except Exception as exc:
        return emit({"ok": False, "firstMissingSignal": str(exc)}, 1)


from agathodaimon.settings._receipt import Receipt
from agathodaimon.settings._ini import ini_read, ini_get, ini_set, set_file_value
from agathodaimon.settings._cmd import run_command, owner_session_command, _default_card


if __name__ == "__main__": raise SystemExit(main())

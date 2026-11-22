"""Caduceus-backed keyboard shortcuts with a read-only fallback."""
from __future__ import annotations

import glob
import json
import os
import re
import threading
from pathlib import Path

try:
    from ._common import _read, _page, _group, _request, _receipt_ok
except ImportError:
    import importlib.util as _importlib_util
    _common_spec = _importlib_util.spec_from_file_location(
        "_common", __file__.replace(__file__.split("/")[-1], "_common.py")
    )
    _common_module = _importlib_util.module_from_spec(_common_spec)
    import sys as _sys
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _read, _page, _group, _request, _receipt_ok

PLUG = {"id": "shortcuts", "title": "Shortcuts", "icon": "preferences-desktop-keyboard-shortcuts-symbolic", "order": 70, "parent": None}

_MEDIA_KEYS = {
    "XF86AudioRaiseVolume": "Volume Up", "XF86AudioLowerVolume": "Volume Down",
    "XF86AudioMute": "Mute", "XF86AudioMicMute": "Microphone Mute",
    "XF86AudioPlay": "Play", "XF86AudioPause": "Pause", "XF86AudioStop": "Stop",
    "XF86AudioNext": "Next Track", "XF86AudioPrev": "Previous Track",
    "XF86AudioForward": "Fast Forward", "XF86AudioRewind": "Rewind",
    "XF86AudioMedia": "Media", "XF86AudioPlayPause": "Play/Pause",
}
_KEY_NAMES = {
    "mod4": "Super", "super": "Super", "mod1": "Alt", "alt": "Alt",
    "control": "Ctrl", "ctrl": "Ctrl", "mod5": "AltGr", "shift": "Shift",
    "return": "Enter", "kp_enter": "Keypad Enter", "space": "Space", "tab": "Tab",
    "iso_left_tab": "Back Tab", "escape": "Esc", "delete": "Delete", "print": "Print Screen",
    "up": "Up", "down": "Down", "left": "Left", "right": "Right",
    "page_up": "Page Up", "page_down": "Page Down", "button1": "Left Mouse Button",
    "mouse:272": "Left Mouse Button", "mouse:273": "Right Mouse Button",
    "mouse:274": "Middle Mouse Button",
    **{key.lower(): label for key, label in _MEDIA_KEYS.items()},
    "xf86monbrightnessup": "Brightness Up", "xf86monbrightnessdown": "Brightness Down",
    "xf86kbdbrightnessup": "Keyboard Brightness Up", "xf86kbdbrightnessdown": "Keyboard Brightness Down",
    "xf86touchpadtoggle": "Toggle Touchpad", "xf86wlan": "Wi-Fi",
    "xf86calculator": "Calculator", "xf86poweroff": "Power Off", "xf86sleep": "Sleep",
}


def _key_name(part: str) -> str:
    lower = part.lower()
    if lower in _KEY_NAMES:
        return _KEY_NAMES[lower]
    if lower.startswith("xf86") and len(part) > 4:
        return re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", " ", part[4:])
    return part.upper() if len(part) == 1 and part.isalpha() else part


def _key_parts(keys: str) -> list[str]:
    return [_key_name(part.strip()) for part in keys.split("+") if part.strip()]


def _last_key(keys: str) -> str:
    return keys.rsplit("+", 1)[-1].strip()


def human_keys(keys: str) -> str:
    return "+".join(_key_parts(keys))


def fold_bindings(bindings):
    """Group named actions in door order without altering their wire values."""
    groups = []
    named = {}
    for binding in bindings:
        name = binding.get("name")
        name = name if isinstance(name, str) and name.strip() else ""
        if name and name in named:
            named[name].append(binding)
        else:
            group = [binding]
            groups.append(group)
            if name:
                named[name] = group
    return groups


def _binding_keys(binding):
    keys = binding.get("keys")
    if not isinstance(keys, str):
        keys = binding.get("default_keys")
    return keys if isinstance(keys, str) else ""


_GROUP_TITLES = ("Windows", "Workspaces", "Media and volume", "Apps and launchers", "Screenshots", "Other")
_ACTION_KINDS = {
    "Screenshots": r"\bscreenshot\b|\bscreen capture\b",
    "Workspaces": r"\bworkspaces?\b",
    "Media and volume": r"\b(?:volume|mute|unmute|track|play|pause|media)\b",
    "Windows": r"\bwindows?\b|\bfull ?screen\b",
    "Apps and launchers": r"^(?:open|launch|start)\b|\b(?:launcher|terminal)\b",
}


def _binding_kind(members):
    name = members[0].get("name")
    for kind, pattern in _ACTION_KINDS.items():
        if isinstance(name, str) and re.search(pattern, name, re.I):
            return kind
    for item in members:
        default = item.get("default_keys")
        key = _last_key(default if isinstance(default, str) else _binding_keys(item))
        if key.lower().startswith("xf86audio"):
            return "Media and volume"
    return "Other"


def _command_caption(bindings):
    commands = list(dict.fromkeys(item.get("command") for item in bindings
                                  if isinstance(item.get("command"), str) and item.get("command")))
    overridden = [human_keys(_binding_keys(item)) or "(unbound)" for item in bindings
                  if item.get("overridden") is True]
    details = commands + (["Overridden: " + ", ".join(overridden)] if overridden else [])
    return " · ".join(details)


def _logical_lines(text: str):
    pending = ""
    for line in text.splitlines():
        stripped = line.rstrip()
        slashes = len(stripped) - len(stripped.rstrip("\\"))
        if slashes % 2:
            pending += stripped[:-1] + " "
        else:
            yield pending + line
            pending = ""
    if pending:
        yield pending


def _tokens(line: str) -> tuple[list[str], list[tuple[int, int]], int]:
    tokens = []
    spans = []
    token = []
    start = None
    quote = None
    index = 0
    end = len(line)
    while index < len(line):
        char = line[index]
        if quote is None and char == "#":
            end = index
            break
        if char == "\\" and index + 1 < len(line):
            if start is None:
                start = index
            token.append(line[index + 1])
            index += 2
            continue
        if quote is not None:
            if char == quote:
                quote = None
            else:
                token.append(char)
            index += 1
            continue
        if char in ("'", '"'):
            if start is None:
                start = index
            quote = char
        elif char.isspace():
            if start is not None:
                tokens.append("".join(token))
                spans.append((start, index))
                token = []
                start = None
        else:
            if start is None:
                start = index
            token.append(char)
        index += 1
    if start is not None:
        tokens.append("".join(token))
        spans.append((start, end))
    return tokens, spans, end


def _expand(value: str, variables: dict[str, str]) -> str:
    for _ in range(8):
        expanded = re.sub(r"\$([A-Za-z_][A-Za-z0-9_]*)",
                          lambda match: variables.get(match.group(1), match.group(0)), value)
        if expanded == value:
            break
        value = expanded
    return value


NAME_PREFIX = "# name:"


def _sway_bindings(paths: list[Path], *, detailed: bool = False):
    variables: dict[str, str] = {}
    modes: list[str] = []
    bindings = []
    valued_options = {"--input-device"}
    for path in paths:
        name = ""
        for line in _logical_lines(_read(str(path))):
            stripped = line.strip()
            if stripped.startswith(NAME_PREFIX):
                name = stripped[len(NAME_PREFIX):].strip()
                continue
            tokens, spans, line_end = _tokens(line)
            if not tokens:
                continue
            bind_name, name = name, ""
            command = tokens[0]
            if command == "set" and len(tokens) >= 3 and tokens[1].startswith("$"):
                variables[tokens[1][1:]] = " ".join(tokens[2:])
                continue
            if command == "mode" and len(tokens) > 1 and "{" in line[:line_end]:
                modes.append(_expand(tokens[1], variables))
                continue
            if line.lstrip().startswith("}"):
                if modes:
                    modes.pop()
                continue
            if command not in {"bindsym", "bindcode"}:
                continue
            index = 1
            options = []
            while index < len(tokens) and tokens[index].startswith("--"):
                option = tokens[index]
                options.append(line[spans[index][0]:spans[index][1]])
                index += 1
                if option in valued_options and index < len(tokens):
                    options.append(line[spans[index][0]:spans[index][1]])
                    index += 1
            if index + 1 >= len(tokens):
                continue
            keys = _expand(tokens[index], variables)
            command_text = line[spans[index + 1][0]:line_end].strip()
            if not command_text:
                continue
            if detailed:
                bindings.append({"keys": keys, "name": bind_name, "command": command_text,
                                 "flags": options, "editable": (not modes and command == "bindsym"
                                    and not re.search(r"(?:^|\+)(?:button[0-9]+|BTN_[A-Za-z0-9_]+)$", keys)),
                                 "mode": modes[-1] if modes else None, "type": command})
            else:
                if modes:
                    command_text = f"mode {modes[-1]} · {command_text}"
                bindings.append((keys, bind_name, command_text))
    return bindings


_HYPR_COMMAND_NAMES = {
    "dolphin": "Open files", "kitty": "Open terminal", "uwsm app -- kitty": "Open terminal",
    "fuzzel --show drun": "Open app launcher", "kate": "Open text editor",
    "killactive": "Close window", "window.close": "Close window",
    "fullscreen": "Full screen on or off", "window.fullscreen": "Full screen on or off",
    "resizewindow": "Resize window with the mouse", "window.drag": "Move window with the mouse",
}


def _hypr_action_name(keys: str, dispatcher: str, args: str) -> str:
    key = _last_key(keys)
    if key.lower().startswith("xf86"):
        return _key_name(key)
    if dispatcher == "exec":
        if "/api/v1/face/bar" in args:
            return "Show or hide the bar"
        if "/api/v1/face/screenshot" in args:
            mode = re.search(r'"mode"\s*:\s*"(\w+)"', args)
            return {"area": "Screenshot of an area", "full": "Screenshot of the full screen",
                    "window": "Screenshot of the focused window"}.get(mode[1] if mode else "", "Take a screenshot")
        if args.endswith("alt-tab.sh forward"):
            return "Next window"
        if args.endswith("alt-tab.sh backward"):
            return "Previous window"
        if args.endswith("/asr-ptt"):
            return "Push to talk"
        return _HYPR_COMMAND_NAMES.get(args, "")
    if dispatcher in {"workspace", "movetoworkspace", "focus", "window.move"}:
        workspace = re.search(r'\bworkspace\s*=\s*"?([\w+-]+)', args)
        target = workspace[1] if workspace else args if dispatcher in {"workspace", "movetoworkspace"} else ""
        if target:
            moving = dispatcher in {"movetoworkspace", "window.move"}
            if target in {"e-1", "e+1"}:
                direction = "next" if target == "e+1" else "previous"
                return f"Move window to {direction} workspace" if moving else f"{direction.title()} workspace"
            return f"Move window to workspace {target}" if moving else f"Workspace {target}"
    if dispatcher in {"movefocus", "movewindow", "focus", "window.move"}:
        direction = re.search(r'\bdirection\s*=\s*"(\w+)"', args)
        direction = direction[1] if direction else {"u": "up", "d": "down", "l": "left", "r": "right"}.get(args, "")
        if direction:
            verb = "Focus" if dispatcher in {"focus", "movefocus"} else "Move"
            return f"{verb} window {direction}"
        if dispatcher == "movewindow" and key.startswith("mouse:"):
            return "Move window with the mouse"
    if dispatcher in {"window.resize", "resizeactive"}:
        delta = re.findall(r"-?\d+", args)
        if len(delta) == 2 and all(len(d) < 10 for d in delta):
            x, y = map(int, delta)
            size = "narrower" if x < 0 else "wider" if x > 0 else "shorter" if y < 0 else "taller"
            return f"Make window {size}"
        if not args and key.startswith("mouse:"):
            return "Resize window with the mouse"
    return _HYPR_COMMAND_NAMES.get(dispatcher, "")


def _hypr_row(keys: str, dispatcher: str, args: str, command: str, name: str = ""):
    return {"keys": keys, "name": name or _hypr_action_name(keys, dispatcher, args), "command": command}


_LUA_STRING = r'"(?:[^"\\]|\\.)*"'
_LUA_BIND = re.compile(rf'\s*hl\.bind\s*\(\s*({_LUA_STRING})\s*,\s*hl\.dsp\.([\w.]+)'
                       rf'\s*\(((?:{_LUA_STRING}|[^"()])*)\)\s*(?:,\s*\{{[^}}]*\}}\s*)?\)\s*;?\s*')


def _hypr_lua_bindings(path: Path):
    """Read literal binds in the shipped Lua root; never evaluate the config."""
    from agathodaimon.settings._shared import hypr_lua_lines

    strings = {}
    rows = []
    for line in hypr_lua_lines(path):
        try:
            var = re.fullmatch(rf'\s*local\s+(\w+)\s*=\s*({_LUA_STRING})\s*;?\s*', line)
            if var:
                strings[var[1]] = json.loads(var[2])
                continue
            unbind = re.fullmatch(rf'\s*hl\.unbind\s*\(\s*({_LUA_STRING})\s*\)\s*;?\s*', line)
            if unbind:
                key = json.loads(unbind[1])
                rows = [row for row in rows if row["keys"] != key]
                continue
            bind = _LUA_BIND.fullmatch(line)
            if not bind:
                continue
            keys, dispatcher, args = json.loads(bind[1]), bind[2], bind[3].strip()
            command = f"hl.dsp.{dispatcher}({args})"
            if dispatcher == "exec_cmd":
                literal = re.fullmatch(rf'(?:(\w+)\s*\.\.\s*)?({_LUA_STRING})', args)
                if literal and (literal[1] is None or literal[1] in strings):
                    args = strings.get(literal[1], "") + json.loads(literal[2])
                    dispatcher, command = "exec", "exec " + args
            rows.append(_hypr_row(keys, dispatcher, args, command))
        except json.JSONDecodeError:
            continue
    return rows


def _hypr_conf_bindings(root: Path):
    """Legacy hyprlang: read the actual source chain rather than orphan fragments."""
    variables = {}
    active = set()
    rows = []

    def visit(path):
        try:
            path = path.resolve()
            if path in active or not path.is_file():
                return
        except (OSError, RuntimeError):
            return
        active.add(path)
        for line in _logical_lines(_read(str(path))):
            line = re.split(r'(?<!#)#(?!#)', line, 1)[0].replace("##", "#")
            keyword, equal, value = line.partition("=")
            keyword, value = keyword.strip(), value.strip()
            if not equal:
                continue
            if keyword.startswith("$"):
                variables[keyword[1:]] = value
                continue
            value = _expand(value, variables)
            if keyword == "source":
                source = path.parent / os.path.expanduser(value)
                for included in sorted(glob.glob(str(source))):
                    visit(Path(included))
            elif re.fullmatch(r'bind[a-z]*|unbind', keyword):
                described = "d" in keyword[4:]
                parts = [part.strip() for part in value.split(",", 4 if described else 3)]
                if len(parts) < 2 or not parts[1]:
                    continue
                mods, key, *action = parts
                modifiers = re.split(r'[\s_]+', mods.upper()) if mods else []
                keys = "+".join([*modifiers, key])
                if keyword == "unbind":
                    rows[:] = [row for row in rows if row["keys"] != keys]
                    continue
                name = action.pop(0) if described and action else ""
                if action and action[0]:
                    dispatcher, *args = action
                    rows.append(_hypr_row(keys, dispatcher, args[0] if args else "", " ".join(action), name))
        active.remove(path)

    visit(root)
    return rows


def _local_bindings(message):
    config = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower().split(":")
    sway_socket = os.environ.get("SWAYSOCK")
    sway = "sway" in desktop or bool(sway_socket and Path(sway_socket).is_socket())
    hypr = config / "hypr"
    lua, conf = hypr / "hyprland.lua", hypr / "hyprland.conf"
    if not sway and ("hyprland" in desktop or os.environ.get("HYPRLAND_INSTANCE_SIGNATURE")
                     or lua.is_file() or conf.is_file()):
        bindings = _hypr_lua_bindings(lua) if lua.is_file() else _hypr_conf_bindings(conf)
        return bindings, ("Shortcuts are read-only here and can be changed on Sway machines." if bindings else
                          "No Hyprland shortcuts could be read; shortcuts can be changed on Sway machines.")
    if message:
        sway_dir = config / "sway"
        paths = [sway_dir / "config", *sorted((sway_dir / "conf.d").glob("*.conf"))]
        bindings = [{"keys": keys, "name": name, "command": command}
                    for keys, name, command in _sway_bindings(paths)]
        return bindings, message
    return [], "Sway did not report any shortcuts." if sway else "No keyboard shortcuts were found on this machine."


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, GLib, Gtk, Pango

    page = _page(Adw, PLUG)
    notice = _group(Adw, page, "")
    notice.set_description("Reading shortcuts…")

    settings_path = "/api/v1/settings/shortcuts"

    def show_binding(row, caps, members):
        detail = _command_caption(members)
        row.set_subtitle(f"<tt>{GLib.markup_escape_text(detail)}</tt>" if detail else "")
        row.set_tooltip_text(detail or None)
        while (child := caps.get_first_child()) is not None:
            caps.remove(child)
        # Use Adwaita's stock keycap styling with our display-only key names.
        # Libadwaita 1.8 moved the style from GtkShortcutLabel's CSS node to its own.
        node = "shortcut-label" if hasattr(Adw, "ShortcutLabel") else "shortcut"
        for binding in members:
            parts = _key_parts(_binding_keys(binding))
            if not parts:
                caps.append(Gtk.Label(label="Unbound", halign=Gtk.Align.END, css_classes=["dim-label"]))
                continue
            chord = Gtk.Box(css_name=node, spacing=4, halign=Gtk.Align.END)
            for index, part in enumerate(parts):
                if index:
                    chord.append(Gtk.Label(label="+", css_classes=["dim-label"]))
                chord.append(Gtk.Label(label=part, css_classes=["keycap"]))
            caps.append(chord)

    def show_status(label, text):
        label.set_text(text)
        label.set_tooltip_text(text)
        label.set_visible(bool(text))

    def finish_read(bindings, message):
        notice.set_description(message or "")
        notice.set_visible(bool(message))
        classified = {title: [] for title in _GROUP_TITLES}
        for members in fold_bindings(bindings):
            classified[_binding_kind(members)].append(members)
        groups = {kind: _group(Adw, page, kind) for kind, actions in classified.items() if actions}

        for kind, members in ((kind, members) for kind, actions in classified.items() for members in actions):
            name = members[0].get("name")
            title = name.strip() if isinstance(name, str) and name.strip() else "Unnamed shortcut"
            row = Adw.ActionRow(title=GLib.markup_escape_text(title), use_markup=True, subtitle_lines=1,
                                focusable=True)
            row.connect("notify::has-focus", lambda focused, _: focused.set_subtitle_lines(0 if focused.has_focus() else 1))
            caps = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, valign=Gtk.Align.CENTER,
                           margin_top=6, margin_bottom=6)
            status_label = Gtk.Label(xalign=0, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                                     lines=2, max_width_chars=18, ellipsize=Pango.EllipsizeMode.END,
                                     visible=False, css_classes=["caption"])
            row.add_suffix(status_label)
            row.add_suffix(caps)
            show_binding(row, caps, members)
            activity = {"busy": False}
            editable = any(binding.get("editable") is True for binding in members)
            row.set_activatable(editable)
            if editable:
                def open_editor(_row, selected_members=members, selected_row=row,
                                selected_keys=caps, selected_status=status_label,
                                action_title=title, selected_activity=activity):
                    if selected_activity["busy"]:
                        return
                    dialog_parent = selected_row.get_root()
                    dialog_kwargs = {"title": action_title, "modal": True}
                    if isinstance(dialog_parent, Gtk.Window):
                        dialog_kwargs["transient_for"] = dialog_parent
                    dialog = Gtk.Dialog(**dialog_kwargs)
                    content = dialog.get_content_area()
                    chooser = None
                    if len(selected_members) > 1:
                        chooser = Gtk.DropDown.new_from_strings([
                            human_keys(_binding_keys(item)) or "(unbound)" for item in selected_members
                        ])
                        content.append(chooser)
                    content.append(Gtk.Label(label="Press the new keys…", xalign=0))
                    capture_entry = Gtk.Entry()
                    capture_entry.set_editable(False)
                    content.append(capture_entry)
                    reset_button = dialog.add_button("Reset to default", Gtk.ResponseType.APPLY)
                    dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
                    save_button = dialog.add_button("Save", Gtk.ResponseType.OK)
                    save_button.set_sensitive(False)
                    dialog.set_default_response(Gtk.ResponseType.OK)
                    captured: dict[str, str | None] = {"keys": None}
                    unsupported_keys: set[str] = set()
                    unsupported_names = {"Hyper_L", "Hyper_R", "ISO_Level3_Shift", "Mode_switch"}

                    def chosen():
                        return selected_members[chooser.get_selected() if chooser is not None else 0]

                    def selection_changed(*_args):
                        captured["keys"] = None
                        capture_entry.set_text("")
                        save_button.set_sensitive(False)
                        reset_button.set_sensitive(chosen().get("editable") is True)

                    if chooser is not None:
                        chooser.connect("notify::selected", selection_changed)
                    selection_changed()

                    def reject_modifiers():
                        captured["keys"] = None
                        capture_entry.set_text("These modifiers cannot be captured")
                        save_button.set_sensitive(False)

                    def on_key(_controller, keyval, _keycode, state):
                        key_name = Gdk.keyval_name(keyval) or ""
                        if key_name in {"Escape", "Esc"}:
                            dialog.response(Gtk.ResponseType.CANCEL)
                            return True
                        if key_name in {"Tab", "ISO_Left_Tab"}:
                            return False
                        # GTK4 Entry hands focus to its inner GtkText child.
                        focus = dialog.get_focus()
                        if focus is None or not (focus is capture_entry or focus.is_ancestor(capture_entry)):
                            return False
                        if key_name in unsupported_names:
                            unsupported_keys.add(key_name)
                            reject_modifiers()
                            return True
                        hyper_mask = getattr(Gdk.ModifierType, "HYPER_MASK", 0)
                        super_mask = getattr(Gdk.ModifierType, "SUPER_MASK", 0)
                        meta_mask = getattr(Gdk.ModifierType, "META_MASK", 0)
                        # GTK4 does not expose named Mod2/3/5 masks. Never
                        # silently save a chord when an unsupported bit is set.
                        if (unsupported_keys or int(state) & (0x10 | 0x20 | 0x80 | int(hyper_mask))
                                or (state & meta_mask and not state & super_mask)):
                            reject_modifiers()
                            return True
                        if key_name in {
                            "Shift_L", "Shift_R", "Control_L", "Control_R",
                            "Alt_L", "Alt_R", "Meta_L", "Meta_R", "Super_L", "Super_R",
                            "Hyper_L", "Hyper_R", "ISO_Level3_Shift", "Mode_switch",
                            "Caps_Lock", "Num_Lock",
                        }:
                            return True
                        modifiers = []
                        if state & Gdk.ModifierType.CONTROL_MASK:
                            modifiers.append("Control")
                        if state & Gdk.ModifierType.ALT_MASK:
                            modifiers.append("Mod1")
                        if state & Gdk.ModifierType.SHIFT_MASK:
                            modifiers.append("Shift")
                        super_mask = getattr(Gdk.ModifierType, "SUPER_MASK", 0)
                        meta_mask = getattr(Gdk.ModifierType, "META_MASK", 0)
                        mod4_mask = getattr(Gdk.ModifierType, "MOD4_MASK", 0)
                        if state & (super_mask | meta_mask | mod4_mask):
                            modifiers.append("Mod4")
                        if not key_name:
                            return False
                        chord = "+".join([*modifiers, key_name])
                        captured["keys"] = chord
                        capture_entry.set_text(human_keys(chord))
                        save_button.set_sensitive(chosen().get("editable") is True)
                        return True

                    def on_key_released(_controller, keyval, _keycode, _state):
                        unsupported_keys.discard(Gdk.keyval_name(keyval) or "")

                    key_controller = Gtk.EventControllerKey.new()
                    key_controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
                    key_controller.connect("key-pressed", on_key)
                    key_controller.connect("key-released", on_key_released)
                    dialog.add_controller(key_controller)

                    def submit(to_keys):
                        selected = chosen()
                        original = selected.get("default_keys")
                        if not isinstance(original, str):
                            original = ""
                        selected_activity["busy"] = True
                        show_status(selected_status, "Saving…")
                        threading.Thread(
                            target=post_change,
                            args=(selected_members, selected, selected_row, selected_keys, selected_status, selected_activity,
                                  original, to_keys),
                            daemon=True,
                        ).start()

                    def on_response(_dialog, response_id):
                        if response_id == Gtk.ResponseType.OK and captured["keys"]:
                            submit(captured["keys"])
                        elif response_id == Gtk.ResponseType.APPLY:
                            submit(None)
                        dialog.destroy()
                        selected_row.grab_focus()

                    dialog.connect("response", on_response)
                    dialog.present()
                    capture_entry.grab_focus()

                row.connect("activated", open_editor)
            groups[kind].add(row)
        return False

    def finish_change(members, binding, row, caps, status_label, activity, default_keys, to_keys,
                      receipt, error):
        if error:
            show_status(status_label, "Settings could not reach the shortcut service.")
        elif _receipt_ok(receipt):
            current_keys = default_keys if to_keys is None else to_keys
            binding["keys"] = current_keys
            binding["overridden"] = current_keys != default_keys
            show_binding(row, caps, members)
            show_status(status_label, "Reset to default" if to_keys is None else "Saved")
        else:
            signal = receipt.get("firstMissingSignal", receipt.get("first_missing_signal", ""))
            if isinstance(signal, str) and signal.startswith("shortcuts-key-taken:"):
                message = "Already used by " + signal.split(":", 1)[1]
            else:
                message = {
                    "invalid:to": "That key combination is not valid",
                    "unknown:from": "This shortcut is no longer available",
                    "shortcuts-override-include-absent": "Shortcut editing is not enabled in Sway",
                    "shortcuts-keycode-conflict-unknown": "A keycode shortcut prevents checking for conflicts",
                    "shortcuts-override-cycle": "These shortcuts cannot be swapped directly",
                    "shortcuts-override-unmanaged": "The shortcut file contains unsupported changes",
                    "shortcuts-orphaned-override": "A saved shortcut no longer has a default",
                    "sway-reload-failed": "Sway could not apply the shortcut",
                    "sway-session-unavailable": "Sway is not available",
                }.get(signal, "Change refused")
            show_status(status_label, message)
        activity["busy"] = False
        return False

    def post_change(members, binding, row, caps, status_label, activity, default_keys, to_keys):
        try:
            receipt = _request(
                settings_path,
                "POST",
                {"from": default_keys, "to": to_keys},
            )
            GLib.idle_add(
                finish_change, members, binding, row, caps, status_label, activity,
                default_keys, to_keys, receipt, None,
            )
        except RuntimeError:
            GLib.idle_add(
                finish_change, members, binding, row, caps, status_label, activity,
                default_keys, to_keys, None, "unavailable",
            )

    def deliver(bindings, message=None):
        if not bindings:
            bindings, message = _local_bindings(message)
        GLib.idle_add(finish_read, bindings, message)

    def read_settings():
        try:
            doors = _request("/api/v1/doors")
            routes = doors.get("routes")
            if not isinstance(routes, list) or settings_path not in routes:
                deliver(None, "Shortcut editing is not available on this machine.")
                return
            receipt = _request(settings_path)
            values = receipt.get("values")
            bindings = values.get("bindings") if isinstance(values, dict) else None
            if not _receipt_ok(receipt) or not isinstance(bindings, list) or not all(
                isinstance(binding, dict) for binding in bindings
            ):
                deliver(None, "Settings could not read the current shortcuts.")
                return
            deliver(bindings)
        except RuntimeError:
            deliver(None, "Settings could not reach the shortcut service.")

    threading.Thread(target=read_settings, daemon=True).start()
    return page

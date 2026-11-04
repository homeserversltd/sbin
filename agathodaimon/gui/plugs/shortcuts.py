"""Caduceus-backed keyboard shortcuts with a read-only fallback."""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path

try:
    from ._common import _read, _page, _group, _row, _request, _receipt_ok
except ImportError:
    import importlib.util as _importlib_util
    _common_spec = _importlib_util.spec_from_file_location(
        "_common", __file__.replace(__file__.split("/")[-1], "_common.py")
    )
    _common_module = _importlib_util.module_from_spec(_common_spec)
    import sys as _sys
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _read, _page, _group, _row, _request, _receipt_ok

PLUG = {"id": "shortcuts", "title": "Shortcuts", "icon": "preferences-desktop-keyboard-shortcuts-symbolic", "order": 70, "parent": None}


def human_keys(keys: str) -> str:
    names = {"Mod4": "Super", "Mod1": "Alt", "Control": "Ctrl",
             "Mod5": "AltGr", "Return": "Enter"}
    return "+".join(names.get(part, part.upper() if len(part) == 1 and part.isalpha() else part)
                    for part in keys.split("+"))


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


def _group_presentation(bindings):
    keys = "\n".join(human_keys(_binding_keys(item)) or "(unbound)" for item in bindings)
    commands = list(dict.fromkeys(item.get("command") for item in bindings
                                  if isinstance(item.get("command"), str) and item.get("command")))
    overridden = [human_keys(_binding_keys(item)) or "(unbound)" for item in bindings
                  if item.get("overridden") is True]
    details = commands + (["Overridden: " + ", ".join(overridden)] if overridden else [])
    return keys, " · ".join(details)


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


def _plain_row(Adw, title: str, subtitle: str = ""):
    row = _row(Adw, title, subtitle)
    row.set_use_markup(False)
    return row


def _read_only_rows(Adw, Gtk, group):
    rows = []
    sway_dir = Path.home() / ".config" / "sway"
    if "SWAYSOCK" in os.environ or sway_dir.exists():
        paths = [sway_dir / "config", *sorted((sway_dir / "conf.d").glob("*.conf"))]
        bindings = [{"keys": keys, "name": name, "command": command}
                    for keys, name, command in _sway_bindings(paths)]
        for members in fold_bindings(bindings):
            name = members[0].get("name") or "(no name)"
            keys, subtitle = _group_presentation(members)
            row = _plain_row(Adw, name, subtitle)
            key_label = Gtk.Label(label=keys, xalign=0, width_chars=22, valign=Gtk.Align.START)
            key_label.add_css_class("monospace")
            row.add_prefix(key_label)
            group.add(row)
            rows.append(row)
    else:
        text = _read("~/.config/hypr/bindings.conf").strip()
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                row = _plain_row(Adw, line)
                group.add(row)
                rows.append(row)
    if not rows:
        row = _row(Adw, "not configured")
        group.add(row)
        rows.append(row)
    return rows


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, GLib, Gtk

    page = _page(Adw, PLUG)
    fallback_group = _group(Adw, page, "")
    editable_group = _group(Adw, page, "")
    editable_group.set_visible(False)
    _read_only_rows(Adw, Gtk, fallback_group)
    fallback_status = Adw.ActionRow(title="Shortcut editing", subtitle="Checking Caduceus door…")
    fallback_status.set_sensitive(False)
    fallback_group.add(fallback_status)

    settings_path = "/api/v1/settings/shortcuts"

    def finish_read(bindings, message):
        if message:
            editable_group.set_visible(False)
            fallback_group.set_visible(True)
            fallback_status.set_subtitle(message)
            return False

        for members in fold_bindings(bindings):
            name = members[0].get("name")
            title = name.strip() if isinstance(name, str) and name.strip() else "(no name)"
            keys, subtitle = _group_presentation(members)
            row = _plain_row(Adw, title, subtitle)
            key_label = Gtk.Label(label=keys, xalign=0, width_chars=22, valign=Gtk.Align.START)
            key_label.add_css_class("monospace")
            row.add_prefix(key_label)
            status_label = Gtk.Label(label="", xalign=1)
            row.add_suffix(status_label)
            activity = {"busy": False}
            editable = any(binding.get("editable") is True for binding in members)
            if editable:
                row.set_activatable(True)
                row.set_focusable(True)

                def open_editor(_row, selected_members=members, selected_row=row,
                                selected_keys=key_label, selected_status=status_label,
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
                    capture_entry.set_placeholder_text("Press the new keys…")
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
                        selected_status.set_text("Saving…")
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
            editable_group.add(row)

        if not bindings:
            editable_group.add(_row(Adw, "not configured"))
        fallback_group.set_visible(False)
        editable_group.set_visible(True)
        return False

    def finish_change(members, binding, row, key_label, status_label, activity, default_keys, to_keys,
                      receipt, error):
        if error:
            status_label.set_text("Caduceus unavailable")
        elif _receipt_ok(receipt):
            current_keys = default_keys if to_keys is None else to_keys
            binding["keys"] = current_keys
            binding["overridden"] = current_keys != default_keys
            keys, subtitle = _group_presentation(members)
            key_label.set_text(keys)
            row.set_subtitle(subtitle)
            status_label.set_text("Reset to default" if to_keys is None else "Saved")
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
            status_label.set_text(message)
        activity["busy"] = False
        return False

    def post_change(members, binding, row, key_label, status_label, activity, default_keys, to_keys):
        try:
            receipt = _request(
                settings_path,
                "POST",
                {"from": default_keys, "to": to_keys},
            )
            GLib.idle_add(
                finish_change, members, binding, row, key_label, status_label, activity,
                default_keys, to_keys, receipt, None,
            )
        except RuntimeError:
            GLib.idle_add(
                finish_change, members, binding, row, key_label, status_label, activity,
                default_keys, to_keys, None, "unavailable",
            )

    def read_settings():
        try:
            doors = _request("/api/v1/doors")
            routes = doors.get("routes")
            if not isinstance(routes, list) or settings_path not in routes:
                GLib.idle_add(finish_read, None, "Read-only: shortcut editing is unavailable")
                return
            receipt = _request(settings_path)
            values = receipt.get("values")
            bindings = values.get("bindings") if isinstance(values, dict) else None
            if not _receipt_ok(receipt) or not isinstance(bindings, list) or not all(
                isinstance(binding, dict) for binding in bindings
            ):
                GLib.idle_add(finish_read, None, "Shortcut settings unavailable")
                return
            GLib.idle_add(finish_read, bindings, None)
        except RuntimeError:
            GLib.idle_add(finish_read, None, "Caduceus unavailable")

    threading.Thread(target=read_settings, daemon=True).start()
    return page

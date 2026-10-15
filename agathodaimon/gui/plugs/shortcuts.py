"""Read-only keyboard shortcuts."""
from __future__ import annotations

import os
import re
from pathlib import Path

try:
    from ._common import _read, _page, _group, _missing, _row, _disabled
except ImportError:
    import importlib.util as _importlib_util
    _common_spec = _importlib_util.spec_from_file_location(
        "_common", __file__.replace(__file__.split("/")[-1], "_common.py")
    )
    _common_module = _importlib_util.module_from_spec(_common_spec)
    import sys as _sys
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _read, _page, _group, _missing, _row, _disabled

PLUG = {"id": "shortcuts", "title": "Shortcuts", "icon": "preferences-desktop-keyboard-shortcuts-symbolic", "order": 70, "parent": None}


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


def _sway_bindings(paths: list[Path]) -> list[tuple[str, str, str]]:
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
                options.append(option)
                index += 1
                if option in valued_options and index < len(tokens):
                    index += 1
            if index + 1 >= len(tokens):
                continue
            keys = _expand(tokens[index], variables)
            command_text = line[spans[index + 1][0]:line_end].strip()
            if not command_text:
                continue
            if modes:
                command_text = f"mode {modes[-1]} · {command_text}"
            bindings.append((keys, bind_name, command_text))
    return bindings


def _plain_row(Adw, title: str, subtitle: str = ""):
    row = _row(Adw, title, subtitle)
    row.set_use_markup(False)
    return row


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    page = _page(Adw, PLUG)
    group = _group(Adw, page, "Bindings")
    sway_dir = Path.home() / ".config" / "sway"
    if "SWAYSOCK" in os.environ or sway_dir.exists():
        paths = [sway_dir / "config", *sorted((sway_dir / "conf.d").glob("*.conf"))]
        bindings = _sway_bindings(paths)
        for keys, name, command in bindings:
            row = _plain_row(Adw, name or "(no name)", command)
            key_label = Gtk.Label(label=keys, xalign=0, width_chars=22)
            key_label.add_css_class("monospace")
            row.add_prefix(key_label)
            group.add(row)
        if not bindings:
            _missing(Adw, group)
    else:
        text = _read("~/.config/hypr/bindings.conf").strip()
        added = False
        if text:
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    group.add(_plain_row(Adw, line))
                    added = True
        if not added:
            _missing(Adw, group)
    _disabled(Gtk, Adw, group, "Shortcut configuration")
    return page

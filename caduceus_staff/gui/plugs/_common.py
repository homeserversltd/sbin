"""Shared read-only helpers for appliance settings plugs."""
from __future__ import annotations

import configparser
import json
import os
import subprocess
from pathlib import Path
from typing import Any


def _read(path: str) -> str:
    try:
        return Path(os.path.expanduser(path)).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return ""


def _ini(path: str) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read(os.path.expanduser(path), encoding="utf-8")
    except (OSError, configparser.Error, UnicodeError, ValueError):
        pass
    return parser


def _json(path: str) -> dict[str, Any]:
    try:
        value = json.loads(_read(path))
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _command(*args: str) -> str:
    try:
        result = subprocess.run(args, check=False, capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""
    return result.stdout.strip()


def _row(Adw: Any, title: str, subtitle: str = "") -> Any:
    return Adw.ActionRow(title=title, subtitle=subtitle)


def _missing(Adw: Any, group: Any) -> None:
    group.add(_row(Adw, "not configured"))


def _page(Adw: Any, plug: dict[str, Any]) -> Any:
    return Adw.PreferencesPage(title=plug["title"], icon_name=plug["icon"])


def _group(Adw: Any, page: Any, title: str) -> Any:
    group = Adw.PreferencesGroup(title=title)
    page.add(group)
    return group


def _disabled(Gtk: Any, Adw: Any, group: Any, title: str) -> None:
    """Show a real, visibly disabled control awaiting the Caduceus door."""
    row = Adw.ActionRow(title=title, subtitle="Awaiting Caduceus door")
    control = Gtk.Entry()
    control.set_editable(False)
    control.set_sensitive(False)
    control.set_placeholder_text("Unavailable")
    row.add_suffix(control)
    row.set_sensitive(False)
    group.add(row)

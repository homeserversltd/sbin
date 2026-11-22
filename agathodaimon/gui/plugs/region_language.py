"""Read-only preview of the planned Region & Language settings."""
from __future__ import annotations

import os
import re
import subprocess
import threading

try:
    from ._common import _group, _json, _page, _receipt_ok, _request
except ImportError:
    from _common import _group, _json, _page, _receipt_ok, _request

PLUG = {"id": "region-language", "title": "Region & Language", "icon": "preferences-desktop-locale-symbolic", "order": 95, "parent": None}

_LOCALE = re.compile(r"(?:([a-z]{2,3})(?:_([A-Z]{2}))?|C|POSIX)(?:\.[A-Za-z0-9-]+)?(?:@[A-Za-z0-9_-]+)?")
_MEASUREMENT = {"metric": "Metric", "imperial": "US customary"}
_PAPER = {("210", "297"): "A4", ("216", "279"): "Letter"}
_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def _english_name(table: str, code: str | None) -> str | None:
    if not code:
        return None
    entries = _json(f"/usr/share/iso-codes/json/iso_{table}.json").get(table)
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and code in (entry.get("alpha_2"), entry.get("alpha_3")):
                name = entry.get("common_name") or entry.get("name")
                return name if isinstance(name, str) and name else None
    return None


def _paper_and_weekday(locale_id: str) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(
            ["locale", "-k", "LC_PAPER", "LC_TIME"], env={**os.environ, "LC_ALL": locale_id},
            capture_output=True, text=True, errors="replace", timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None, None
    # An ungenerated locale can print C defaults with a warning and exit zero.
    if result.returncode or result.stderr:
        return None, None
    facts = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    paper = _PAPER.get((facts.get("width", ""), facts.get("height", "")))
    # glibc's first_weekday is one-based relative to the week origin.
    week_origin = {"19971130": 6, "19971201": 0}.get(facts.get("week-1stday", ""))
    first = facts.get("first_weekday", "")
    weekday = None
    if week_origin is not None and first in {"1", "2", "3", "4", "5", "6", "7"}:
        weekday = _WEEKDAYS[(week_origin + int(first) - 1) % len(_WEEKDAYS)]
    return paper, weekday


def _current_values() -> tuple[str | None, ...]:
    try:
        reply = _request("/api/v1/settings/region", method="GET")
    except RuntimeError:
        return (None,) * 5
    values = reply.get("values")
    if not _receipt_ok(reply) or not isinstance(values, dict):
        return (None,) * 5

    units = values.get("measurement_units")
    measurement = _MEASUREMENT.get(units) if isinstance(units, str) else None
    locale_id = values.get("locale")
    match = _LOCALE.fullmatch(locale_id) if isinstance(locale_id, str) and len(locale_id) <= 128 else None
    if match is None:
        return None, None, measurement, None, None
    language = _english_name("639-3", match[1])
    region = _english_name("3166-1", match[2])
    if language and region:
        language = f"{language} ({region})"
    paper, weekday = _paper_and_weekday(match[0])
    return language, region, measurement, paper, weekday


def build_widget():
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    page = _page(Adw, PLUG)
    group = _group(Adw, page, "")
    rows = []
    for title in ("Language", "Formats", "Measurement", "Paper size", "First day of the week"):
        row = Adw.ActionRow(title=title, subtitle="Coming soon", sensitive=False,
                            activatable=False, selectable=False)
        group.add(row)
        rows.append(row)

    def finish(values):
        if page.get_root() is not None:
            for row, value in zip(rows, values):
                if value is not None:
                    row.add_suffix(Gtk.Label(label=value, valign=Gtk.Align.CENTER,
                                             wrap=True, width_chars=min(len(value), 32),
                                             max_width_chars=32, justify=Gtk.Justification.RIGHT))
        return GLib.SOURCE_REMOVE

    def read():
        GLib.idle_add(finish, _current_values())

    def on_map(widget):
        widget.disconnect(map_handler)
        threading.Thread(target=read, daemon=True).start()

    map_handler = page.connect("map", on_map)
    return page

"""Read-only preview of the planned Region & Language settings."""
from __future__ import annotations

import os
import re
import subprocess
import threading

try:
    from ._common import _group, _page, _receipt_ok, _request
except ImportError:
    from _common import _group, _page, _receipt_ok, _request

PLUG = {"id": "region-language", "title": "Region & Language", "icon": "preferences-desktop-locale-symbolic", "order": 95, "parent": None}

_LOCALE = re.compile(r"(?:[a-z]{2,3}(?:_[A-Z]{2})?|C|POSIX)(?:\.[A-Za-z0-9-]+)?(?:@[A-Za-z0-9_-]+)?")
_MEASUREMENT = {"metric": "Metric", "imperial": "US customary"}
_PAPER = {("210", "297"): "A4", ("216", "279"): "Letter"}
_WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
_FORMATS_PROBE = r"""
/usr/bin/locale charmap
/usr/bin/date '+%x%n%X'
/usr/bin/printf "%'.2f\n" 1234.56
/usr/bin/locale -k LC_ADDRESS LC_PAPER LC_TIME
"""


def _language_label(options, locale_id: str) -> str | None:
    entries = options.get("locale") if isinstance(options, dict) else None
    if isinstance(entries, list):
        for entry in entries:
            if isinstance(entry, dict) and entry.get("value") == locale_id:
                label = entry.get("label")
                return label if isinstance(label, str) and label else None
    return None


def _locale_formats(locale_id: str) -> tuple[str, str | None, str | None] | None:
    """Read and format under the stored locale without changing GTK's locale."""
    try:
        result = subprocess.run(
            ["/bin/sh", "-ec", _FORMATS_PROBE], env={**os.environ, "LC_ALL": locale_id},
            capture_output=True, timeout=3, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    # An ungenerated locale can print C defaults with a warning and exit zero.
    if result.returncode or result.stderr:
        return None
    charmap, _, output = result.stdout.partition(b"\n")
    try:
        date, time, number, keywords = output.decode(charmap.decode("ascii")).split("\n", 3)
    except (LookupError, ValueError):
        return None
    facts = dict(line.split("=", 1) for line in keywords.splitlines() if "=" in line)
    country = facts.get("country_name", "").removeprefix('"').removesuffix('"')
    preview = " · ".join((date, time, number))
    formats = f"{country}\n{preview}" if country else preview
    paper = _PAPER.get((facts.get("width", ""), facts.get("height", "")))
    # glibc's first_weekday is one-based relative to the week origin.
    week_origin = {"19971130": 6, "19971201": 0}.get(facts.get("week-1stday", ""))
    first = facts.get("first_weekday", "")
    weekday = None
    if week_origin is not None and first in {"1", "2", "3", "4", "5", "6", "7"}:
        weekday = _WEEKDAYS[(week_origin + int(first) - 1) % len(_WEEKDAYS)]
    return formats, paper, weekday


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
    if not isinstance(locale_id, str) or len(locale_id) > 128 or not _LOCALE.fullmatch(locale_id):
        return None, None, measurement, None, None
    probe = _locale_formats(locale_id)
    if probe is None:
        return None, None, measurement, None, None
    formats, paper, weekday = probe
    return _language_label(reply.get("options"), locale_id), formats, measurement, paper, weekday


def build_widget():
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk, Pango

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
                    row.add_suffix(Gtk.Label(
                        label=value, valign=Gtk.Align.CENTER, xalign=1,
                        justify=Gtk.Justification.RIGHT, wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR,
                        natural_wrap_mode=Gtk.NaturalWrapMode.NONE,
                    ))
        return GLib.SOURCE_REMOVE

    def read():
        GLib.idle_add(finish, _current_values())

    def on_map(widget):
        widget.disconnect(map_handler)
        threading.Thread(target=read, daemon=True).start()

    map_handler = page.connect("map", on_map)
    return page

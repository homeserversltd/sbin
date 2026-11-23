"""Date and time settings over the Caduceus datetime door."""
from __future__ import annotations

import re
import threading
from datetime import datetime, timezone
from http.client import HTTPException
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import _common

PLUG = {"id": "date-time", "title": "Date & Time", "icon": "preferences-system-time-symbolic", "order": 100, "parent": None}
_PATH = "/api/v1/settings/datetime"
_CLOCK_LABELS = {"24h": "24-hour", "12h": "12-hour"}
_WALL_TIME = "%Y-%m-%d %H:%M"
_AUTOMATIC_TIME_ON = "unsupported:automatic-time-on"
_REFUSALS = {
    "unsupported:homeserver-keeps-house-time": "Your HomeServer keeps the house's time.",
    _AUTOMATIC_TIME_ON: "Turn off automatic date and time before setting the clock.",
    "unsupported:bar-clock-override-absent": "This device's clock format can't be changed from Settings.",
}


def _request(method="GET", payload=None):
    try:
        return _common._request(_PATH, method, payload)
    except (RuntimeError, HTTPException):
        return {}


def _choices(options, field):
    entries = options.get(field)
    if not isinstance(entries, list):
        return {}
    return {item["value"]: item["label"] for item in entries
            if isinstance(item, dict) and isinstance(item.get("value"), str)
            and isinstance(item.get("label"), str) and item["value"] and item["label"]
            and (field != "time_format" or item["value"] in _CLOCK_LABELS)}


def _zone(name):
    if isinstance(name, str) and name:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError):
            pass
    return None


def _sync_status(values, now):
    if values.get("ntp_enabled") is False:
        return "Automatic time is off."
    if values.get("ntp_synchronized") is False:
        return "The clock hasn't synchronized yet."
    if values.get("ntp_synchronized") is not True:
        return "Sync status is unavailable."

    server = values.get("time_server")
    if server == "home.arpa":
        server = "your HomeServer"
    text = f"Synced with {server}" if isinstance(server, str) and server else "Synced"
    last_sync = values.get("last_sync")
    if isinstance(last_sync, str):
        try:
            stamp = datetime.fromisoformat(last_sync)
            if stamp.tzinfo is not None and now >= stamp:
                minutes = int((now - stamp).total_seconds() // 60)
                if minutes >= 1440:
                    days = minutes // 1440
                    age = f"{days} day{'s' if days != 1 else ''} ago"
                elif minutes >= 60:
                    age = f"{minutes // 60} hr ago"
                else:
                    age = f"{minutes} min ago" if minutes else "just now"
                text += f" · {age}"
        except ValueError:
            pass
    return text


def _refusal(receipt):
    # A generic gate signal can ride beside the staff's more specific refusal.
    staff = _common._signal(receipt)
    return staff if staff in _REFUSALS else _common._refusal_signal(receipt)


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk, Pango

    page = _common._page(Adw, PLUG)
    group = Adw.PreferencesGroup()
    page.add(group)
    switches = {
        "automatic_timezone": Adw.SwitchRow(title="Automatic time zone", use_markup=False),
        "ntp_enabled": Adw.SwitchRow(title="Automatic date and time", use_markup=False),
    }
    combos = {
        "timezone": Adw.ComboRow(title="Time zone", use_markup=False),
        "time_format": Adw.ComboRow(title="Clock", use_markup=False),
    }
    combos["timezone"].set_enable_search(True)
    manual = Adw.ActionRow(title="Date and time", use_markup=False)
    entry = Gtk.Entry(placeholder_text="YYYY-MM-DD HH:MM", width_chars=18, valign=Gtk.Align.CENTER)
    entry.update_property([Gtk.AccessibleProperty.LABEL], ["New local date and time (YYYY-MM-DD HH:MM)"])
    button = Gtk.Button(label="Set", valign=Gtk.Align.CENTER)
    manual.add_suffix(entry)
    manual.add_suffix(button)
    controls = {
        "automatic_timezone": switches["automatic_timezone"],
        "timezone": combos["timezone"],
        "ntp_enabled": switches["ntp_enabled"],
        "local_time": manual,
        "time_format": combos["time_format"],
    }
    alternatives = {}
    for field, row in controls.items():
        row.set_visible(False)
        group.add(row)
        if field != "local_time":
            # A disabled ComboRow or SwitchRow cannot select text. Keep the
            # value and refusal together in a stock read-only row in that case.
            alternate = Adw.ActionRow(title=row.get_title(), use_markup=False)
            label = Gtk.Label(valign=Gtk.Align.CENTER)
            alternate.add_suffix(label)
            alternate.set_visible(False)
            group.add(alternate)
            alternatives[field] = (alternate, label)
    read_status = Adw.ActionRow(title="Reading date and time…")
    group.add(read_status)

    values = {}
    offered = {}
    readonly = {}
    locked = {}
    selected_options = {}
    outcomes = {}
    editable = set()
    zone = None
    available = painting = reading = saving = manual_wait = False
    revision = minute_source = 0

    def subtitle_label(widget):
        child = widget.get_first_child()
        while child is not None:
            if isinstance(child, Gtk.Label) and child.has_css_class("subtitle"):
                return child
            found = subtitle_label(child)
            if found is not None:
                return found
            child = child.get_next_sibling()
        return None

    def paint_subtitle(row, resting, message, signal):
        text = "\n".join(filter(None, (resting, message, signal)))
        if row.get_subtitle() == text:
            return
        row.set_subtitle(text)
        label = subtitle_label(row)
        if label is not None:
            attributes = None
            if signal:
                attributes = Pango.AttrList()
                small = Pango.attr_scale_new(0.83)
                small.start_index = len(text.encode("utf-8")) - len(signal.encode("utf-8"))
                attributes.insert(small)
            label.set_attributes(attributes)
            label.set_selectable(bool(signal))

    def paint(now=None):
        nonlocal painting
        painting = True
        try:
            now = now or datetime.now(timezone.utc)
            follows_house = values.get("automatic_timezone")
            manual_time = values.get("ntp_enabled") is False
            named = {}
            editable.clear()
            for field, row in switches.items():
                value = values.get(field)
                row.set_active(value is True)
                if isinstance(value, bool):
                    named[field] = "On" if value else "Off"
                    editable.add(field)
                else:
                    named[field] = "Unavailable"
            for field, row in combos.items():
                value = values.get(field)
                value = value if isinstance(value, str) else None
                options = offered.get(field, {})
                if field == "timezone":
                    fallback = value.replace("_", " ") if value else "Unavailable"
                else:
                    fallback = _CLOCK_LABELS.get(value, "Not set") if value is not None else "Not set"
                named[field] = options.get(value, fallback) if value is not None else fallback
                entries = list(options.items())
                if value not in options:
                    entries.insert(0, (value, named[field]))
                entries = tuple(entries)
                if selected_options.get(field) != entries:
                    selected_options[field] = entries
                    row.set_model(Gtk.StringList.new([label for _, label in entries]))
                row.set_selected(next(i for i, (key, _) in enumerate(entries) if key == value))
                if options and (field == "time_format" or (zone is not None and follows_house is False)):
                    editable.add(field)
            if manual_time and zone is not None and not manual_wait:
                editable.add("local_time")
            blocked = {**readonly, **locked}
            editable.difference_update(blocked)
            if saving or not available:
                editable.clear()

            local = now.astimezone(zone) if zone is not None else None
            clock = "%I:%M %p" if values.get("time_format") == "12h" else "%H:%M"
            clock_text = local.strftime(clock) if local else ""
            zone_text = f"Local time: {clock_text}" if local else "Local time is unavailable."
            if follows_house is True:
                zone_text += " · Set by your house"
            resting = {
                "timezone": zone_text,
                "ntp_enabled": _sync_status(values, now),
                "local_time": f"Current date and time: {local:%Y-%m-%d} · {clock_text}" if local else "Local time is unavailable.",
                "time_format": "Clock format is unavailable." if not offered.get("time_format") else "",
            }
            for field, row in controls.items():
                enabled = field in editable
                signal = blocked.get(field, "")
                message = _REFUSALS.get(signal, "This setting can't be changed on this device.") if signal else ""
                message, signal = outcomes.get(field, (message, signal))
                visible = bool(values) and (field != "local_time" or manual_time)
                if field == "local_time":
                    entry.set_sensitive(enabled)
                    button.set_sensitive(enabled)
                    row.set_visible(visible)
                else:
                    alternate, label = alternatives[field]
                    show_alternate = visible and not enabled and (bool(signal) or named[field] == "Unavailable")
                    alternate.set_visible(show_alternate)
                    row.set_visible(visible and not show_alternate)
                    row.set_sensitive(enabled)
                    if show_alternate:
                        label.set_label(named[field])
                        row = alternate
                paint_subtitle(row, resting.get(field, ""), message, signal)
        finally:
            painting = False

    def hydrate(reply):
        nonlocal values, zone, offered, readonly, available, manual_wait
        available = _common._receipt_ok(reply) and isinstance(reply.get("values"), dict)
        read_status.set_title("Couldn't read date and time settings.")
        read_status.set_visible(not available)
        if available:
            values = reply["values"]
            zone = _zone(values.get("timezone"))
            options = reply.get("options")
            offered = {field: _choices(options, field) for field in combos} if isinstance(options, dict) else {}
            reasons = reply.get("readonly")
            readonly = ({field: signal for field, signal in reasons.items() if isinstance(signal, str) and signal}
                        if isinstance(reasons, dict) else {})
            if values.get("ntp_enabled") is not False:
                manual_wait = False
                entry.set_text("")
                outcomes.pop("local_time", None)

    def refresh():
        nonlocal reading
        if reading or saving or manual_wait or not page.get_mapped():
            return
        reading = True
        started = revision

        def complete(reply):
            nonlocal reading
            if revision == started:
                reading = False
                hydrate(reply)
                paint()
            return GLib.SOURCE_REMOVE

        def work():
            GLib.idle_add(complete, _request())

        threading.Thread(target=work, daemon=True).start()

    def outcome(field, message, signal="", delay=0):
        notice = (message, signal)
        outcomes[field] = notice
        if delay:
            def dismiss():
                nonlocal manual_wait, available
                if outcomes.get(field) is notice:
                    del outcomes[field]
                    if field == "local_time" and manual_wait:
                        manual_wait = False
                        # Never re-enable the editor until this read confirms NTP is off.
                        available = False
                        paint()
                        refresh()
                    else:
                        paint()
                return GLib.SOURCE_REMOVE

            GLib.timeout_add(delay, dismiss)

    def save(field, value):
        nonlocal saving, reading, revision
        if painting or saving or field not in editable:
            return
        revision += 1  # An earlier refresh can't paint over the write's readback.
        reading = False
        saving = True
        outcome(field, "Saving…")
        paint()

        def complete(patch, signal, reply):
            nonlocal saving, manual_wait
            if reply is not None:
                hydrate(reply)
            saving = False
            if not _common._receipt_ok(patch):
                if signal in _REFUSALS and signal != _AUTOMATIC_TIME_ON:
                    locked[field] = signal
                message = _REFUSALS.get(signal, "Couldn't save this setting.")
                if field == "local_time" and signal:
                    # A fresh read can hide the manual row when NTP came back
                    # on. Disable its inputs and let the owner read the refusal.
                    manual_wait = True
                    outcome(field, message, signal, delay=8000)
                else:
                    outcome(field, message, signal)
            elif not available:
                outcome(field, "Couldn't confirm the current setting.")
            elif field != "local_time" and values.get(field) != value:
                outcome(field, "The device didn't keep this change.", "settings-readback-mismatch")
            else:
                if field == "local_time":
                    entry.set_text("")
                outcome(field, "Saved", delay=3000)
            paint()
            return GLib.SOURCE_REMOVE

        def work():
            patch = _request("PATCH", {field: value})
            signal = _refusal(patch) if not _common._receipt_ok(patch) else ""
            reply = None if field == "local_time" and signal else _request()
            GLib.idle_add(complete, patch, signal, reply)

        threading.Thread(target=work, daemon=True).start()

    def switch_changed(row, _param, field):
        if row.get_active() != values.get(field):
            save(field, row.get_active())

    def choice_changed(row, _param, field):
        index = row.get_selected()
        entries = selected_options.get(field, ())
        if index < len(entries):
            value, _ = entries[index]
            if value is not None and value != values.get(field):
                save(field, value)

    def set_time(_widget):
        if "local_time" not in editable:
            return
        value = entry.get_text()
        try:
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}", value):
                raise ValueError
            datetime.strptime(value, _WALL_TIME)
        except ValueError:
            outcome("local_time", "Enter a valid date and time as YYYY-MM-DD HH:MM.")
            paint()
            return
        save("local_time", value)

    def minute():
        nonlocal minute_source
        now = datetime.now(timezone.utc)
        paint(now)
        refresh()
        # Anchor each tick to the next wall-clock minute, not to page-open time.
        minute_source = GLib.timeout_add(60_000 - now.second * 1000 - now.microsecond // 1000, minute)
        return GLib.SOURCE_REMOVE

    def unmapped(_page):
        nonlocal minute_source
        if minute_source:
            GLib.source_remove(minute_source)
            minute_source = 0

    for field, row in switches.items():
        row.connect("notify::active", switch_changed, field)
    for field, row in combos.items():
        row.connect("notify::selected", choice_changed, field)
    entry.connect("activate", set_time)
    button.connect("clicked", set_time)
    page.connect("map", lambda _page: minute())
    page.connect("unmap", unmapped)
    return page

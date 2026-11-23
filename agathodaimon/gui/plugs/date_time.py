"""Date and time settings over the Caduceus datetime door."""
from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import _common

PLUG = {"id": "date-time", "title": "Date & Time", "icon": "preferences-system-time-symbolic", "order": 100, "parent": None}
_PATH = "/api/v1/settings/datetime"
_CLOCK_LABELS = {"24h": "24-hour", "12h": "12-hour"}
_WALL_TIME = "%Y-%m-%d %H:%M"
_WALL_SHAPE = r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}"
_AUTOMATIC_TIME_ON = "unsupported:automatic-time-on"
_STANDING = {
    "unsupported:homeserver-keeps-house-time": "Your HomeServer keeps the house's time.",
    "unsupported:bar-clock-override-absent": "This device's clock format can't be changed from Settings.",
}
_REFUSALS = {
    **_STANDING,
    _AUTOMATIC_TIME_ON: "The clock wasn't set because automatic date and time was on.",
    "invalid:local_time:nonexistent": "The clocks change then and skip that time.",
    "invalid:local_time:ambiguous": "The clocks change then and repeat that time.",
}
_REFUSED = "The change didn't finish."
_UNCONFIRMED = "Couldn't confirm this change."
# The shell builds a new widget when the owner returns to this plug. Only
# the pending probe's deadline crosses that boundary, not its GTK source.
_sync_until = 0.0


def _request(method="GET", payload=None):
    try:
        if method == "PATCH":
            # The door may hold the crossing for 180 seconds. Keep the same
            # envelope, but give this write more time than a settings read.
            reply = _common._direct_request(_PATH, method, _common._staff_envelope(_PATH, payload), timeout=185)
        else:
            reply = _common._request(_PATH)
        return reply if isinstance(reply, dict) else {}
    except Exception:
        # Includes failures reading the body of an HTTP error, not just urlopen.
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


def _clock_text(local, mode):
    if mode == "12h":
        return f"{local.hour % 12 or 12:02d}:{local.minute:02d} {'AM' if local.hour < 12 else 'PM'}"
    return local.strftime("%H:%M")


def _wall_text(local, mode):
    return f"{local.date().isoformat()} {_clock_text(local, mode)}"


def _parse_wall(text, mode):
    text = text.strip().upper()
    if not re.fullmatch(_WALL_SHAPE + (r" (AM|PM)" if mode == "12h" else ""), text):
        raise ValueError
    if mode == "12h":
        hour = int(text[11:13])
        if not 1 <= hour <= 12:
            raise ValueError
        hour = hour % 12 + (12 if text.endswith("PM") else 0)
        text = f"{text[:11]}{hour:02d}{text[13:16]}"
    datetime.strptime(text, _WALL_TIME)
    return text


def _sync_status(values, now):
    if values.get("ntp_enabled") is False:
        return "Automatic time is off."
    if values.get("ntp_enabled") is not True:
        return "This device didn't report whether automatic time is on."
    if values.get("ntp_synchronized") is False:
        return "The clock hasn't synchronized yet."
    if values.get("ntp_synchronized") is not True:
        return "This device didn't report its sync status."

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
    # The staff's reason is the refusal to show even when the door adds
    # a familiar signal. A door-only refusal still has its own reason.
    return _common._signal(receipt) or _common._refusal_signal(receipt)


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gio, GLib, Gtk, Pango

    def descendant(widget, kind, css_class=None):
        child = widget.get_first_child()
        while child is not None:
            if isinstance(child, kind) and (not css_class or child.has_css_class(css_class)):
                return child
            found = descendant(child, kind, css_class)
            if found is not None:
                return found
            child = child.get_next_sibling()
        return None

    page = _common._page(Adw, PLUG)
    group = Adw.PreferencesGroup()
    page.add(group)
    switches = {
        "automatic_timezone": Adw.SwitchRow(title="Automatic time zone", use_markup=False),
        "ntp_enabled": Adw.SwitchRow(title="Automatic date and time", use_markup=False),
    }
    zone_picker = Adw.ComboRow(title="Time zone", use_markup=False, enable_search=True)
    zone_picker.set_expression(Gtk.PropertyExpression.new(Gtk.StringObject.__gtype__, None, "string"))
    zone_picker.set_search_match_mode(Gtk.StringFilterMatchMode.SUBSTRING)
    # Adwaita supplies the filter and list; keep the search text and the filter
    # in step on Escape, and allow Enter from the search entry itself.
    popover = descendant(zone_picker, Gtk.Popover)
    search = descendant(popover, Gtk.SearchEntry) if popover is not None else None
    results = descendant(popover, Gtk.ListView) if popover is not None else None
    if popover is not None and search is not None and results is not None:
        def search_enter(widget):
            widget.emit("search-changed")
            model = results.get_model()
            if model is not None and model.get_selected_item() is not None:
                results.emit("activate", model.get_selected())

        def search_escape(_controller, key, _code, _state):
            if key != Gdk.KEY_Escape:
                return False
            if search.get_text():
                search.set_text("")
                search.emit("search-changed")
                search.grab_focus()
            else:
                popover.popdown()
            return True

        keys = Gtk.EventControllerKey()
        keys.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        keys.connect("key-pressed", search_escape)
        popover.add_controller(keys)
        popover.connect("map", lambda _popover: search.grab_focus())
        search.connect("activate", search_enter)

    manual = Adw.ActionRow(title="Date and time", use_markup=False, focusable=True)
    entry = Gtk.Entry(width_chars=21, valign=Gtk.Align.CENTER)
    entry.update_property([Gtk.AccessibleProperty.LABEL], ["New local date and time"])
    button = Gtk.Button(label="Set", valign=Gtk.Align.CENTER)
    manual.add_suffix(entry)
    manual.add_suffix(button)

    # A MenuButton keeps the current value out of the choices; a ComboRow
    # auto-selects the first item and cannot present a null value honestly.
    clock = Adw.ActionRow(title="Clock", use_markup=False)
    clock_button = Gtk.MenuButton(valign=Gtk.Align.CENTER, always_show_arrow=True)
    clock.add_suffix(clock_button)
    clock.set_activatable_widget(clock_button)
    clock_actions = Gio.SimpleActionGroup()
    clock_action = Gio.SimpleAction.new_stateful("pick", GLib.VariantType.new("s"), GLib.Variant("s", ""))
    clock_actions.add_action(clock_action)
    clock_button.insert_action_group("clock", clock_actions)

    controls = {
        "automatic_timezone": switches["automatic_timezone"],
        "timezone": zone_picker,
        "ntp_enabled": switches["ntp_enabled"],
        "local_time": manual,
        "time_format": clock,
    }
    alternatives = {}
    for field, row in controls.items():
        row.set_visible(False)
        group.add(row)
        if field != "local_time":
            # A locked control has a focusable, non-activatable twin so the
            # owner can still read and select a refusal without acting again.
            alternate = Adw.ActionRow(title=row.get_title(), use_markup=False, focusable=True)
            label = Gtk.Label(valign=Gtk.Align.CENTER)
            alternate.add_suffix(label)
            alternate.set_visible(False)
            group.add(alternate)
            alternatives[field] = (alternate, label)
    read_status = Adw.ActionRow(title="Reading date and time…", focusable=True)
    group.add(read_status)

    values: dict[str, Any] = {}
    offered: dict[str, dict[str, str]] = {}
    readonly: dict[str, str] = {}
    locked: dict[str, str] = {}
    outcomes: dict[str, tuple[str, str, bool]] = {}
    editable = set()
    zone = None
    zone_entries: tuple[tuple[str, str], ...] = ()
    clock_entries: tuple[tuple[str, str], ...] = ()
    focus_return: str | None = None
    pending: tuple[str, Any] | None = None
    dirty = painting = reading = available = False
    recheck_lost = False
    revision = minute_source = sync_source = 0
    last_read = 0.0

    def paint_subtitle(row, resting, message, signal):
        text = "\n".join(filter(None, (resting, message, signal)))
        if row.get_subtitle() == text:
            return
        row.set_subtitle(text)
        label = descendant(row, Gtk.Label, "subtitle")
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
        nonlocal painting, zone_entries, clock_entries, focus_return
        painting = True
        try:
            now = now or datetime.now(timezone.utc)
            root = page.get_root()
            focus = root.get_focus() if root is not None else None

            def has_focus(widget, current=focus):
                return current is not None and (current == widget or current.is_ancestor(widget))

            display = dict(values)
            if pending is not None:
                display[pending[0]] = pending[1]
            follows_house = values.get("automatic_timezone")
            manual_time = available and values.get("ntp_enabled") is False
            blocked = {**readonly, **locked}
            named = {}
            resting = {}
            editable.clear()
            for field, row in switches.items():
                value = display.get(field)
                row.set_active(value is True)
                if isinstance(value, bool):
                    named[field] = "On" if value else "Off"
                    editable.add(field)
                else:
                    named[field] = "Not reported"
            resting["automatic_timezone"] = ("This device didn't report whether it follows the house."
                                              if not isinstance(values.get("automatic_timezone"), bool) else "")
            resting["ntp_enabled"] = _sync_status(values, now)

            zone_options = offered.get("timezone", {})
            zone_key = display.get("timezone")
            zone_name = zone_options.get(zone_key, zone_key.replace("_", " ")) if isinstance(zone_key, str) and zone else "Not reported"
            named["timezone"] = zone_name
            zones = tuple(zone_options.items())
            if zone is not None and isinstance(zone_key, str) and zone_key not in zone_options:
                zones = ((zone_key, zone_name), *zones)
            if zones != zone_entries:
                zone_entries = zones
                zone_picker.set_model(Gtk.StringList.new([label for _, label in zones]))
            if zones:
                index = next((i for i, (key, _) in enumerate(zones) if key == zone_key), 0)
                if zone_picker.get_selected() != index:
                    zone_picker.set_selected(index)
            if zone is not None and follows_house is False and len(zones) > 1:
                editable.add("timezone")

            clock_format = display.get("time_format")
            clock_reported = "time_format" in values
            clocks = tuple(offered.get("time_format", {}).items())
            if clocks != clock_entries:
                clock_entries = clocks
                menu = Gio.Menu()
                for key, name in clocks:
                    item = Gio.MenuItem.new(name, None)
                    item.set_action_and_target_value("clock.pick", GLib.Variant("s", key))
                    menu.append_item(item)
                clock_button.set_menu_model(menu)
            # Empty state matches no menu target. An activation asks to save;
            # only a confirmed read changes which menu item is marked.
            marked_format = values.get("time_format") or ""
            if clock_action.get_state().get_string() != marked_format:
                clock_action.set_state(GLib.Variant("s", marked_format))
            clock_name = "Not set" if clock_reported else "Not reported"
            if isinstance(clock_format, str):
                clock_name = dict(clocks).get(clock_format, _CLOCK_LABELS[clock_format])
            named["time_format"] = clock_name
            if clock_button.get_label() != clock_name:
                clock_button.set_label(clock_name)
            if clock_reported and clocks:
                editable.add("time_format")
            if not clock_reported:
                resting["time_format"] = "This device didn't report its clock format."
            elif not clocks:
                resting["time_format"] = "This device doesn't offer clock formats."

            local = now.astimezone(zone) if zone is not None else None
            mode = values.get("time_format")
            wall = _wall_text(local, mode) if local is not None else ""
            shown_zone = _zone(zone_key) if pending is not None and pending[0] == "timezone" else zone
            shown_time = now.astimezone(shown_zone) if shown_zone is not None else None
            zone_text = (f"Local time: {_clock_text(shown_time, mode)}" if shown_time is not None
                         else "This device didn't report a time zone.")
            if follows_house is True:
                zone_text += " · Set by your house"
            elif follows_house is not False and zone is not None:
                zone_text += " · This device didn't report how the zone is set."
            elif zone is not None and len(zones) <= 1:
                zone_text += " · No other time zones were reported."
            resting["timezone"] = zone_text
            resting["local_time"] = f"Current date and time: {wall}" if wall else "This device didn't report a time zone."
            if manual_time and local is not None:
                editable.add("local_time")
                hint = "YYYY-MM-DD HH:MM AM/PM" if mode == "12h" else "YYYY-MM-DD HH:MM"
                if entry.get_placeholder_text() != hint:
                    entry.set_placeholder_text(hint)
                if not dirty and (pending is None or pending[0] != "local_time") and entry.get_text() != wall:
                    position = entry.get_position()
                    anchor = entry.get_property("selection-bound")
                    entry.set_text(wall)
                    entry.select_region(min(anchor, len(wall)), min(position, len(wall)))

            editable.difference_update(blocked)
            if not available:
                editable.clear()
            busy_field = pending[0] if pending is not None else None
            busy = busy_field is not None
            for field, row in switches.items():
                row.set_activatable(field in editable and not busy)
            zone_picker.set_activatable("timezone" in editable and not busy)
            clock.set_activatable("time_format" in editable and not busy)
            clock_action.set_enabled("time_format" in editable and not busy)

            # Take focus from a row only if it is disappearing. Ordinary saves
            # use activatability and a dispatch gate, not widget sensitivity.
            focused_field = None
            visible_rows = {}
            if not available:
                read_status.set_visible(True)
            for field, row in controls.items():
                twin = alternatives.get(field)
                if has_focus(row) or (twin is not None and has_focus(twin[0])):
                    focused_field = field
                enabled = field in editable
                signal = blocked.get(field, "") if available else ""
                message = _REFUSALS.get(signal, "This setting can't be changed on this device.") if signal else ""
                message, signal, _saved = outcomes.get(field, (message, signal, False))
                if busy_field == field:
                    message, signal = "Saving…", ""
                if field == "local_time":
                    visible = manual_time
                    if not visible and has_focus(manual):
                        target = visible_rows.get("ntp_enabled")
                        if target is None and not available:
                            target = read_status
                        if target is not None:
                            target.grab_focus()
                    entry.set_sensitive(enabled)
                    entry.set_editable(enabled and not busy)
                    button.set_sensitive(enabled)
                else:
                    alternate, label = alternatives[field]
                    visible = available or field in outcomes
                    if not enabled and visible:
                        alternate.set_visible(True)
                        label.set_label(named[field] if available else "")
                        visible_rows[field] = alternate
                    alternate.set_visible(visible and not enabled)
                    visible = visible and enabled
                row.set_visible(visible)
                if visible:
                    visible_rows[field] = row
                if field in visible_rows:
                    hide_sync = field == "ntp_enabled" and busy_field == field
                    shown_text = resting.get(field, "") if available and not hide_sync else ""
                    paint_subtitle(visible_rows[field], shown_text, message, signal)

            if focused_field is not None:
                target = visible_rows.get(focused_field)
                if target is None:
                    if focused_field == "local_time":
                        target = visible_rows.get("ntp_enabled")
                    if target is None and not available:
                        focus_return = focused_field
                        target = read_status
                if target is not None and root is not None and not has_focus(target, root.get_focus()):
                    target.grab_focus()
            elif available and has_focus(read_status) and focus_return is not None:
                target = visible_rows.get(focus_return) or visible_rows.get("ntp_enabled")
                if target is not None:
                    target.grab_focus()
                focus_return = None
            read_status.set_visible(not available)
        finally:
            painting = False

    def hydrate(reply):
        nonlocal values, zone, offered, readonly, available, last_read
        last_read = time.monotonic()
        actual = reply.get("values") if _common._receipt_ok(reply) else None
        found_zone = _zone(actual.get("timezone")) if isinstance(actual, dict) else None
        # Today's older reply still reports the zone and NTP switch. Missing
        # optional fields get their own reasons, not guesses at current values.
        available = isinstance(actual, dict) and (found_zone is not None or isinstance(actual.get("ntp_enabled"), bool))
        read_status.set_title("Couldn't read date and time settings.")
        if not available or not isinstance(actual, dict):
            values, offered, readonly, zone = {}, {}, {}, None
            # A minute retry can fail while a save's failure is still being
            # read. Keep its timer, but don't show old successes as current.
            for field, notice in tuple(outcomes.items()):
                if notice[2]:
                    del outcomes[field]
            return
        values, zone = dict(actual), found_zone
        mode = values.get("time_format")
        if mode is not None and (not isinstance(mode, str) or mode not in _CLOCK_LABELS):
            values.pop("time_format", None)
        for field in ("automatic_timezone", "ntp_enabled", "ntp_synchronized"):
            if not isinstance(values.get(field), bool):
                values.pop(field, None)
        options = reply.get("options")
        offered = {field: _choices(options, field) for field in ("timezone", "time_format")} if isinstance(options, dict) else {}
        reasons = reply.get("readonly")
        readonly = ({field: signal for field, signal in reasons.items() if isinstance(signal, str) and signal}
                    if isinstance(reasons, dict) else {})
        if values.get("ntp_enabled") is not False:
            outcomes.pop("local_time", None)

    def background(work, complete):
        def run():
            result = None
            try:
                result = work()
            except Exception:
                pass
            finally:
                GLib.idle_add(complete, result)

        started = False
        try:
            threading.Thread(target=run, daemon=True).start()
            started = True
        except Exception:
            pass
        finally:
            if not started:
                complete(None)

    def refresh():
        nonlocal reading
        if reading or pending is not None or not page.get_mapped():
            return False
        reading = True
        started = revision

        def complete(reply):
            nonlocal reading
            if revision == started:
                reading = False
                hydrate(reply or {})
                resume_probe()
                paint()
            return GLib.SOURCE_REMOVE

        background(_request, complete)
        return True

    def outcome(field, message, signal="", saved=False):
        notice = (message, signal, saved)
        outcomes[field] = notice

        def dismiss():
            if outcomes.get(field) is notice:
                del outcomes[field]
                paint()
            return GLib.SOURCE_REMOVE

        GLib.timeout_add(3000 if saved else 8000, dismiss)

    def can_probe():
        return (page.get_mapped() and available and time.monotonic() < _sync_until
                and values.get("ntp_enabled") is True and values.get("ntp_synchronized") is not True)

    def probe_sync():
        nonlocal sync_source
        if not can_probe():
            sync_source = 0
            return GLib.SOURCE_REMOVE
        refresh()
        return GLib.SOURCE_CONTINUE

    def stop_probe():
        nonlocal sync_source
        if sync_source:
            GLib.source_remove(sync_source)
            sync_source = 0

    def resume_probe():
        global _sync_until
        nonlocal sync_source
        if page.get_mapped() and (values.get("ntp_enabled") is False or values.get("ntp_synchronized") is True):
            _sync_until = 0.0
        if not can_probe():
            stop_probe()
        elif not sync_source:
            sync_source = GLib.timeout_add(15_000, probe_sync)

    def can_save(field):
        return not painting and pending is None and field in editable

    def save(field, value):
        nonlocal pending, reading, revision
        if not can_save(field):
            return
        revision += 1  # Ignore a refresh that began before this write.
        reading = False
        attempt = pending = (field, value)
        outcomes.pop(field, None)
        paint()

        def complete(result):
            global _sync_until
            nonlocal pending, dirty, recheck_lost
            if pending is not attempt:
                return GLib.SOURCE_REMOVE
            pending = None
            patch, reply, read_at = result or ({}, {}, datetime.now(timezone.utc))
            hydrate(reply)
            destination = field
            if field == "local_time" and values.get("ntp_enabled") is not False:
                destination = "ntp_enabled"
            ok = _common._receipt_ok(patch)
            signal = "" if ok else _refusal(patch)
            if not ok and (patch.get("ok") is False or signal):
                if signal in _STANDING:
                    locked[field] = signal
                outcome(destination, _REFUSALS.get(signal, _REFUSED), signal)
            else:
                if not ok:
                    recheck_lost = True
                    # Only an absent verdict is inferred from the fresh read.
                    # The GET has no local_time field; compare native wall time.
                    if field == "local_time":
                        ok = (zone is not None and values.get("ntp_enabled") is False
                              and _wall_text(read_at.astimezone(zone), "24h") == value)
                    else:
                        ok = available and values.get(field) == value
                if ok:
                    if field == "local_time":
                        dirty = False
                    outcome(destination, "Time set." if destination != field else "Saved", saved=True)
                    if field == "ntp_enabled":
                        stop_probe()
                        _sync_until = (time.monotonic() + 60 if value is True
                                       and values.get("ntp_enabled") is not False
                                       and values.get("ntp_synchronized") is not True else 0.0)
                else:
                    outcome(destination, _UNCONFIRMED)
            resume_probe()
            paint()
            return GLib.SOURCE_REMOVE

        def work():
            patch = _request("PATCH", {field: value})
            reply = _request()
            return patch, reply, datetime.now(timezone.utc)

        background(work, complete)

    def switch_changed(row, _param, field):
        if painting or (row.get_active() == values.get(field) and pending is None):
            return
        if can_save(field):
            save(field, row.get_active())
        else:
            paint()

    def zone_changed(row, _param):
        index = row.get_selected()
        if painting or index >= len(zone_entries):
            return
        value, _ = zone_entries[index]
        if can_save("timezone") and value != values.get("timezone"):
            # The popover can unmap while GtkRoot still points at its search
            # entry. Return keyboard focus to the visible picker before saving.
            root = row.get_root()
            focus = root.get_focus() if root is not None else None
            if root is not None and (focus is None or (focus != row and focus.is_ancestor(row))):
                row.grab_focus()
            save("timezone", value)
        elif pending is not None:
            paint()

    def clock_chosen(_action, parameter):
        value = parameter.get_string()
        if value in offered.get("time_format", {}) and value != values.get("time_format"):
            save("time_format", value)

    def clock_opened(widget, _param):
        if widget.get_active() and not can_save("time_format"):
            widget.popdown()

    def entry_changed(_entry):
        nonlocal dirty
        if not painting:
            dirty = True

    def set_time(_widget):
        if not can_save("local_time"):
            return
        mode = values.get("time_format")
        try:
            value = _parse_wall(entry.get_text(), mode)
        except ValueError:
            example = "2026-11-23 04:30 PM" if mode == "12h" else "2026-11-23 16:30"
            outcome("local_time", f"Enter a date and time like {example}.")
            paint()
            return
        save("local_time", value)

    def minute(*, on_show=False):
        nonlocal minute_source, recheck_lost
        now = datetime.now(timezone.utc)
        # Re-arm before painting or reading. The local minute tick is not a GET.
        minute_source = GLib.timeout_add(60_000 - now.second * 1000 - now.microsecond // 1000, minute)
        paint(now)
        if on_show:
            refresh()
        elif recheck_lost or not available or time.monotonic() - last_read >= 600:
            if refresh():
                recheck_lost = False
        return GLib.SOURCE_REMOVE

    def shown(_page):
        minute(on_show=True)

    def unmapped(_page):
        nonlocal minute_source
        if minute_source:
            GLib.source_remove(minute_source)
            minute_source = 0
        stop_probe()

    for field, row in switches.items():
        row.connect("notify::active", switch_changed, field)
    zone_picker.connect("notify::selected", zone_changed)
    clock_action.connect("activate", clock_chosen)
    clock_button.connect("notify::active", clock_opened)
    entry.connect("changed", entry_changed)
    entry.connect("activate", set_time)
    button.connect("clicked", set_time)
    page.connect("map", shown)
    page.connect("unmap", unmapped)
    return page

"""Energy & Power renders the rows carried by the settings door."""
from __future__ import annotations

import threading

try:
    from . import _common
except ImportError:
    import _common


PLUG = {"id": "energy-power", "title": "Energy & Power", "icon": "battery-symbolic", "order": 97, "parent": None}
_PATH = "/api/v1/settings/energy"
_POWER_BUTTON = [("poweroff", "Shut down"), ("suspend", "Suspend"), ("ignore", "Do nothing")]
_SCREEN_TIMES = [(0, "Never"), (300, "5 minutes"), (600, "10 minutes"), (900, "15 minutes"),
                 (1800, "30 minutes"), (3600, "1 hour")]


def _screen_label(value: int) -> str:
    known = dict(_SCREEN_TIMES).get(value)
    if known:
        return known
    if value % 60 == 0:
        minutes = value // 60
        return f"{minutes} minute" if minutes == 1 else f"{minutes} minutes"
    return f"{value} second" if value == 1 else f"{value} seconds"


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk, Pango

    page = _common._page(Adw, PLUG)
    group = _common._group(Adw, page, "")
    power_button = Adw.ComboRow(title="Power button action")
    profile = Adw.ComboRow(title="Power profile")
    screen = Adw.ComboRow(title="Turn screen off after")
    charge_limit = Adw.SwitchRow(title="Charge limit", subtitle="Reduces the maximum battery charge")

    def value_row(title, subtitle=""):
        row = Adw.ActionRow(title=title, subtitle=subtitle)
        value = Gtk.Label(valign=Gtk.Align.CENTER)
        row.add_suffix(value)
        return row, value

    screen_readonly, screen_value = value_row("Turn screen off after")
    sleep = Adw.ActionRow(title="Sleep")
    level, level_value = value_row("Battery level")
    battery, battery_value = value_row("Battery state")
    lid, lid_value = value_row("Lid action", "Set by the system")
    combos = {"power_button_action": power_button, "power_profile": profile, "screen_off_seconds": screen}
    controls = {**combos, "charge_limit": charge_limit}
    # If an edited control becomes unavailable, its refusal still needs a
    # selectable subtitle; an insensitive widget can't receive text selection.
    unavailable = {field: value_row(row.get_title()) for field, row in controls.items()}
    read_status = Adw.ActionRow(title="Reading Energy & Power…", use_markup=False)
    fields_by_row = {row: field for field, row in controls.items()}
    for row in (power_button, profile, screen, screen_readonly, sleep, level, battery, charge_limit, lid):
        row.set_visible(False)
        group.add(row)
        if row in fields_by_row:
            alternate, _ = unavailable[fields_by_row[row]]
            alternate.set_visible(False)
            group.add(alternate)
    group.add(read_status)

    choice_values = {}
    editable = set()
    values = {}
    busy = False
    last_read = None
    tv = _common._json("/etc/appliance/profile.json").get("profile") in {"tv", "hometv"}
    base_subtitles = {row: row.get_subtitle() for row in (*controls.values(), screen_readonly)}
    outcomes = {}

    def style_subtitle(widget, detail_at):
        child = widget.get_first_child()
        while child is not None:
            if isinstance(child, Gtk.Label) and child.has_css_class("subtitle"):
                attributes = None
                if detail_at is not None:
                    attributes = Pango.AttrList()
                    small = Pango.attr_scale_new(0.83)
                    small.start_index = detail_at
                    attributes.insert(small)
                child.set_attributes(attributes)
                child.set_selectable(detail_at is not None)
            else:
                style_subtitle(child, detail_at)
            child = child.get_next_sibling()

    def paint_outcome(field):
        readonly_screen = field == "screen_off_seconds" and screen_readonly.get_visible()
        row = screen_readonly if readonly_screen else controls[field]
        message, signal, _ = outcomes.get(field, (base_subtitles[row], "", None))
        alternate, alternate_value = unavailable[field]
        needs_alternate = bool(signal) and not readonly_screen and field not in editable
        alternate.set_visible(needs_alternate)
        if not readonly_screen:
            row.set_visible(not needs_alternate and (field != "charge_limit" or field in values))
        if needs_alternate:
            current = values.get(field)
            if field == "charge_limit":
                label = ("On" if current else "Off") if isinstance(current, bool) else "Unavailable"
            else:
                label = row.get_model().get_string(row.get_selected())
            alternate_value.set_label(label or "Unavailable")
            row = alternate
        # Keep options and signals literal. ComboRow disables Pango markup
        # by default; style only the signal's byte range on the subtitle label.
        row.set_use_markup(False)
        row.set_subtitle(message + "\n" + signal if signal else message)
        style_subtitle(row, len((message + "\n").encode()) if signal else None)

    def show_outcome(field, message, signal="", *, temporary=False):
        token = object()
        outcomes[field] = (message, signal, token)
        paint_outcome(field)
        if temporary:
            def dismiss():
                if outcomes.get(field, (None, None, None))[2] is token:
                    del outcomes[field]
                    paint_outcome(field)
                return False

            GLib.timeout_add(3000, dismiss)

    def set_choices(field, entries, current, missing="Unavailable", *, extra_label=None):
        entries = list(entries)
        if current not in {value for value, _ in entries}:
            entries.insert(0, (current, extra_label or missing))
        ids, labels = zip(*entries)
        choice_values[field] = ids
        row = combos[field]
        row.set_model(Gtk.StringList.new(list(labels)))
        row.set_selected(ids.index(current))
        if current is not None and len(ids) > 1:
            editable.add(field)

    def hydrate(reply):
        nonlocal values
        editable.clear()
        values = reply["values"]
        readonly = reply.get("readonly")
        readonly = readonly if isinstance(readonly, dict) else {}
        options = reply.get("options")
        offered = options.get("power_profile") if isinstance(options, dict) else None
        offered = [item for item in offered if isinstance(item, dict) and isinstance(item.get("value"), str)
                   and isinstance(item.get("label"), str)] if isinstance(offered, list) else []

        power_action = values.get("power_button_action")
        set_choices("power_button_action", _POWER_BUTTON, power_action if isinstance(power_action, str) else None)
        profile_value = values.get("power_profile")
        set_choices("power_profile", [(item["value"], item["label"]) for item in offered],
                    profile_value if isinstance(profile_value, str) else None)
        if not offered or profile_value is None:
            base_subtitles[profile] = "The power profile service is unavailable"
        else:
            base_subtitles[profile] = "This setting only affects the processor" if any(item.get("cpu_only") is True for item in offered) else ""
        power_button.set_visible(True)
        profile.set_visible(True)

        seconds = values.get("screen_off_seconds")
        seconds = seconds if type(seconds) is int and seconds >= 0 else None
        reason = readonly.get("screen_off_seconds")
        reason = reason if isinstance(reason, str) else None
        screen.set_visible(not reason)
        screen_readonly.set_visible(bool(reason))
        if reason:
            base_subtitles[screen_readonly] = _common._SWAY_ONLY_REASON if reason in _common._SWAY_ONLY_SIGNALS else "Set by the system"
            screen_value.set_label(_screen_label(seconds) if seconds is not None else "Unavailable")
        else:
            set_choices("screen_off_seconds", _SCREEN_TIMES, seconds, "Current timeout unavailable",
                        extra_label=_screen_label(seconds) if seconds is not None else None)

        has_battery = "battery_level" in values or "battery_state" in values
        sleep.set_subtitle("This TV does not sleep" if tv and not has_battery else "Sleep is set by the system")
        sleep.set_visible(True)
        level.set_visible("battery_level" in values)
        battery.set_visible("battery_state" in values)
        lid.set_visible("lid_action" in values)
        percent = values.get("battery_level")
        level_value.set_label(f"{percent}%" if type(percent) is int and 0 <= percent <= 100 else "Unavailable")
        state = values.get("battery_state")
        battery_value.set_label(state if isinstance(state, str) and state else "Unavailable")
        action = values.get("lid_action")
        lid_value.set_label(dict(_POWER_BUTTON).get(action, action.replace("-", " ").capitalize())
                            if isinstance(action, str) and action else "Unavailable")
        charge_limit.set_visible("charge_limit" in values)
        limit = values.get("charge_limit")
        if isinstance(limit, bool):
            charge_limit.set_active(limit)
            base_subtitles[charge_limit] = "Reduces the maximum battery charge"
            editable.add("charge_limit")
        else:
            base_subtitles[charge_limit] = "Couldn't read the charge limit"
        editable.difference_update(readonly)
        for key, control in controls.items():
            control.set_sensitive(key in editable)
            paint_outcome(key)

    def complete(reply, field, desired, patch_reply):
        nonlocal busy, last_read
        read_ok = _common._receipt_ok(reply) and isinstance(reply.get("values"), dict)
        if read_ok:
            last_read = reply
        if last_read is None:
            read_status.set_title("Couldn't read Energy & Power")
            read_status.set_visible(True)
            busy = False
            return False
        read_status.set_visible(False)
        hydrate(last_read)
        if field is not None:
            signal = _common._refusal_signal(patch_reply)
            staff_signal = _common._signal(patch_reply)
            if not _common._receipt_ok(patch_reply):
                if signal in _common._SWAY_ONLY_SIGNALS or staff_signal in _common._SWAY_ONLY_SIGNALS:
                    message = _common._SWAY_ONLY_REASON + "."
                else:
                    message = "Couldn't save this setting." if read_ok else "Couldn't save or confirm this setting."
                show_outcome(field, message, signal)
            elif not read_ok:
                show_outcome(field, "Couldn't confirm the current setting.")
            elif field not in editable or values.get(field) != desired:
                show_outcome(field, "The device didn't keep this change.", "settings-readback-mismatch")
            else:
                show_outcome(field, "Saved", temporary=True)
        busy = False
        return False

    def refresh(field=None, desired=None):
        nonlocal busy
        if busy:
            return
        busy = True
        for control in controls.values():
            control.set_sensitive(False)
        if field is not None:
            show_outcome(field, "Saving…")

        def work():
            patch_reply = {}
            if field is not None:
                try:
                    patch_reply = _common._request(_PATH, "PATCH", {field: desired})
                except RuntimeError:
                    pass
            try:
                if field is None:
                    routes = _common._request("/api/v1/doors").get("routes")
                    if not isinstance(routes, list) or _PATH not in routes:
                        raise RuntimeError("Settings door unavailable")
                reply = _common._request(_PATH)
            except RuntimeError:
                reply = {}
            GLib.idle_add(complete, reply, field, desired, patch_reply)

        threading.Thread(target=work, daemon=True).start()

    def changed(control, _param, field):
        if busy or field not in editable:
            return
        if field == "charge_limit":
            value = control.get_active()
        else:
            index = control.get_selected()
            choices = choice_values[field]
            if not 0 <= index < len(choices):
                return
            value = choices[index]
        if value is not None and value != values.get(field):
            refresh(field, value)

    for field, row in combos.items():
        row.connect("notify::selected", changed, field)
    charge_limit.connect("notify::active", changed, "charge_limit")
    refresh()
    return page

"""Shared helpers for appliance settings plugs."""
from __future__ import annotations

import configparser
import json
import math
import os
import subprocess
import threading
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

def _caduceus_url() -> str:
    configured = os.environ.get("CADUCEUS_URL")
    if configured:
        return configured.rstrip("/")
    try:
        from agathodaimon._load_trace import _caduceus_base_url
        return _caduceus_base_url()
    except (OSError, ValueError, KeyError, TypeError):
        return "http://127.0.0.1:3014"


CADUCEUS_URL = _caduceus_url()


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
    """Retain the read-only plug fallback for panes without an admitted door."""
    row = Adw.ActionRow(title=title, subtitle="Awaiting Caduceus door")
    control = Gtk.Entry()
    control.set_editable(False)
    control.set_sensitive(False)
    control.set_placeholder_text("Unavailable")
    row.add_suffix(control)
    row.set_sensitive(False)
    group.add(row)


def _staff_envelope(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        'schema': 'caduceus.staff.v1',
        'intent_id': f'agathodaimon-gui-{uuid.uuid4()}',
        'transition': path,
        'target': 'dark',
    }
    if payload is not None:
        envelope['payload'] = payload
    return envelope


def _request(path: str, method: str = 'GET', payload: dict[str, Any] | None = None,
             *, headers: dict[str, str] | None = None) -> dict[str, Any]:
    data = json.dumps(_staff_envelope(path, payload)).encode('utf-8')
    request_headers = {'Content-Type': 'application/json', **(headers or {})}
    request = urllib.request.Request(CADUCEUS_URL + path, data=data, headers=request_headers, method=method)

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(256 * 1024)
    except urllib.error.HTTPError as error:
        raw = error.read(256 * 1024)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError(f'Caduceus refused with HTTP {error.code}') from error
        if isinstance(value, dict):
            return value
        raise RuntimeError(f'Caduceus refused with HTTP {error.code}') from error
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError('Caduceus is unavailable') from error
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError('Caduceus returned an unreadable receipt') from error
    if not isinstance(value, dict):
        raise RuntimeError('Caduceus returned an invalid receipt')
    return value


def _direct_request(path: str, method: str = "GET", payload: dict[str, Any] | None = None,
                    timeout: int = 30) -> dict[str, Any]:
    """Call a native Caduceus door without a staff envelope."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(CADUCEUS_URL + path, data=data, headers=headers, method=method)
    try:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read(256 * 1024)
        except urllib.error.HTTPError as error:
            if method == "GET":
                raise RuntimeError("Caduceus read refused") from error
            raw = error.read(256 * 1024)
        value = json.loads(raw)
    except (OSError, urllib.error.URLError, ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("Caduceus is unavailable or returned an unreadable response") from error
    if not isinstance(value, dict):
        raise RuntimeError("Caduceus returned an invalid response")
    return value


def _signal(receipt: dict[str, Any]) -> str:
    value = receipt.get("firstMissingSignal", receipt.get("first_missing_signal", ""))
    return value if isinstance(value, str) and value != "none" else ""


# A door verdict rides beside the stop's receipt.
def _refusal_signal(receipt: dict[str, Any]) -> str:
    value = receipt.get("doorSignal")
    return value if isinstance(value, str) and value and value != "none" else _signal(receipt)


def _receipt_ok(receipt: dict[str, Any]) -> bool:
    return receipt.get("ok") is True and receipt.get("doorSignal", "none") == "none"

def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _number(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return fallback


def add_manager_row(page: Any, title: str, button_text: str, program: str) -> None:
    """Ask the admitted face door to toggle a manager, then show its receipt."""
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    group = Adw.PreferencesGroup()
    page.add(group)
    row = Adw.ActionRow(title=title, subtitle="Checking Caduceus door…")
    button = Gtk.Button(label=button_text, valign=Gtk.Align.CENTER)
    button.set_sensitive(False)
    row.add_suffix(button)
    group.add(row)

    def checked(message: str, enabled: bool) -> bool:
        row.set_subtitle(message)
        button.set_sensitive(enabled)
        return False

    def discover() -> None:
        try:
            doors = _request("/api/v1/doors")
            routes = doors.get("routes")
            present = isinstance(routes, list) and "/api/v1/face/app" in routes
            GLib.idle_add(checked, "Ready" if present else "Manager door unavailable", present)
        except RuntimeError as error:
            GLib.idle_add(checked, str(error), False)

    def toggle() -> None:
        try:
            data = json.dumps({"id": program, "action": "toggle"}).encode("utf-8")
            request = urllib.request.Request(CADUCEUS_URL + "/api/v1/face/app", data=data,
                                             headers={"Content-Type": "application/json"}, method="POST")
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    raw = response.read(256 * 1024)
            except urllib.error.HTTPError as error:
                raw = error.read(256 * 1024)
            receipt = json.loads(raw)
            if not isinstance(receipt, dict):
                raise ValueError("invalid receipt")
            if receipt.get("ok") is True:
                running = receipt.get("running")
                message = "Opened" if running is True else "Closed" if running is False else "Request completed"
            else:
                message = _refusal_signal(receipt) or "Manager request refused"
        except (OSError, urllib.error.URLError, ValueError, UnicodeDecodeError) as error:
            message = f"Manager unavailable: {error}"
        GLib.idle_add(checked, message, True)

    def on_click(_button: Any) -> None:
        button.set_sensitive(False)
        row.set_subtitle("Waiting for Caduceus receipt…")
        threading.Thread(target=toggle, daemon=True).start()

    button.connect("clicked", on_click)
    threading.Thread(target=discover, daemon=True).start()


_SWAY_ONLY_SIGNALS = {"sway-session-unavailable", "unsupported:sway-session-unavailable"}
_SWAY_ONLY_REASON = "Changes apply on Sway machines"
_SLIDER_WRITE_INTERVAL_US = 300_000
_SLIDER_SETTLE_MS = 150


class _LiveSlider:
    """Coalesce GTK motion into serial writes; read back once the hand is idle."""

    def __init__(self, Gtk: Any, Gdk: Any, GLib: Any, spec: dict[str, Any], send: Any, refresh: Any):
        self.glib = GLib
        self.send = send
        self.refresh = refresh
        self.digits = int(spec.get("digits", 0))
        lower, upper = float(spec["minimum"]), float(spec["maximum"])
        step = float(spec.get("step", 1))
        page = float(spec.get("page", step * 10))
        self.scale = scale = Gtk.Scale.new(Gtk.Orientation.HORIZONTAL, Gtk.Adjustment(
            value=lower, lower=lower, upper=upper, step_increment=step, page_increment=page,
        ))
        scale.set_hexpand(True)
        scale.set_valign(Gtk.Align.CENTER)
        scale.set_size_request(280, -1)
        scale.set_focusable(True)
        scale.set_digits(self.digits)
        scale.set_draw_value(True)
        scale.update_property([Gtk.AccessibleProperty.LABEL], [spec["title"]])
        marks = []
        for item in spec.get("marks", ()):
            value, label = (item["value"], item.get("label")) if isinstance(item, dict) else (item, None)
            scale.add_mark(value, Gtk.PositionType.BOTTOM, GLib.markup_escape_text(label) if label else None)
            marks.append(value)
        self.snap_marks = marks if spec.get("snap") else []

        self.dragging = self.drag_changed = False
        self.held_keys: set[int] = set()
        self.pending = self.in_flight = self.readback_pending = False
        self.send_source = self.settle_source = self.last_send = 0

        # Observe the pointer stream without claiming Gtk.Range's native drag gesture.
        pointer = Gtk.EventControllerLegacy.new()
        pointer.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        pointer.connect("event", self._pointer_event, Gdk)
        scale.add_controller(pointer)

        keys = Gtk.EventControllerKey.new()
        keys.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
        moves = {getattr(Gdk, "KEY_" + prefix + key): (delta, snap_move) for prefix in ("", "KP_")
                 for key, delta, snap_move in (("Left", -step, "previous"), ("Right", step, "next"),
                                               ("Up", step, "next"), ("Down", -step, "previous"),
                                               ("Page_Up", page, "last"), ("Page_Down", -page, "first"))}
        keys.connect("key-pressed", self._key_pressed, moves)
        keys.connect("key-released", self._key_released)
        focus = Gtk.EventControllerFocus.new()

        def focus_in(_focus: Any) -> None:
            # The shell captures Page Up/Down for scrolling. Take them only while
            # this scale owns focus, before the shell's window controller.
            root = scale.get_root()
            if isinstance(root, Gtk.Window) and keys.get_widget() is None:
                root.add_controller(keys)

        def focus_out(_widget: Any) -> None:
            root = keys.get_widget()
            if root is not None:
                root.remove_controller(keys)
            self.held_keys.clear()
            self._advance()

        def unmapped(widget: Any) -> None:
            self.dragging = self.drag_changed = False
            focus_out(widget)

        focus.connect("enter", focus_in)
        focus.connect("leave", focus_out)
        scale.add_controller(focus)
        scale.connect("unmap", unmapped)

    @property
    def held(self) -> bool:
        return self.dragging or bool(self.held_keys)

    @property
    def protected(self) -> bool:
        return self.held or self.pending or self.in_flight or bool(self.settle_source)

    def wire_value(self, value: float) -> int | float:
        return round(value, self.digits) if self.digits else round(value)

    def moved(self) -> None:
        self.pending = True
        self.drag_changed |= self.dragging
        if not self.held:
            if self.settle_source:
                self.glib.source_remove(self.settle_source)
            self.settle_source = self.glib.timeout_add(_SLIDER_SETTLE_MS, self._settled)
        self._advance()

    def _settled(self) -> bool:
        self.settle_source = 0
        self._advance()
        return False

    def _advance(self) -> None:
        if self.pending and not self.in_flight and not self.send_source:
            until = self.last_send + _SLIDER_WRITE_INTERVAL_US - self.glib.get_monotonic_time()
            delay = max(0, (until + 999) // 1000)
            self.send_source = self.glib.timeout_add(delay, self._flush)
        if self.readback_pending and not self.protected:
            self.readback_pending = False
            self.refresh()

    def _flush(self) -> bool:
        self.send_source = 0
        self.pending = False
        if self.scale.is_sensitive() and self.send(self.wire_value(self.scale.get_value())):
            self.last_send = self.glib.get_monotonic_time()
            self.in_flight = True
        self._advance()
        return False

    def complete(self, ok: bool) -> None:
        self.in_flight = False
        if ok:
            self.readback_pending = True
            self._advance()
        else:
            self.discard()

    def discard(self) -> None:
        if self.send_source:
            self.glib.source_remove(self.send_source)
        if self.settle_source:
            self.glib.source_remove(self.settle_source)
        self.send_source = self.settle_source = 0
        self.pending = self.readback_pending = self.drag_changed = False

    def _pointer_event(self, controller: Any, event: Any, Gdk: Any) -> bool:
        # PyGObject 3.50 can marshal the signal argument as None. The
        # controller exposes the concrete Gdk event during dispatch.
        if event is None:
            event = controller.get_current_event()
        if event is None:
            return False
        event_type = event.get_event_type()
        if not self.dragging and event_type in (Gdk.EventType.BUTTON_PRESS, Gdk.EventType.TOUCH_BEGIN):
            self.dragging, self.drag_changed = True, False
        elif event_type in (Gdk.EventType.BUTTON_RELEASE, Gdk.EventType.TOUCH_END, Gdk.EventType.TOUCH_CANCEL,
                            Gdk.EventType.GRAB_BROKEN) and self.dragging:
            self.dragging = False
            released = event_type in (Gdk.EventType.BUTTON_RELEASE, Gdk.EventType.TOUCH_END)
            if released and self.drag_changed and self.snap_marks and self.scale.is_sensitive():
                value = self.scale.get_value()
                self.scale.set_value(min(self.snap_marks, key=lambda mark: abs(mark - value)))
            self.drag_changed = False
            self._advance()
        return False

    def _key_pressed(self, controller: Any, keyval: int, keycode: int, _mods: Any,
                     moves: dict[int, tuple[float, str]]) -> bool:
        root = controller.get_widget()
        if keyval not in moves or root is None or root.get_focus() is not self.scale or not self.scale.is_sensitive():
            return False
        self.held_keys.add(keycode)
        value = self.scale.get_value()
        delta, snap_move = moves[keyval]
        if not self.snap_marks:
            value = self.wire_value(value + delta)
        elif snap_move == "previous":
            value = max((mark for mark in self.snap_marks if mark < value), default=value)
        elif snap_move == "next":
            value = min((mark for mark in self.snap_marks if mark > value), default=value)
        elif snap_move == "first":
            value = min(self.snap_marks)
        else:
            value = max(self.snap_marks)
        self.scale.set_value(value)
        return True

    def _key_released(self, _controller: Any, _keyval: int, keycode: int, _mods: Any) -> None:
        if keycode in self.held_keys:
            self.held_keys.remove(keycode)
            self._advance()


def build_settings_widget(plug: dict[str, Any], family: str, group_title: str, specs: list[dict[str, Any]], *, required_route: str | None = None, mutation_method: str = "PATCH", page: Any = None) -> Any:
    """Build one receipt-backed settings pane over its admitted Caduceus door."""
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, GLib, Gtk

    if page is None:
        page = _page(Adw, plug)
    group = _group(Adw, page, group_title)
    path = f"/api/v1/settings/{family}"
    discovery_path = "/api/v1/doors"
    state: dict[str, Any] = {"hydrating": False, "hydrated": False, "read_generation": 0, "busy": set(), "values": {}, "status": {}}
    rows: dict[str, Any] = {}
    status_rows: dict[str, Any] = {}
    unavailable_rows: dict[str, Any] = {}
    absent_reasons: dict[str, str] = {}
    status_generation: dict[str, int] = {}
    getters: dict[str, Any] = {}
    setters: dict[str, Any] = {}
    static_signals: dict[str, str] = {}
    readonly_signals: dict[str, str] = {}
    sliders: dict[str, _LiveSlider] = {}
    action_fields: set[str] = set()
    choices: dict[str, dict[str, Any]] = {}
    numeric_choices = {spec["field"] for spec in specs
                       if spec.get("kind") == "choice" and spec.get("number") is True}

    read_error = Adw.ActionRow(title="Couldn't read these settings")
    read_error.set_visible(False)
    group.add(read_error)

    def selectable_subtitle(widget: Any) -> None:
        child = widget.get_first_child()
        while child is not None:
            if isinstance(child, Gtk.Label) and child.has_css_class("subtitle"):
                child.set_selectable(True)
                child.add_css_class("dim-label")
            selectable_subtitle(child)
            child = child.get_next_sibling()

    def show_status(field: str, message: str = "", signal: str = "") -> None:
        status = status_rows[field]
        status.set_title(message)
        status.set_subtitle(signal)
        status.set_visible(bool(message))
        if signal:
            selectable_subtitle(status)

    def show_readonly(field: str, signal: str) -> None:
        state["status"].pop(field, None)
        if signal in _SWAY_ONLY_SIGNALS:
            show_status(field, _SWAY_ONLY_REASON)
        else:
            show_status(field, "Can't be changed from Settings yet", GLib.markup_escape_text(signal))

    def set_control_sensitive(field: str, enabled: bool) -> None:
        # Keep a slider's info button available when its value is read-only.
        control = sliders[field].scale if field in sliders else rows[field]
        control.set_sensitive(enabled)

    def clear_saved(field: str, generation: int) -> bool:
        if status_generation.get(field) == generation and state["status"].get(field) == "Saved":
            state["status"].pop(field, None)
            show_status(field)
        return False

    def add_info(row: Any, info: Any) -> None:
        if not isinstance(info, str) or not info.strip():
            return
        label = Gtk.Label(label=info, wrap=True, max_width_chars=40)
        popover = Gtk.Popover()
        popover.set_child(label)
        button = Gtk.MenuButton(icon_name="help-about-symbolic", valign=Gtk.Align.CENTER)
        button.add_css_class("flat")
        button.set_focusable(True)
        button.set_tooltip_text(info)
        button.set_popover(popover)
        row.add_prefix(button)

    for spec in specs:
        field = spec["field"]
        status_generation[field] = 0
        absent_reasons[field] = spec.get("absent", "Can't be changed from Settings yet")
        kind = spec.get("kind", "entry")
        title = spec["title"]
        if spec.get("underline_title"):
            title = "<u>" + GLib.markup_escape_text(title) + "</u>"
        signal = spec.get("signal", "")
        event_source = None
        if kind == "action":
            action_fields.add(field)
            row = Adw.ActionRow(title=title)
            event_source = Gtk.Button(label=spec.get("button", "Run"), valign=Gtk.Align.CENTER)
            row.add_suffix(event_source)
            getters[field] = lambda: True
            setters[field] = lambda value: None
            changed_signal = "clicked"
        elif kind == "switch":
            row = Adw.SwitchRow(title=title)
            getters[field] = row.get_active
            setters[field] = lambda value, item=row: item.set_active(_bool(value))
            changed_signal = "notify::active"
        elif kind == "spin":
            adjustment = Gtk.Adjustment(
                value=float(spec.get("minimum", 0.0)),
                lower=float(spec.get("minimum", 0.0)),
                upper=float(spec.get("maximum", 100.0)),
                step_increment=float(spec.get("step", 1.0)),
                page_increment=float(spec.get("page", spec.get("step", 1.0) * 10)),
                page_size=0.0,
            )
            row = Adw.SpinRow.new(adjustment, float(spec.get("climb", 1.0)), int(spec.get("digits", 0)))
            row.set_title(title)
            digits = int(spec.get("digits", 0))
            getters[field] = (lambda item=row: int(item.get_value())) if digits == 0 else row.get_value
            setters[field] = lambda value, item=row, default=float(spec.get("minimum", 0.0)): item.set_value(_number(value, default))
            changed_signal = "notify::value"
        elif kind == "slider":
            row = Adw.ActionRow(title=title)
            slider = _LiveSlider(Gtk, Gdk, GLib, spec,
                                 lambda value, key=field: send_slider(key, value),
                                 lambda key=field: refresh(key))
            sliders[field] = slider
            event_source = scale = slider.scale
            row.add_suffix(scale)

            def set_slider(value: Any, item: Any = scale, target: Any = row) -> None:
                adjustment = item.get_adjustment()
                number = _number(value, adjustment.get_lower())
                in_range = adjustment.get_lower() <= number <= adjustment.get_upper()
                target.set_subtitle("" if in_range else f"Current value: {number:g}")
                item.set_draw_value(in_range)
                item.set_value(number)

            setters[field] = set_slider
            changed_signal = "value-changed"
        elif kind == "combo":
            options = spec["options"]
            typed = bool(options) and isinstance(options[0], dict)
            values = [item["value"] for item in options] if typed else [str(item) for item in options]
            labels = [item["label"] for item in options] if typed else values
            row = Adw.ComboRow(title=title, model=Gtk.StringList.new(labels))
            aliases = {str(key): str(value) for key, value in spec.get("aliases", {}).items()}
            def get_combo(item: Any = row, choices: list[Any] = values) -> Any:
                index = item.get_selected()
                return choices[index] if 0 <= index < len(choices) else ""
            def set_combo(value: Any, item: Any = row, choices: list[Any] = values, names: dict[str, str] = aliases, original: list[Any] = list(values), original_labels: list[str] = list(labels), allow_unknown: bool = typed) -> None:
                selected = names.get(str(value), str(value)) if not allow_unknown else value
                choices[:] = original
                names_list = list(original_labels)
                if allow_unknown and selected not in choices:
                    choices.insert(0, selected)
                    names_list.insert(0, str(selected))
                item.set_model(Gtk.StringList.new(names_list))
                item.set_selected(choices.index(selected) if selected in choices else 0)
            getters[field] = get_combo
            setters[field] = set_combo
            changed_signal = "notify::selected"
        else:
            row = Adw.EntryRow(title=title)
            row.set_show_apply_button(True)
            getters[field] = row.get_text
            setters[field] = lambda value, item=row: item.set_text("" if value is None else str(value))
            changed_signal = "apply"
        add_info(row, spec.get("info"))
        rows[field] = row
        set_control_sensitive(field, False)
        group.add(row)
        if kind == "choice":
            combo = Adw.ComboRow(title=title)
            add_info(combo, spec.get("info"))
            combo.set_visible(False)
            combo.set_sensitive(False)
            group.add(combo)
            choices[field] = {"entry": row, "combo": combo, "values": [],
                              "empty_label": spec.get("absent", "No selection")}
        status_row = Adw.ActionRow()
        status_row.set_visible(False)
        status_rows[field] = status_row
        group.add(status_row)
        unavailable = Adw.ActionRow(title=title, subtitle=absent_reasons[field])
        add_info(unavailable, spec.get("info"))
        unavailable.set_sensitive(bool(isinstance(spec.get("info"), str) and spec["info"].strip()))
        unavailable.set_visible(False)
        unavailable_rows[field] = unavailable
        group.add(unavailable)
        if signal:
            static_signals[field] = signal
            show_status(field, "Can't be changed from Settings yet", signal)
        else:
            row.set_visible(False)
            unavailable.set_subtitle("Reading Caduceus…")
            unavailable.set_visible(True)

        def on_changed(_row: Any, _param: Any = None, selected: str = field) -> None:
            if (not state["hydrated"] or state["hydrating"] or selected in state["busy"]
                    or selected in static_signals or selected in readonly_signals):
                return
            if selected in sliders:
                slider = sliders[selected]
                if not slider.scale.is_sensitive():
                    return
                if status_rows[selected].get_visible():
                    status_generation[selected] += 1
                    state["status"].pop(selected, None)
                    show_status(selected)
                rows[selected].set_subtitle("")
                slider.scale.set_draw_value(True)
                slider.moved()
                return
            previous = state["values"].get(selected)
            value = getters[selected]()
            if selected in choices and rows[selected] is choices[selected]["combo"] and value is None:
                return
            if value == previous and selected not in action_fields:
                return
            if selected in numeric_choices and rows[selected] is choices[selected]["entry"]:
                try:
                    number = float(value)
                    if not math.isfinite(number):
                        raise ValueError("not finite")
                except (ValueError, OverflowError):
                    status_generation[selected] += 1
                    state["status"][selected] = "Not saved"
                    show_status(selected, "Not saved", "not a number")
                    return
                value = int(number) if number.is_integer() else number
            status_generation[selected] += 1
            state["status"].pop(selected, None)
            show_status(selected)
            state["busy"].add(selected)
            rows[selected].set_sensitive(False)
            show_status(selected, "Saving…")
            threading.Thread(target=mutate, args=(selected, value, previous), daemon=True).start()

        (event_source if event_source is not None else row).connect(changed_signal, on_changed)
        if kind == "choice":
            combo.connect("notify::selected", on_changed)
        if kind in ("entry", "choice"):
            def on_entry_changed(_row: Any, selected: str = field) -> None:
                if (state["hydrated"] and not state["hydrating"] and selected not in state["busy"]
                        and selected not in readonly_signals):
                    status_generation[selected] += 1
                    state["status"].pop(selected, None)
                    show_status(selected)
            row.connect("changed", on_entry_changed)

    def apply_values(values: dict[str, Any], options: dict[str, Any], readonly: dict[str, Any], message_field: str | None) -> None:
        previously_readonly = set(readonly_signals)
        readonly_signals.clear()
        readonly_signals.update((field, signal) for field, signal in readonly.items()
                                if field in rows and isinstance(signal, str) and signal)
        state["hydrating"] = True
        try:
            for field, choice in choices.items():
                if field in state["busy"] and field not in readonly_signals:
                    continue
                raw = options.get(field)
                offered = [item for item in raw if isinstance(item, dict) and "value" in item and isinstance(item.get("label"), str)] if isinstance(raw, list) else []
                entry, combo = choice["entry"], choice["combo"]
                if offered:
                    offered_values = [item["value"] for item in offered]
                    labels = [item["label"] for item in offered]
                    value = values.get(field)
                    if value is None:
                        offered_values.insert(0, None)
                        labels.insert(0, choice["empty_label"])
                    elif value not in offered_values:
                        offered_values.insert(0, value)
                        labels.insert(0, str(value))
                    choice["values"] = offered_values
                    combo.set_model(Gtk.StringList.new(labels))
                    if hasattr(combo, "set_enable_search"):
                        combo.set_enable_search(len(offered) > 20)
                    entry.set_visible(False)
                    rows[field] = combo
                    getters[field] = lambda item=combo, data=choice: data["values"][item.get_selected()] if 0 <= item.get_selected() < len(data["values"]) else None
                    setters[field] = lambda value, item=combo, data=choice: item.set_selected(data["values"].index(value) if value in data["values"] else Gtk.INVALID_LIST_POSITION)
                else:
                    combo.set_visible(False)
                    rows[field] = entry
                    getters[field] = entry.get_text
                    setters[field] = lambda value, item=entry: item.set_text("" if value is None else str(value))
            for field, row in rows.items():
                slider = sliders.get(field)
                readonly_signal = readonly_signals.get(field)
                value = values.get(field)
                if slider and value is not None:
                    number = _number(value, math.nan)
                    value = number if math.isfinite(number) else None
                if slider and slider.protected and not readonly_signal:
                    if field == message_field:
                        slider.readback_pending = True
                    continue
                defer_value = bool(slider and readonly_signal and (slider.held or slider.in_flight))
                if slider and readonly_signal:
                    slider.discard()
                    slider.dragging = False
                    slider.held_keys.clear()
                available = (field in action_fields or value is not None
                             or (field in choices and row is choices[field]["combo"]))
                show_unavailable = not available and (field not in static_signals or bool(readonly_signal))
                row.set_visible(not show_unavailable)
                if show_unavailable:
                    unavailable_rows[field].set_subtitle("" if readonly_signal else absent_reasons[field])
                    show_status(field)
                unavailable_rows[field].set_visible(show_unavailable)
                previous = state["values"].get(field)
                if available and not defer_value and (field not in state["busy"] or readonly_signal):
                    setters[field](value)
                    state["values"][field] = value if slider else getters[field]()
                if readonly_signal:
                    show_readonly(field, readonly_signal)
                    set_control_sensitive(field, False)
                    if slider and defer_value and not slider.in_flight:
                        GLib.idle_add(refresh)
                    continue
                if field in static_signals:
                    signal = static_signals[field]
                    if signal in _SWAY_ONLY_SIGNALS:
                        show_readonly(field, signal)
                    else:
                        show_status(field, "Can't be changed from Settings yet", signal)
                    set_control_sensitive(field, False)
                elif not available:
                    set_control_sensitive(field, False)
                else:
                    set_control_sensitive(field, field not in state["busy"])
                    if field in previously_readonly:
                        show_status(field)
                    if field == message_field:
                        if slider and slider.wire_value(state["values"][field]) != previous:
                            show_status(field, "Not saved", "settings-readback-mismatch")
                        else:
                            if slider:
                                state["status"][field] = "Saved"
                            show_status(field, state["status"].get(field, "Saved"))
                            GLib.timeout_add_seconds(3, clear_saved, field, status_generation[field])
        finally:
            state["hydrating"] = False

    def finish_read(generation: int, receipt: dict[str, Any] | None, error: str | None, message_field: str | None = None) -> bool:
        if generation != state["read_generation"]:
            return False
        if error is not None or receipt is None or not _receipt_ok(receipt) or not isinstance(receipt.get("values"), dict):
            signal = error or (_refusal_signal(receipt) if receipt is not None else "") or "Settings read refused"
            for field, row in rows.items():
                row.set_visible(False)
                show_status(field)
                unavailable_rows[field].set_visible(False)
                set_control_sensitive(field, False)
            read_error.set_subtitle(signal)
            read_error.set_visible(True)
            selectable_subtitle(read_error)
            return False
        read_error.set_visible(False)
        state["hydrated"] = True
        options = receipt.get("options")
        readonly = receipt.get("readonly")
        apply_values(receipt["values"], options if isinstance(options, dict) else {},
                     readonly if isinstance(readonly, dict) else {}, message_field)
        return False

    def read_door(generation: int, message_field: str | None = None) -> None:
        try:
            if required_route is not None:
                doors = _request(discovery_path)
                routes = doors.get("routes", []) if isinstance(doors, dict) else []
                admitted = isinstance(routes, list) and required_route in routes
                if not admitted:
                    raise RuntimeError(f"missing door: {required_route}")
            receipt = _request(path)
            GLib.idle_add(finish_read, generation, receipt, None, message_field)
        except RuntimeError as error:
            message = str(error)
            if required_route is not None and not message.startswith("missing door:"):
                message = f"missing door: {required_route} (discovery failed: {message})"
            GLib.idle_add(finish_read, generation, None, message, message_field)

    def refresh(message_field: str | None = None) -> bool:
        state["read_generation"] += 1
        generation = state["read_generation"]
        threading.Thread(target=read_door, args=(generation, message_field), daemon=True).start()
        return False

    def send_slider(field: str, value: int | float) -> bool:
        previous = state["values"].get(field)
        if field in static_signals or field in readonly_signals or value == previous:
            return False
        threading.Thread(target=mutate, args=(field, value, previous), daemon=True).start()
        return True

    def finish_mutation(field: str, value: Any, previous: Any, receipt: dict[str, Any] | None, error: str | None) -> bool:
        state["busy"].discard(field)
        slider = sliders.get(field)
        if field in readonly_signals:
            if slider:
                slider.complete(False)
            refresh()
            return False
        if error is not None:
            if slider:
                slider.complete(False)
            state["hydrating"] = True
            try:
                setters[field](previous)
                show_status(field, "Not saved", error)
                set_control_sensitive(field, True)
            finally:
                state["hydrating"] = False
            return False
        assert receipt is not None
        if _receipt_ok(receipt):
            if slider:
                state["values"][field] = value
                slider.complete(True)
                return False
            state["status"][field] = "Saved"
            refresh(field)
            return False
        signal = _refusal_signal(receipt) or "Setting refused"
        staff_signal = _signal(receipt)
        sway_only = signal in _SWAY_ONLY_SIGNALS or staff_signal in _SWAY_ONLY_SIGNALS
        if slider:
            slider.complete(False)
        state["hydrating"] = True
        try:
            setters[field](previous)
            if sway_only:
                static_signals[field] = staff_signal if staff_signal in _SWAY_ONLY_SIGNALS else signal
                show_readonly(field, static_signals[field])
            else:
                show_status(field, "Not saved", signal)
                if staff_signal.startswith(("unsupported:", "privilege:")):
                    static_signals[field] = staff_signal
            if slider and field in static_signals:
                slider.dragging = False
            set_control_sensitive(field, field not in static_signals)
        finally:
            state["hydrating"] = False
        return False

    def mutate(field: str, value: Any, previous: Any) -> None:
        try:
            receipt = _request(path, mutation_method, {field: value})
            GLib.idle_add(finish_mutation, field, value, previous, receipt, None)
        except RuntimeError as error:
            GLib.idle_add(finish_mutation, field, value, previous, None, str(error))

    refresh()
    return page

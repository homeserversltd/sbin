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


def _receipt_ok(receipt: dict[str, Any]) -> bool:
    return receipt.get("ok") is True

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
                message = _signal(receipt) or "Manager request refused"
        except (OSError, urllib.error.URLError, ValueError, UnicodeDecodeError) as error:
            message = f"Manager unavailable: {error}"
        GLib.idle_add(checked, message, True)

    def on_click(_button: Any) -> None:
        button.set_sensitive(False)
        row.set_subtitle("Waiting for Caduceus receipt…")
        threading.Thread(target=toggle, daemon=True).start()

    button.connect("clicked", on_click)
    threading.Thread(target=discover, daemon=True).start()


def build_manager_widget(plug: dict[str, Any], program: str) -> Any:
    import gi
    gi.require_version("Adw", "1")
    from gi.repository import Adw
    page = _page(Adw, plug)
    add_manager_row(page, plug["title"], "Open", program)
    return page


def build_settings_widget(plug: dict[str, Any], family: str, group_title: str, specs: list[dict[str, Any]], *, required_route: str | None = None, mutation_method: str = "PATCH", page: Any = None) -> Any:
    """Build one receipt-backed settings pane over its admitted Caduceus door."""
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

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

    def clear_saved(field: str, generation: int) -> bool:
        if status_generation.get(field) == generation and state["status"].get(field) == "Saved":
            state["status"].pop(field, None)
            show_status(field)
        return False

    for spec in specs:
        field = spec["field"]
        status_generation[field] = 0
        absent_reasons[field] = spec.get("absent", "Can't be changed from Settings yet")
        kind = spec.get("kind", "entry")
        title = spec["title"]
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
        rows[field] = row
        row.set_sensitive(False)
        group.add(row)
        if kind == "choice":
            combo = Adw.ComboRow(title=title)
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
        unavailable.set_sensitive(False)
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
            if not state["hydrated"] or state["hydrating"] or selected in state["busy"] or selected in static_signals:
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
                if state["hydrated"] and not state["hydrating"] and selected not in state["busy"]:
                    status_generation[selected] += 1
                    state["status"].pop(selected, None)
                    show_status(selected)
            row.connect("changed", on_entry_changed)

    def apply_values(values: dict[str, Any], options: dict[str, Any], message_field: str | None = None) -> None:
        state["hydrating"] = True
        try:
            for field, choice in choices.items():
                if field in state["busy"]:
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
                available = (field in action_fields or (field in values and values[field] is not None)
                             or (field in choices and row is choices[field]["combo"]))
                show_unavailable = not available and field not in static_signals
                row.set_visible(not show_unavailable)
                if show_unavailable:
                    unavailable_rows[field].set_subtitle(absent_reasons[field])
                    show_status(field)
                unavailable_rows[field].set_visible(show_unavailable)
                if available and field not in state["busy"]:
                    setters[field](values.get(field))
                    state["values"][field] = getters[field]()
                if field in static_signals:
                    show_status(field, "Can't be changed from Settings yet", static_signals[field])
                    row.set_sensitive(False)
                elif not available:
                    row.set_sensitive(False)
                else:
                    row.set_sensitive(field not in state["busy"])
                    if field == message_field:
                        show_status(field, state["status"].get(field, "Saved"))
                        GLib.timeout_add_seconds(3, clear_saved, field, status_generation[field])
        finally:
            state["hydrating"] = False

    def finish_read(generation: int, receipt: dict[str, Any] | None, error: str | None, message_field: str | None = None) -> bool:
        if generation != state["read_generation"]:
            return False
        if error is not None or receipt is None or not _receipt_ok(receipt) or not isinstance(receipt.get("values"), dict):
            signal = error or (_signal(receipt) if receipt is not None else "") or "Settings read refused"
            for field, row in rows.items():
                row.set_visible(False)
                show_status(field)
                unavailable_rows[field].set_visible(False)
                row.set_sensitive(False)
            read_error.set_subtitle(signal)
            read_error.set_visible(True)
            selectable_subtitle(read_error)
            return False
        read_error.set_visible(False)
        state["hydrated"] = True
        options = receipt.get("options")
        apply_values(receipt["values"], options if isinstance(options, dict) else {}, message_field)
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

    def finish_mutation(field: str, previous: Any, receipt: dict[str, Any] | None, error: str | None) -> bool:
        state["busy"].discard(field)
        row = rows[field]
        if error is not None:
            state["hydrating"] = True
            try:
                setters[field](previous)
                show_status(field, "Not saved", error)
                row.set_sensitive(True)
            finally:
                state["hydrating"] = False
            return False
        assert receipt is not None
        if _receipt_ok(receipt):
            state["status"][field] = "Saved"
            refresh(field)
            return False
        signal = _signal(receipt) or "Setting refused"
        state["hydrating"] = True
        try:
            setters[field](previous)
            show_status(field, "Not saved", signal)
            if signal.startswith(("unsupported:", "privilege:")):
                static_signals[field] = signal
                row.set_sensitive(False)
            else:
                row.set_sensitive(True)
        finally:
            state["hydrating"] = False
        return False

    def mutate(field: str, value: Any, previous: Any) -> None:
        try:
            receipt = _request(path, mutation_method, {field: value})
            GLib.idle_add(finish_mutation, field, previous, receipt, None)
        except RuntimeError as error:
            GLib.idle_add(finish_mutation, field, previous, None, str(error))

    refresh()
    return page

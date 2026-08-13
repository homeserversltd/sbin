"""Shared helpers for appliance settings plugs."""
from __future__ import annotations

import configparser
import json
import os
import subprocess
import threading
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

CADUCEUS_URL = os.environ.get("CADUCEUS_URL", "http://127.0.0.1:8787").rstrip("/")


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


def _request(path: str, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"} if data is not None else {}
    request = urllib.request.Request(CADUCEUS_URL + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(256 * 1024)
    except urllib.error.HTTPError as error:
        body = error.read(256 * 1024)
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RuntimeError(f"Caduceus refused with HTTP {error.code}") from error
        if isinstance(value, dict):
            return value
        raise RuntimeError(f"Caduceus refused with HTTP {error.code}") from error
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("Caduceus is unavailable") from error
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Caduceus returned an unreadable receipt") from error
    if not isinstance(value, dict):
        raise RuntimeError("Caduceus returned an invalid receipt")
    return value


def _signal(receipt: dict[str, Any]) -> str:
    value = receipt.get("firstMissingSignal", receipt.get("first_missing_signal", ""))
    return value if isinstance(value, str) and value != "none" else ""


def _bool(value: Any) -> bool:
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _number(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except (TypeError, ValueError):
        return fallback


def build_settings_widget(plug: dict[str, Any], family: str, group_title: str, specs: list[dict[str, Any]]) -> Any:
    """Build one receipt-backed settings pane over its admitted Caduceus door."""
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    page = _page(Adw, plug)
    group = _group(Adw, page, group_title)
    path = f"/api/v1/settings/{family}"
    state: dict[str, Any] = {"hydrating": False, "hydrated": False, "read_generation": 0, "busy": set(), "values": {}, "status": {}}
    rows: dict[str, Any] = {}
    status_rows: dict[str, Any] = {}
    getters: dict[str, Any] = {}
    setters: dict[str, Any] = {}
    static_signals: dict[str, str] = {}

    for spec in specs:
        field = spec["field"]
        kind = spec.get("kind", "entry")
        title = spec["title"]
        signal = spec.get("signal", "")
        if kind == "switch":
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
            options = [str(item) for item in spec["options"]]
            row = Adw.ComboRow(title=title, model=Gtk.StringList.new(options))
            aliases = {str(key): str(value) for key, value in spec.get("aliases", {}).items()}
            def get_combo(item: Any = row, choices: list[str] = options) -> str:
                index = item.get_selected()
                return choices[index] if 0 <= index < len(choices) else ""
            def set_combo(value: Any, item: Any = row, choices: list[str] = options, names: dict[str, str] = aliases) -> None:
                text = names.get(str(value), str(value))
                item.set_selected(choices.index(text) if text in choices else 0)
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
        if kind == "entry":
            status_row = Adw.ActionRow(title=f"{title} status")
            status_rows[field] = status_row
            group.add(status_row)
        else:
            status_rows[field] = row
        if signal:
            static_signals[field] = signal
            status_rows[field].set_subtitle(signal)
        else:
            status_rows[field].set_subtitle("Reading Caduceus…")

        def on_changed(_row: Any, _param: Any = None, selected: str = field) -> None:
            if not state["hydrated"] or state["hydrating"] or selected in state["busy"] or selected in static_signals:
                return
            previous = state["values"].get(selected)
            value = getters[selected]()
            if value == previous:
                return
            state["busy"].add(selected)
            rows[selected].set_sensitive(False)
            status_rows[selected].set_subtitle("Waiting for Caduceus receipt…")
            threading.Thread(target=mutate, args=(selected, value, previous), daemon=True).start()

        row.connect(changed_signal, on_changed)

    def apply_values(values: dict[str, Any], message_field: str | None = None) -> None:
        state["hydrating"] = True
        try:
            for field, row in rows.items():
                if field in values and field not in state["busy"]:
                    setters[field](values[field])
                    state["values"][field] = getters[field]()
                if field in static_signals:
                    status_rows[field].set_subtitle(static_signals[field])
                    row.set_sensitive(False)
                else:
                    row.set_sensitive(field not in state["busy"])
                    if field == message_field:
                        status_rows[field].set_subtitle(state["status"].get(field, "Saved"))
                    elif field not in state["busy"]:
                        status_rows[field].set_subtitle("")
        finally:
            state["hydrating"] = False

    def finish_read(generation: int, receipt: dict[str, Any] | None, error: str | None, message_field: str | None = None) -> bool:
        if generation != state["read_generation"]:
            return False
        if error is not None:
            for field, row in rows.items():
                if field not in static_signals:
                    status_rows[field].set_subtitle(error)
                    row.set_sensitive(False)
            return False
        assert receipt is not None
        if receipt.get("ok") is not True or not isinstance(receipt.get("values"), dict):
            signal = _signal(receipt) or "Settings read refused"
            for field, row in rows.items():
                if field not in static_signals:
                    status_rows[field].set_subtitle(signal)
                    row.set_sensitive(False)
            return False
        state["hydrated"] = True
        apply_values(receipt["values"], message_field)
        return False

    def read_door(generation: int, message_field: str | None = None) -> None:
        try:
            receipt = _request(path)
            GLib.idle_add(finish_read, generation, receipt, None, message_field)
        except RuntimeError as error:
            GLib.idle_add(finish_read, generation, None, str(error), message_field)

    def refresh(message_field: str | None = None) -> bool:
        state["read_generation"] += 1
        generation = state["read_generation"]
        threading.Thread(target=read_door, args=(generation, message_field), daemon=True).start()
        return False

    def finish_mutation(field: str, previous: Any, receipt: dict[str, Any] | None, error: str | None) -> bool:
        state["busy"].discard(field)
        row = rows[field]
        status_row = status_rows[field]
        if error is not None:
            state["hydrating"] = True
            try:
                setters[field](previous)
                status_row.set_subtitle(error)
                row.set_sensitive(True)
            finally:
                state["hydrating"] = False
            return False
        assert receipt is not None
        if receipt.get("ok") is True:
            state["status"][field] = "Saved"
            refresh(field)
            return False
        signal = _signal(receipt) or "Setting refused"
        state["hydrating"] = True
        try:
            setters[field](previous)
            status_row.set_subtitle(signal)
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
            receipt = _request(path, "POST", {field: value})
            GLib.idle_add(finish_mutation, field, previous, receipt, None)
        except RuntimeError as error:
            GLib.idle_add(finish_mutation, field, previous, None, str(error))

    refresh()
    return page

"""Harmonia Updates plug using only existing Caduceus HTTP doors."""
from __future__ import annotations

import json
import os
import threading
import urllib.error
import urllib.request
from typing import Any

PLUG = {
    "id": "harmonia-updates",
    "title": "Updates",
    "icon": "software-update-available-symbolic",
    "order": 10,
    "parent": None,
}

CADUCEUS_URL = os.environ.get("CADUCEUS_URL", "http://127.0.0.1:8787").rstrip("/")
STATUS_DOOR = "/api/v1/update/status"
TIMER_DOOR = "/api/v1/update/service/status"
UPDATE_DOOR = "/api/v1/gui/update/now"


def _request(path: str, method: str = "GET") -> dict[str, Any]:
    request = urllib.request.Request(CADUCEUS_URL + path, method=method)
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
    return value if isinstance(value, str) else ""


def build_widget() -> Any:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    page = Adw.PreferencesPage(title="Updates", icon_name=PLUG["icon"])
    status_group = Adw.PreferencesGroup(title="Update status")
    status_row = Adw.ActionRow(title="Appliance software", subtitle="Reading Caduceus…")
    status_icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
    status_row.add_prefix(status_icon)
    status_group.add(status_row)
    page.add(status_group)

    timer_group = Adw.PreferencesGroup(title="Automatic updates")
    timer_row = Adw.ActionRow(title="Update timer", subtitle="Reading Caduceus…")
    timer_group.add(timer_row)
    page.add(timer_group)

    action_group = Adw.PreferencesGroup(title="Update now")
    action_row = Adw.ActionRow(
        title="Apply available updates",
        subtitle="Caduceus performs the update and returns its receipt.",
    )
    update_button = Gtk.Button(label="Update Now", valign=Gtk.Align.CENTER)
    update_button.add_css_class("suggested-action")
    action_row.add_suffix(update_button)
    action_group.add(action_row)
    page.add(action_group)

    state = {"busy": False}

    def finish_status(receipt: dict[str, Any] | None, error: str | None) -> bool:
        if error is not None:
            status_row.set_subtitle(error)
            status_icon.set_from_icon_name("dialog-warning-symbolic")
            return False
        assert receipt is not None
        ok = receipt.get("ok") is True
        signal = _signal(receipt)
        status_row.set_subtitle("Ready" if ok else signal or "Update service unavailable")
        status_icon.set_from_icon_name("emblem-ok-symbolic" if ok else "dialog-warning-symbolic")
        update_button.set_sensitive(ok and not state["busy"])
        return False

    def finish_timer(receipt: dict[str, Any] | None, error: str | None) -> bool:
        if error is not None:
            timer_row.set_subtitle(error)
            return False
        assert receipt is not None
        timer = receipt.get("timer", "Update timer")
        timer_state = receipt.get("timerState", "unknown")
        timer_row.set_title(str(timer))
        timer_row.set_subtitle(str(timer_state))
        return False

    def read_door(path: str, finish: Any) -> None:
        try:
            receipt = _request(path)
            GLib.idle_add(finish, receipt, None)
        except RuntimeError as error:
            GLib.idle_add(finish, None, str(error))

    def refresh() -> bool:
        threading.Thread(target=read_door, args=(STATUS_DOOR, finish_status), daemon=True).start()
        threading.Thread(target=read_door, args=(TIMER_DOOR, finish_timer), daemon=True).start()
        return True

    def finish_update(receipt: dict[str, Any] | None, error: str | None) -> bool:
        state["busy"] = False
        update_button.set_label("Update Now")
        if error is not None:
            action_row.set_subtitle(error)
            update_button.set_sensitive(True)
            return False
        assert receipt is not None
        ok = receipt.get("ok") is True
        action_row.set_subtitle("Update complete" if ok else _signal(receipt) or "Update refused")
        update_button.set_sensitive(True)
        refresh()
        return False

    def update() -> None:
        try:
            receipt = _request(UPDATE_DOOR, "POST")
            GLib.idle_add(finish_update, receipt, None)
        except RuntimeError as error:
            GLib.idle_add(finish_update, None, str(error))

    def on_update(_button: Any) -> None:
        if state["busy"]:
            return
        state["busy"] = True
        update_button.set_sensitive(False)
        update_button.set_label("Updating…")
        action_row.set_subtitle("Waiting for Caduceus receipt…")
        threading.Thread(target=update, daemon=True).start()

    update_button.connect("clicked", on_update)
    refresh()
    GLib.timeout_add_seconds(30, refresh)
    return page

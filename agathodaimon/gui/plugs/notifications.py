"""Household inbox and notification settings, through this device's Caduceus."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from typing import Any, Callable

from ._common import CADUCEUS_URL, build_settings_widget

PLUG = {"id": "notifications", "title": "Notifications", "icon": "preferences-system-notifications-symbolic", "order": 5, "parent": None}
NOTIFICATIONS_DOOR = "/api/v1/notifications"
SCHEMA_ID = "caduceus.notifications.v1"
SCHEMA_DOOR = f"/api/v1/schema/{SCHEMA_ID}"
GUEST_INSTRUCTION = "Accept this from your HomeServer in Admin Mode"
SPECS = [
    {"field": "enabled", "title": "Notifications enabled", "kind": "switch"},
    {"field": "do_not_disturb", "title": "Do not disturb", "kind": "switch"},
    {"field": "show_banners", "title": "Show banners", "kind": "switch"},
    {"field": "show_on_lock_screen", "title": "Show on lock screen", "kind": "switch"},
    {"field": "sound_enabled", "title": "Notification sounds", "kind": "switch"},
]


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _get_json(path: str) -> tuple[int, dict[str, Any] | None]:
    request = urllib.request.Request(CADUCEUS_URL + path, headers={"Accept": "application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        response = opener.open(request, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.code
        # Older profiles can answer an absent door with an HTML 404.
        if status in (404, 405, 501):
            return status, None
        raw = response.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("response too large")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("response is not an object")
    return status, value


def _refusal(value: dict[str, Any]) -> str:
    signal = _text(value.get("firstMissingSignal", value.get("first_missing_signal", value.get("signal"))))
    return {
        "link-up-name-invalid": "Choose a valid household name on your HomeServer.",
        "link-up-name-taken": "That household name is already in use.",
        "link-up-admin-required": GUEST_INSTRUCTION,
        "link-up-accept-on-homeserver": GUEST_INSTRUCTION,
    }.get(signal, "Notifications are not available on this device yet.")


def read_model() -> dict[str, Any]:
    """Transient, guest-only projection; missing doors are quiet, failed reads are not."""
    model: dict[str, Any] = {
        "state": "unavailable", "pending_count": None, "notifications": [],
        "message": "Notifications are unavailable. Try again.", "admin_mode": False,
    }
    try:
        # Load the public seat, never a private schema copy. Before the producer
        # lands, an absent seat selects the primitive reader of the supplied seam.
        schema_status, seat = _get_json(SCHEMA_DOOR)
        status, receipt = _get_json(NOTIFICATIONS_DOOR)
        if status in (404, 405, 501):
            model.update(state="empty", pending_count=0, message="No household notifications.")
            return model
        if status >= 400 or (receipt is not None and receipt.get("ok") is False):
            model.update(state="refused", message=_refusal(receipt or {}))
            return model
        if schema_status not in (404, 405, 501) and (
            schema_status >= 400 or seat is None or seat.get("schema", seat.get("$id")) != SCHEMA_ID
        ):
            return model
        if receipt is None or receipt.get("schema") not in (None, SCHEMA_ID):
            return model
        values = receipt.get("notifications")
        if values is None:
            values = []
        if not isinstance(values, list):
            return model
        items = []
        for value in values:
            if not isinstance(value, dict):
                continue
            origin = value.get("from")
            origin = origin if isinstance(origin, dict) else {}
            source = list(dict.fromkeys(filter(None, (_text(origin.get(key)) for key in (
                "hostname", "canonical_name", "ipv4", "mac",
            )))))
            names = value.get("names")
            names = [_text(name) for name in names if _text(name)] if isinstance(names, list) else []
            state = _text(value.get("state"))
            kind = _text(value.get("kind"))
            items.append({
                "id": _text(value.get("id")),
                "title": _text(value.get("title")) or "Household notification",
                "from": " · ".join(source) or "Household device",
                "names": names,
                "status": {"pending": "Waiting", "accepted": "Accepted", "dismissed": "Dismissed"}.get(state, ""),
                "instruction": GUEST_INSTRUCTION if kind == "house-link-up" and state == "pending" else "",
            })
        count = sum(isinstance(item, dict) and item.get("state") == "pending" for item in values)
        model.update(state="ready" if items else "empty", pending_count=count, notifications=items,
                     message="" if items else "No household notifications.")
    except (OSError, ValueError, urllib.error.URLError):
        pass
    return model


def _watch(widget: Any, render: Callable[[dict[str, Any]], None]) -> Callable[..., None]:
    """One bounded read on entry or a deliberate refresh; no polling or disk state."""
    from gi.repository import GLib

    state = {"alive": False, "busy": False, "generation": 0}

    def refresh(*_args: Any) -> None:
        if not state["alive"] or state["busy"]:
            return
        state["busy"] = True
        generation = state["generation"]

        def finish(model: dict[str, Any]) -> bool:
            state["busy"] = False
            if state["alive"]:
                if generation == state["generation"]:
                    render(model)
                else:
                    refresh()
            return False

        def read() -> None:
            GLib.idle_add(finish, read_model())

        threading.Thread(target=read, daemon=True).start()

    def mapped(_widget: Any) -> None:
        state["alive"] = True
        refresh()

    def unmapped(_widget: Any) -> None:
        state["alive"] = False
        state["generation"] += 1

    widget.connect("map", mapped)
    widget.connect("unmap", unmapped)
    return refresh


def build_indicator(activate: Callable[[], None]) -> tuple[Any, Callable[[dict[str, Any]], None]]:
    from gi.repository import Gtk

    button = Gtk.Button(tooltip_text="Notifications")
    line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
    line.append(Gtk.Image.new_from_icon_name(PLUG["icon"]))
    count = Gtk.Label(label="…")
    line.append(count)
    button.set_child(line)

    def render(model: dict[str, Any]) -> None:
        pending = model["pending_count"]
        count.set_text(str(pending) if pending is not None else "?")
        button.set_tooltip_text(f"Notifications: {pending} waiting" if pending is not None else model["message"])

    refresh = _watch(button, render)

    def clicked(_button: Any) -> None:
        refresh()
        activate()

    button.connect("clicked", clicked)
    return button, render


def build_widget(on_model: Callable[[dict[str, Any]], None] | None = None) -> Any:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    stack = Gtk.Stack(hexpand=True, vexpand=True)
    page = Adw.PreferencesPage()
    stack.add_named(page, "inbox")
    group = Adw.PreferencesGroup()
    page.add(group)
    toolbar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    refresh_button = Gtk.Button(label="Refresh")
    settings_button = Gtk.Button(label="Notification settings")
    toolbar.append(refresh_button)
    toolbar.append(settings_button)
    group.add(toolbar)
    message = Gtk.Label(label="Reading household notifications…", xalign=0, wrap=True)
    group.add(message)
    listing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    group.add(listing)

    def render(model: dict[str, Any]) -> None:
        message.set_text(model["message"])
        message.set_visible(bool(model["message"]))
        child = listing.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            listing.remove(child)
            child = following
        for item in model["notifications"]:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            texts = [item["title"], f"From: {item['from']}"]
            if item["names"]:
                texts.append("Names: " + ", ".join(item["names"]))
            texts.extend(filter(None, (item["status"], item["instruction"])))
            for text in texts:
                card.append(Gtk.Label(label=text, xalign=0, wrap=True, selectable=True))
            listing.append(card)
        if on_model is not None:
            on_model(model)

    refresh_button.connect("clicked", _watch(page, render))

    def show_settings(_button: Any) -> None:
        if stack.get_child_by_name("settings") is None:
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            back = Gtk.Button(label="Back to household notifications")
            back.connect("clicked", lambda _button: stack.set_visible_child_name("inbox"))
            box.append(back)
            box.append(build_settings_widget(PLUG, "notifications", "Notification configuration", SPECS))
            stack.add_named(box, "settings")
        stack.set_visible_child_name("settings")

    settings_button.connect("clicked", show_settings)
    return stack

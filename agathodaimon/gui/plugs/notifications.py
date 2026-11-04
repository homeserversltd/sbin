"""Household inbox and notification settings, through this device's Caduceus."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
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


def _posted_datetime(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _posted_label(value: str) -> str:
    posted = _posted_datetime(value)
    if posted is None:
        return ""
    local = posted.astimezone()
    today = datetime.now().astimezone().date()
    clock = local.strftime("%H:%M")
    if local.date() == today:
        return f"Today {clock}"
    if local.date() == today - timedelta(days=1):
        return f"Yesterday {clock}"
    return f"{local.strftime('%b')} {local.day}, {clock}"


def _fold(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fold only rows with a known kind and body; keep newest row's fields."""
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    folded = []
    oldest = datetime.min.replace(tzinfo=timezone.utc)
    for item in sorted(items, key=lambda row: _posted_datetime(row["posted_at"]) or oldest, reverse=True):
        identity = item["mac"] or item["hostname"]
        key = (item["kind"], identity.casefold(), item["state"])
        if item["kind"] and identity and key in groups:
            groups[key]["count"] += 1
            continue
        item["count"] = 1
        folded.append(item)
        if item["kind"] and identity:
            groups[key] = item
    return folded


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
            hostname = _text(origin.get("hostname"))
            ipv4 = _text(origin.get("ipv4"))
            mac = _text(origin.get("mac"))
            source = list(dict.fromkeys(filter(None, (hostname, ipv4))))
            names = value.get("names")
            names = [_text(name) for name in names if _text(name)] if isinstance(names, list) else []
            state = _text(value.get("state"))
            kind = _text(value.get("kind"))
            items.append({
                "id": _text(value.get("id")),
                "title": _text(value.get("title")) or "Household notification",
                "body": _text(value.get("body")),
                "posted_at": _text(value.get("posted_at")),
                "color": _text(value.get("color")),
                "kind": kind, "state": state,
                "hostname": hostname, "canonical_name": _text(origin.get("canonical_name")),
                "ipv4": ipv4, "mac": mac,
                "from": " · ".join(source) or "Household device",
                "names": names,
                "status": {"pending": "Waiting", "accepted": "Accepted", "dismissed": "Dismissed", "expired": "Expired"}.get(state, ""),
                "instruction": GUEST_INSTRUCTION if kind == "house-link-up" and state == "pending" else "",
            })
        count = sum(isinstance(item, dict) and item.get("state") == "pending" for item in values)
        model.update(state="ready" if items else "empty", pending_count=count, notifications=_fold(items),
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
            card.add_css_class("card")
            title = Gtk.Label(label=item["title"], xalign=0, wrap=True, selectable=True)
            title.add_css_class("heading")
            color_class = {"red": "error", "amber": "warning", "blue": "accent"}.get(item["color"])
            if color_class:
                title.add_css_class(color_class)
            card.append(title)
            if item["body"]:
                card.append(Gtk.Label(label=item["body"], xalign=0, wrap=True, selectable=True))
            details = [item["from"], _posted_label(item["posted_at"])]
            if item["count"] > 1:
                details.append(f"{item['count']} times")
            detail = Gtk.Label(label=" · ".join(filter(None, details)), xalign=0, wrap=True, selectable=True)
            detail.add_css_class("dim-label")
            card.append(detail)
            texts = []
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
            box.append(build_settings_widget(PLUG, "notifications", "", SPECS))
            stack.add_named(box, "settings")
        stack.set_visible_child_name("settings")

    settings_button.connect("clicked", show_settings)
    return stack

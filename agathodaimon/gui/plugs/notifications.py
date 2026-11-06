"""Household inbox and notification settings, through this device's Caduceus."""
from __future__ import annotations

import ipaddress
import json
import socket
import struct
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from ._common import CADUCEUS_URL, _receipt_ok, _signal, build_settings_widget

PLUG = {"id": "notifications", "title": "Notifications", "icon": "preferences-system-notifications-symbolic", "order": 5, "parent": None}
NOTIFICATIONS_DOOR = "/api/v1/notifications"
SCHEMA_ID = "caduceus.notifications.v1"
SCHEMA_DOOR = f"/api/v1/schema/{SCHEMA_ID}"
APPLIANCE_CONFIG_PATH = "/etc/appliance/config.json"
GUEST_INSTRUCTION = "Accept this from your HomeServer in Admin Mode"
GATEWAY_INSTRUCTION = "Act on this from your HomeServer in Admin Mode"
ADMIN_SIGNALS = {"link-up-admin-required", "caduceus-administrative-pin-required",
                 "caduceus-administrative-pin-wrong"}
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


def _get_json(path: str, base: str = CADUCEUS_URL) -> tuple[int, dict[str, Any] | None]:
    request = urllib.request.Request(base + path, headers={"Accept": "application/json"})
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
        limit = 16 * 1024 * 1024 if path == "/api/v1/ruyi" else 256 * 1024
        raw = response.read(limit + 1)
    if len(raw) > limit:
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
        "notification-act-on-homeserver": GATEWAY_INSTRUCTION,
        "notification-not-pending": "This notification was already handled.",
    }.get(signal, "Notifications are not available on this device yet.")


def _read_notifications_model() -> dict[str, Any]:
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
            actions = value.get("actions")
            actions = [
                {"verb": _text(action.get("verb")), "label": _text(action.get("label")) or _text(action.get("verb"))}
                for action in (actions if isinstance(actions, list) else [])
                if isinstance(action, dict) and _text(action.get("verb"))
            ] if state == "pending" and _text(value.get("id")) else []
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
                "names": names, "actions": actions,
                "status": {"pending": "Waiting", "accepted": "Accepted", "dismissed": "Dismissed", "expired": "Expired"}.get(state, ""),
                "instruction": GUEST_INSTRUCTION if kind == "house-link-up" and state == "pending" else "",
            })
        count = sum(isinstance(item, dict) and item.get("state") == "pending" for item in values)
        model.update(state="ready" if items else "empty", pending_count=count, notifications=_fold(items),
                     message="" if items else "No household notifications.")
    except (OSError, ValueError, urllib.error.URLError):
        pass
    return model


def _default_gateway() -> str:
    with open("/proc/net/route", encoding="ascii") as routes:
        next(routes, None)
        for line in routes:
            fields = line.split()
            if (len(fields) >= 4 and fields[1] == "00000000" and fields[2] != "00000000"
                    and int(fields[3], 16) & 3 == 3):
                return socket.inet_ntoa(struct.pack("<I", int(fields[2], 16)))
    return ""


def _seat_port() -> int | None:
    try:
        with open(APPLIANCE_CONFIG_PATH, encoding="utf-8") as config:
            port = json.load(config).get("caduceus", {}).get("seat_port")
        if not isinstance(port, bool) and isinstance(port, int) and 1 <= port <= 65535:
            return port
    except (OSError, ValueError, AttributeError):
        pass
    return None


def _read_trust() -> dict[str, Any] | None:
    trust = {"state": "unavailable", "fingerprint": "", "gateway_fingerprint": "",
             "server": "", "message": "Your HomeServer could not be reached."}
    try:
        status, own = _get_json("/api/v1/cert/status")
        if status >= 400 or not own or own.get("ok") is False:
            return trust
        if _text(own.get("role")).lower() == "homeserver":
            return None
        trust["fingerprint"] = _text(own.get("ca_fingerprint"))
        gateway = _default_gateway()
        seat_port = _seat_port()
        if not gateway or seat_port is None:
            return trust
        status, roster = _get_json("/api/v1/ruyi", f"http://{gateway}:{seat_port}")
        if status >= 400 or not roster or roster.get("ok") is False:
            return trust
        seat = roster.get("seat")
        staves = roster.get("staves")
        if not isinstance(seat, dict) or seat.get("ipv4") != gateway or not isinstance(staves, list):
            return trust
        mac = _text(seat.get("mac")).casefold()
        if not mac:
            return trust
        row = next((item for item in staves if isinstance(item, dict) and _text(item.get("mac")).casefold() == mac), None)
        port = row.get("caduceus_port") if row else None
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            return trust
        trust["server"] = f"{gateway}:{port}"
        status, remote = _get_json("/api/v1/cert/status", f"http://{trust['server']}")
        if status >= 400 or not remote or remote.get("ok") is False:
            return trust
        served = _text(remote.get("ca_fingerprint"))
        if not served:
            return trust
        trust["gateway_fingerprint"] = served
        recorded = trust["fingerprint"]
        if recorded and recorded.casefold() != served.casefold():
            trust.update(state="renew", message="HomeServer trust needs to be renewed.")
        elif own.get("bundle_installed") is not True or own.get("browser_trust", True) is False or not recorded:
            trust.update(state="accept", message="Accept HomeServer trust on this device.")
        else:
            trust.update(state="trusted", message="Trusted")
    except (OSError, ValueError, TypeError, urllib.error.URLError):
        pass
    return trust


def read_model() -> dict[str, Any]:
    model = _read_notifications_model()
    trust = _read_trust()
    model["trust"] = trust
    if trust and trust["state"] in ("accept", "renew"):
        model["pending_count"] = (model["pending_count"] or 0) + 1
    return model


def _trust_fetch(server: str, renew: bool) -> str:
    request = urllib.request.Request(
        CADUCEUS_URL + "/api/v1/cert/trust-fetch",
        data=json.dumps({"server": server, "platform": "linux", "renew": renew}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            raw = response.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise ValueError("response too large")
        receipt = json.loads(raw)
        if not isinstance(receipt, dict):
            raise ValueError("invalid receipt")
        if status < 400 and receipt.get("ok") is True:
            return ""
        signal = _text(receipt.get("firstMissingSignal", receipt.get("first_missing_signal")))
        if signal and signal != "none":
            return "Could not update trust: " + signal.replace("-", " ").replace("_", " ") + "."
    except (OSError, ValueError, urllib.error.URLError):
        pass
    return "Could not update HomeServer trust. Try again."


def _is_gateway() -> bool:
    """Notification actions are answered only by the HomeServer's own Caduceus."""
    try:
        profile = json.loads(Path("/etc/appliance/profile.json").read_text(encoding="utf-8")).get("profile")
    except (OSError, ValueError, AttributeError):
        return False
    return profile == "homeserver"


class _ActionGate:
    """One in-memory Admin Mode attendance for this pane's notification actions."""

    def __init__(self) -> None:
        self.document = str(uuid.uuid4())
        self.attendance = ""
        self.lock = threading.Lock()

    def _open(self, prompt: Callable[[], str | None]) -> None:
        host = urllib.parse.urlsplit(CADUCEUS_URL).hostname or ""
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise RuntimeError("PIN can only be sent to local Caduceus")
        pin = prompt()
        if pin is None:
            raise RuntimeError("PIN entry cancelled")
        try:
            receipt = self._post("/api/v1/exousia/open", {
                "pin": pin, "documentId": self.document, "documentIncarnation": self.document,
            }, attend=False)
        finally:
            pin = ""
        if not _receipt_ok(receipt):
            raise RuntimeError("PIN not accepted" if "pin-wrong" in _signal(receipt) else "Admin Mode refused")
        attendance = receipt.get("attendance")
        if not isinstance(attendance, str) or not attendance:
            raise RuntimeError("Admin Mode unavailable")
        self.attendance = attendance

    def _post(self, path: str, payload: dict[str, Any] | None = None, attend: bool = True) -> dict[str, Any]:
        # Never through an environment proxy: the PIN and attendance stay on this body.
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if attend:
            headers["x-caduceus-document"] = self.document
            if self.attendance:
                headers["x-caduceus-attendance"] = self.attendance
        data = json.dumps(payload if payload is not None else {}).encode("utf-8")
        request = urllib.request.Request(CADUCEUS_URL + path, data=data, headers=headers, method="POST")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            response = opener.open(request, timeout=120)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read(256 * 1024)
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, ValueError) as error:
            raise RuntimeError("Caduceus returned an unreadable receipt") from error
        if not isinstance(value, dict):
            raise RuntimeError("Caduceus returned an invalid receipt")
        return value

    def run(self, ident: str, verb: str, prompt: Callable[[], str | None]) -> dict[str, Any]:
        path = f"{NOTIFICATIONS_DOOR}/{urllib.parse.quote(ident, safe='')}/{urllib.parse.quote(verb, safe='')}"
        with self.lock:
            try:
                receipt = self._post(path)
                if not _receipt_ok(receipt) and _signal(receipt) in ADMIN_SIGNALS:
                    self.attendance = ""
                    self._open(prompt)
                    receipt = self._post(path)
            except RuntimeError:
                raise
            except Exception as error:  # transport failures (OSError, http.client) surface on the card
                raise RuntimeError("Caduceus is unavailable") from error
            return receipt


def _watch(widget: Any, render: Callable[[dict[str, Any]], None]) -> Callable[..., None]:
    """One bounded read on entry or a deliberate refresh; no polling or disk state."""
    from gi.repository import GLib

    state = {"alive": False, "busy": False, "again": False, "generation": 0}

    def refresh(*_args: Any) -> None:
        if not state["alive"]:
            return
        if state["busy"]:
            state["again"] = True
            return
        state["busy"] = True
        generation = state["generation"]

        def finish(model: dict[str, Any]) -> bool:
            state["busy"] = False
            again, state["again"] = state["again"], False
            if state["alive"]:
                if generation == state["generation"]:
                    render(model)
                if again or generation != state["generation"]:
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
    from gi.repository import Adw, GLib, Gtk

    stack = Gtk.Stack(hexpand=True, vexpand=True)
    page = Adw.PreferencesPage()
    stack.add_named(page, "inbox")
    group = Adw.PreferencesGroup()
    page.add(group)
    refresh_button = Gtk.Button(label="Refresh")
    settings_button = Gtk.Button(label="Notification settings")
    back_button = Gtk.Button(label="Back to notifications", visible=False)
    # The shell packs these into the top bar beside the close button, in shell and standalone alike.
    stack.header_buttons = (refresh_button, settings_button, back_button)
    message = Gtk.Label(label="Reading household notifications…", xalign=0, wrap=True)
    group.add(message)
    listing = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
    group.add(listing)
    gate = _ActionGate()
    gateway = _is_gateway()
    trust_action = {"busy": False, "message": ""}
    alive = {"value": False}
    stack.connect("map", lambda _widget: alive.update(value=True))
    stack.connect("unmap", lambda _widget: alive.update(value=False))

    def prompt_pin() -> str | None:
        done = threading.Event()
        answer: list[str | None] = [None]

        def show() -> bool:
            try:
                return present()
            except Exception:
                done.set()
                return False

        def present() -> bool:
            if not alive["value"]:
                done.set()
                return False
            dialog = Adw.AlertDialog(heading="Appliance PIN", body="Enter your PIN to enter Admin Mode.")
            entry = Gtk.PasswordEntry()
            entry.set_show_peek_icon(False)
            dialog.set_extra_child(entry)
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("continue", "Continue")
            dialog.set_default_response("continue")
            dialog.set_close_response("cancel")

            def responded(_dialog: Any, response: str) -> None:
                if response == "continue":
                    answer[0] = entry.get_text()
                entry.set_text("")
                done.set()

            dialog.connect("response", responded)
            entry.connect("activate", lambda _entry: dialog.response("continue"))
            dialog.present(stack)
            entry.grab_focus()
            return False

        GLib.idle_add(show)
        done.wait()
        return answer.pop()

    def action_column(item: dict[str, Any]) -> Any:
        column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, valign=Gtk.Align.CENTER)
        status = Gtk.Label(xalign=1, wrap=True, visible=False, max_width_chars=24)
        status.add_css_class("dim-label")
        buttons = []

        def finish(receipt: dict[str, Any] | None, error: str) -> bool:
            if receipt is not None and _receipt_ok(receipt):
                status.set_visible(False)
                refresh()
                return False
            status.set_text(error or _refusal(receipt or {}))
            status.set_visible(True)
            for button in buttons:
                button.set_sensitive(gateway)
            return False

        def act(_button: Any, verb: str) -> None:
            for button in buttons:
                button.set_sensitive(False)
            status.set_visible(False)

            def run() -> None:
                try:
                    GLib.idle_add(finish, gate.run(item["id"], verb, prompt_pin), "")
                except Exception as error:  # every failure re-enables the card
                    GLib.idle_add(finish, None, str(error) or "Caduceus is unavailable")

            threading.Thread(target=run, daemon=True).start()

        for action in item["actions"]:
            button = Gtk.Button(label=action["label"])
            if action["verb"] == "accept":
                button.add_css_class("suggested-action")
            button.connect("clicked", act, action["verb"])
            if not gateway:
                button.set_sensitive(False)
                button.set_tooltip_text(GATEWAY_INSTRUCTION)
            buttons.append(button)
            column.append(button)
        if buttons and not gateway:
            status.set_text(GATEWAY_INSTRUCTION)
            status.set_visible(True)
        column.append(status)
        return column

    def render(model: dict[str, Any]) -> None:
        message.set_text(model["message"])
        message.set_visible(bool(model["message"]))
        child = listing.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            listing.remove(child)
            child = following
        trust = model.get("trust")
        if trust is not None:
            card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            card.add_css_class("card")
            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
            for edge in ("top", "bottom", "start"):
                getattr(content, f"set_margin_{edge}")(12)
            card.append(content)
            title = Gtk.Label(label="HomeServer trust", xalign=0, wrap=True)
            title.add_css_class("heading")
            content.append(title)
            state_label = Gtk.Label(label=trust["message"], xalign=0, wrap=True)
            state_label.add_css_class("accent" if trust["state"] == "trusted" else "warning")
            content.append(state_label)
            fingerprint = trust["gateway_fingerprint"] or trust["fingerprint"]
            if fingerprint:
                label = Gtk.Label(label="Fingerprint: " + fingerprint, xalign=0, wrap=True, selectable=True)
                label.add_css_class("dim-label")
                content.append(label)
            column = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, valign=Gtk.Align.CENTER)
            for edge in ("top", "bottom", "end"):
                getattr(column, f"set_margin_{edge}")(12)
            if trust["state"] in ("accept", "renew"):
                button = Gtk.Button(label="Accept" if trust["state"] == "accept" else "Renew")
                button.set_sensitive(not trust_action["busy"])
                column.append(button)
                notice = Gtk.Label(label=trust_action["message"], xalign=1, wrap=True, selectable=True, max_width_chars=24)
                notice.add_css_class("warning")
                column.append(notice)

                def pressed(_button: Any) -> None:
                    if trust_action["busy"]:
                        return
                    trust_action["busy"] = True
                    trust_action["message"] = ""
                    button.set_sensitive(False)
                    notice.set_text("Updating trust…")

                    def complete(updated: dict[str, Any], failure: str) -> bool:
                        trust_action["busy"] = False
                        trust_action["message"] = failure
                        render(updated)
                        return False

                    def run() -> None:
                        failure = _trust_fetch(trust["server"], trust["state"] == "renew")
                        GLib.idle_add(complete, read_model(), failure)

                    threading.Thread(target=run, daemon=True).start()

                button.connect("clicked", pressed)
            card.append(column)
            listing.append(card)
        for item in model["notifications"]:
            card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            card.add_css_class("card")
            # Left column: what the notification says. Right column: what you can do about it.
            content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6, hexpand=True)
            for edge in ("top", "bottom", "start"):
                getattr(content, f"set_margin_{edge}")(12)
            card.append(content)
            title = Gtk.Label(label=item["title"], xalign=0, wrap=True, selectable=True)
            title.add_css_class("heading")
            color_class = {"red": "error", "amber": "warning", "blue": "accent"}.get(item["color"])
            if color_class:
                title.add_css_class(color_class)
            content.append(title)
            if item["body"]:
                content.append(Gtk.Label(label=item["body"], xalign=0, wrap=True, selectable=True))
            details = [item["from"], _posted_label(item["posted_at"])]
            if item["count"] > 1:
                details.append(f"{item['count']} times")
            detail = Gtk.Label(label=" · ".join(filter(None, details)), xalign=0, wrap=True, selectable=True)
            detail.add_css_class("dim-label")
            content.append(detail)
            texts = []
            if item["names"]:
                texts.append("Names: " + ", ".join(item["names"]))
            # A card with buttons carries its guidance in the action column instead.
            texts.extend(filter(None, (item["status"], "" if item["actions"] else item["instruction"])))
            for text in texts:
                content.append(Gtk.Label(label=text, xalign=0, wrap=True, selectable=True))
            actions = action_column(item)
            for edge in ("top", "bottom", "end"):
                getattr(actions, f"set_margin_{edge}")(12)
            card.append(actions)
            listing.append(card)
        if on_model is not None:
            on_model(model)

    refresh = _watch(page, render)
    refresh_button.connect("clicked", refresh)

    def show_inbox(_button: Any) -> None:
        stack.set_visible_child_name("inbox")
        back_button.set_visible(False)
        refresh_button.set_visible(True)
        settings_button.set_visible(True)

    def show_settings(_button: Any) -> None:
        if stack.get_child_by_name("settings") is None:
            stack.add_named(build_settings_widget(PLUG, "notifications", "", SPECS), "settings")
        stack.set_visible_child_name("settings")
        refresh_button.set_visible(False)
        settings_button.set_visible(False)
        back_button.set_visible(True)

    back_button.connect("clicked", show_inbox)
    settings_button.connect("clicked", show_settings)
    return stack

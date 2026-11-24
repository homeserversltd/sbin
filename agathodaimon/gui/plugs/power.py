"""Power controls in the Settings sidebar header."""
from __future__ import annotations

import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from agathodaimon.gui.plugs._attendance import GATE
from agathodaimon.gui.plugs._common import CADUCEUS_URL, _background, _receipt_ok, _refusal_signal

PLUG = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _post(verb: str, pin: str | None = None) -> dict[str, Any]:
    try:
        url = urllib.parse.urlsplit(CADUCEUS_URL)
        try:
            local = url.hostname == "localhost" or ipaddress.ip_address(url.hostname or "").is_loopback
        except ValueError:
            local = False
        if url.scheme != "http" or not local or url.username is not None or url.password is not None:
            raise RuntimeError("Caduceus must be on this device")
        data = json.dumps({"flags": {"exousia": {"pin": pin}}} if pin is not None else {}).encode("utf-8")
    finally:
        pin = None
    request = urllib.request.Request(
        CADUCEUS_URL + "/api/v1/appliance/power/" + verb,
        data=data, headers={"Content-Type": "application/json", **GATE.headers()}, method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        try:
            response = opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.code
            raw = response.read(256 * 1024)
        receipt = json.loads(raw)
    except (OSError, ValueError, UnicodeDecodeError) as error:
        raise RuntimeError("Caduceus is unavailable or returned an unreadable response") from error
    if not isinstance(receipt, dict):
        raise RuntimeError("Caduceus returned an invalid receipt")
    if not 200 <= status < 300 and _receipt_ok(receipt):
        raise RuntimeError(f"Caduceus refused with HTTP {status}")
    return receipt


def build_indicator() -> Any:
    from gi.repository import Adw, GLib, Gtk

    box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
    state = {"busy": False, "dialog": None}

    def unmapped(_widget: Any) -> None:
        dialog = state["dialog"]
        if dialog is not None:
            dialog.close()

    box.connect("unmap", unmapped)

    def show_refusal(signal: str) -> None:
        if not box.get_mapped():
            return
        dialog = Adw.AlertDialog(heading="Couldn't complete this action", body=signal)
        dialog.add_response("close", "Close")
        dialog.set_default_response("close")
        dialog.set_close_response("close")
        dialog.present(box)

    def act(verb: str) -> None:
        if state["busy"]:
            return
        state["busy"] = True

        def work() -> dict[str, Any]:
            if verb == "reboot":
                body = "Enter your PIN to restart this device."
                refusal = "Not restarted: the PIN was not confirmed."
            else:
                body = "Enter your PIN to shut down this device."
                refusal = "Not shut down: the PIN was not confirmed."
            pin = GATE.pin_confirm(box, body)
            if pin is None:
                raise RuntimeError(refusal)
            try:
                return _post(verb, pin)
            finally:
                pin = None

        def finished(receipt: dict[str, Any] | None, error: str | None) -> bool:
            state["busy"] = False
            if error:
                show_refusal(error)
            elif receipt is not None and not _receipt_ok(receipt):
                signal = _refusal_signal(receipt) or "Caduceus did not accept the request."
                show_refusal("The device refused the request: " + signal)
            return False

        _background(GLib, work, finished)

    def confirm(button: Any, heading: str, label: str, verb: str) -> None:
        if state["busy"]:
            return
        dialog = Adw.AlertDialog(heading=heading, body="Everything on it stops until it comes back.")
        dialog.add_response("cancel", "Cancel")
        dialog.add_response("confirm", label)
        dialog.set_response_appearance("confirm", Adw.ResponseAppearance.DESTRUCTIVE)
        dialog.set_default_response("cancel")
        dialog.set_close_response("cancel")
        dialog.connect("response", lambda _dialog, response: act(verb) if response == "confirm" else None)
        dialog.present(button)

    for label, icon, heading, action, verb in (
        ("Shut down", "system-shutdown-symbolic", "Shut down this device?", "Shut Down", "poweroff"),
        ("Restart", "system-reboot-symbolic", "Restart this device?", "Restart", "reboot"),
    ):
        button = Gtk.Button(icon_name=icon, tooltip_text=label)
        button.update_property([Gtk.AccessibleProperty.LABEL], [label])
        button.connect("clicked", lambda item, h=heading, a=action, v=verb: confirm(item, h, a, v))
        box.append(button)
    return box

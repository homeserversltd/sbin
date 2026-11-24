"""The settings window's shared Caduceus document and attendance."""
from __future__ import annotations

import ipaddress
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Callable

from ._common import CADUCEUS_URL, _receipt_ok, _refusal_signal

PIN_REFUSALS = frozenset({
    "exousia-pin-required", "exousia-pin-wrong", "caduceus-attendance-not-current",
})


class _Attendance:
    def __init__(self) -> None:
        self.document = str(uuid.uuid4())
        self.attendance = ""
        self.lock = threading.Lock()

    def headers(self) -> dict[str, str]:
        headers = {"x-caduceus-document": self.document}
        if self.attendance:
            headers["x-caduceus-attendance"] = self.attendance
        return headers

    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        host = urllib.parse.urlsplit(CADUCEUS_URL).hostname or ""
        try:
            loopback = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = False
        if not loopback:
            raise RuntimeError("PIN can only be sent to local Caduceus")
        request = urllib.request.Request(CADUCEUS_URL + path, data=json.dumps(payload).encode("utf-8"),
                                         headers={"Content-Type": "application/json"}, method="POST")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            try:
                response = opener.open(request, timeout=30)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                receipt = json.loads(response.read(256 * 1024))
        except (OSError, ValueError, UnicodeDecodeError) as error:
            raise RuntimeError("Caduceus is unavailable or returned an unreadable response") from error
        if not isinstance(receipt, dict):
            raise RuntimeError("Caduceus returned an invalid response")
        return receipt

    def check(self, pin: str) -> bool:
        try:
            return self._post("/api/v1/exousia/verify", {"pin": pin}).get("verified") is True
        except Exception:
            return False
        finally:
            pin = ""

    def pin_check(self, parent: Any, body: str = "Enter your PIN to confirm.") -> bool:
        return self.pin_confirm(parent, body) is not None

    def pin_confirm(self, parent: Any, body: str = "Enter your PIN to confirm.") -> str | None:
        if threading.current_thread() is threading.main_thread():
            return None
        try:
            import gi

            gi.require_version("Gtk", "4.0")
            gi.require_version("Adw", "1")
            from gi.repository import Adw, GLib, Gtk
        except Exception:
            return None

        done = threading.Event()
        answer: list[str | None] = [None]

        def show() -> bool:
            try:
                window = parent.get_root() if parent is not None else None
                if not isinstance(window, Gtk.Window):
                    done.set()
                    return False
                dialog = Adw.AlertDialog(heading="Appliance PIN", body=body)
                entry = Gtk.PasswordEntry()
                entry.set_show_peek_icon(False)
                dialog.set_extra_child(entry)
                dialog.add_response("cancel", "Cancel")
                dialog.add_response("continue", "Continue")
                dialog.set_default_response("continue")
                dialog.set_close_response("cancel")

                def responded(_dialog: Any, response: str) -> None:
                    try:
                        if response == "continue":
                            answer[0] = entry.get_text()
                    finally:
                        try:
                            entry.set_text("")
                        finally:
                            done.set()

                dialog.connect("response", responded)
                entry.connect("activate", lambda _entry: (dialog.emit("response", "continue"), dialog.close()))
                dialog.present(window)
                entry.grab_focus()
            except Exception:
                answer[0] = None
                done.set()
            return False

        try:
            GLib.idle_add(show)
        except Exception:
            return None
        done.wait()
        pin = answer.pop()
        if pin is None:
            return None
        try:
            return pin if self.check(pin) else None
        finally:
            pin = ""

    def open(self, pin: str) -> None:
        try:
            receipt = self._post("/api/v1/exousia/open", {
                "pin": pin, "documentId": self.document, "documentIncarnation": self.document,
            })
        finally:
            pin = ""
        if not _receipt_ok(receipt):
            if "pin-wrong" in _refusal_signal(receipt):
                raise RuntimeError("PIN not accepted")
            raise RuntimeError("Attendance refused")
        attendance = receipt.get("attendance")
        if not isinstance(attendance, str) or not attendance:
            raise RuntimeError("Attendance unavailable")
        self.attendance = attendance

    def ask(self, prompt: Callable[[], str | None]) -> None:
        with self.lock:
            self.attendance = ""
            pin = prompt()
            if pin is None:
                raise RuntimeError("PIN entry cancelled")
            try:
                self.open(pin)
            finally:
                pin = ""

    def touch(self) -> None:
        with self.lock:
            if not self.attendance:
                return
            try:
                receipt = self._post("/api/v1/exousia/touch", {
                    "attendance": self.attendance, "documentId": self.document,
                    "documentIncarnation": self.document,
                })
                if not _receipt_ok(receipt):
                    raise RuntimeError("Attendance touch refused")
            except Exception:
                self.attendance = ""
                raise


GATE = _Attendance()

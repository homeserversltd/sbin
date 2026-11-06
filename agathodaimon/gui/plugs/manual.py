"""This device's manual: one icon in the settings sidebar header that opens the loopback hub."""
from __future__ import annotations

from typing import Any

PLUG = None
MANUAL_URI = "http://127.0.0.1:8005/"
ICON = "accessories-dictionary-symbolic"
TOOLTIP = "Open the Manual"


def build_indicator() -> Any:
    from gi.repository import Gio, GLib, Gtk

    button = Gtk.Button(icon_name=ICON, tooltip_text=TOOLTIP)
    button.update_property([Gtk.AccessibleProperty.LABEL], [TOOLTIP])

    def launched(_source: Any, result: Any) -> None:
        try:
            Gio.AppInfo.launch_default_for_uri_finish(result)
        except GLib.Error:
            button.set_tooltip_text("Could not open the manual in your browser.")
        else:
            button.set_tooltip_text(TOOLTIP)

    def clicked(_button: Any) -> None:
        Gio.AppInfo.launch_default_for_uri_async(
            MANUAL_URI,
            button.get_display().get_app_launch_context(),
            None,
            launched,
        )

    button.connect("clicked", clicked)
    return button

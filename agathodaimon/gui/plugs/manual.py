"""Open this device's manual in the desktop session's default browser."""
from __future__ import annotations

PLUG = {"id": "manual", "title": "Manual", "icon": "accessories-dictionary-symbolic", "order": 1, "parent": None}


def _open_manual(button, row):
    from gi.repository import Gio, GLib

    def launched(_source, result):
        try:
            Gio.AppInfo.launch_default_for_uri_finish(result)
        except GLib.Error:
            row.set_subtitle("Could not open the manual in your browser.")
        else:
            row.set_subtitle("")

    Gio.AppInfo.launch_default_for_uri_async(
        "http://127.0.0.1:8005/",
        button.get_display().get_app_launch_context(),
        None,
        launched,
    )


def build_widget():
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    from ._common import _group, _page, _row

    page = _page(Adw, PLUG)
    group = _group(Adw, page, "")
    row = _row(Adw, "This device's manual")
    button = Gtk.Button(label="Open the Manual", valign=Gtk.Align.CENTER)
    button.connect("clicked", _open_manual, row)
    row.add_suffix(button)
    row.set_activatable_widget(button)
    group.add(row)
    return page

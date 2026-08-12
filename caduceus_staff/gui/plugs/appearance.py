"""Read-only appearance settings."""
from __future__ import annotations

try:
    from ._common import _ini, _page, _group, _missing, _row, _disabled
except ImportError:
    import importlib.util as _importlib_util
    import sys as _sys
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _ini, _page, _group, _missing, _row, _disabled

PLUG = {"id": "appearance", "title": "Appearance", "icon": "preferences-desktop-theme-symbolic", "order": 40, "parent": None}


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gtk

    page = _page(Adw, PLUG)
    group = _group(Adw, page, "Theme")
    found = False
    gtk_keys = {
        "gtk-theme-name": "GTK theme",
        "gtk-icon-theme-name": "Icon theme",
        "gtk-cursor-theme-name": "Cursor theme",
        "gtk-application-prefer-dark-theme": "Prefer dark theme",
    }
    for label, path in (("GTK 3", "~/.config/gtk-3.0/settings.ini"), ("GTK 4", "~/.config/gtk-4.0/settings.ini")):
        cfg = _ini(path)
        for key, title in gtk_keys.items():
            for section in cfg.sections():
                if cfg.has_option(section, key):
                    value = cfg.get(section, key, fallback="").strip()
                    if value:
                        found = True
                        group.add(_row(Adw, f"{label}: {title}", value))
    kde = _ini("~/.config/kdeglobals")
    kde_keys = {"colorscheme": "Color scheme", "lookandfeelpackage": "Look and feel", "theme": "Theme", "cursortheme": "Cursor theme", "widgetstyle": "Widget style"}
    for section in kde.sections():
        for key, title in kde_keys.items():
            if cfg_key := next((candidate for candidate in kde[section] if candidate.casefold() == key), None):
                value = kde.get(section, cfg_key, fallback="").strip()
                if value:
                    found = True
                    group.add(_row(Adw, f"KDE: {title}", value))
    if not found:
        _missing(Adw, group)
    _disabled(Gtk, Adw, group, "Theme selection")
    return page

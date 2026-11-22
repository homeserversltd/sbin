"""Receipt-backed default application settings."""
from __future__ import annotations
try:
    from ._common import add_manager_row, build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import add_manager_row, build_settings_widget
PLUG={"id":"default-applications","title":"Default Applications","icon":"preferences-desktop-apps-symbolic","order":90,"parent":None}
SPECS=[
 {"field":"browser","title":"Web browser"}, {"field":"mail","title":"Mail"},
 {"field":"calendar","title":"Calendar"}, {"field":"music","title":"Music"},
 {"field":"video","title":"Video"}, {"field":"photos","title":"Photos"},
 {"field":"text_editor","title":"Text editor"}, {"field":"terminal","title":"Terminal"},
 {"field":"file_manager","title":"File manager"},
]
for spec in SPECS:
    spec["absent"] = "No default chosen"
    spec["kind"] = "choice"


def _descendants(widget):
    for child in widget:
        yield child
        yield from _descendants(child)


def _describe_chooser(row, _property):
    subtitle = row.get_subtitle()
    if subtitle == "Ready":
        row.set_subtitle("Use KDE’s Default Applications to pick any installed app or type a command.")
    elif subtitle == "face-app-kcm-host-absent":
        row.set_subtitle("KDE’s Default Applications isn’t installed on this device.\n" + subtitle)
    elif subtitle in {"face-app-kcm-window-not-observed", "face-app-kcm-window-observation-unavailable"}:
        row.set_subtitle("Couldn’t open the KDE Default Applications window.\n" + subtitle)


def build_widget():
    page = build_settings_widget(PLUG, "default-apps", "", SPECS)
    from gi.repository import Adw

    title = "Another application"
    add_manager_row(page, title, "Choose…", "kcm_componentchooser")
    # The shared helper owns availability and action feedback and doesn't return the row.
    for row in _descendants(page):
        if isinstance(row, Adw.ActionRow) and row.get_title() == title:
            row.connect("notify::subtitle", _describe_chooser)
            break
    return page

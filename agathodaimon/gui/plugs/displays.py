"""Receipt-backed display settings."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
PLUG={"id":"displays","title":"Displays","icon":"video-display-symbolic","order":30,"parent":None}
SPECS=[
 {"field":"resolution","title":"Resolution","kind":"choice"},
 {"field":"refresh_rate","title":"Refresh rate (Hz)","kind":"choice","number":True},
 {"field":"scale","title":"Scale","kind":"choice","number":True,"info":"Makes everything on the screen bigger at once: windows, text, icons and the pointer. To make only the text bigger, use Appearance → Text size."},
 {"field":"orientation","title":"Orientation","kind":"choice"},
 {"field":"brightness","title":"Brightness (%)","kind":"spin","minimum":0,"maximum":100,"step":1,"absent":"Not available on this TV yet"},
 {"field":"night_light","title":"Night light","kind":"switch","absent":"Not available on this TV yet"},
 {"field":"hdr","title":"HDR","kind":"switch","absent":"This display doesn't report HDR"},
 {"field":"adaptive_sync","title":"Adaptive sync","kind":"switch","absent":"This display doesn't report adaptive sync"},
 {"field":"overscan","title":"Overscan","kind":"spin","minimum":0,"maximum":100,"absent":"Not available on this TV yet"},
]

def build_widget():
    import gi
    gi.require_version("Adw", "1")
    from gi.repository import Adw

    page = build_settings_widget(PLUG, "display", "", SPECS)

    def shorten_current_scale(combo, _param):
        model = combo.get_model()
        if model is None or model.get_n_items() == 0:
            return
        label = model.get_string(0)
        try:
            short = format(float(label), ".6g")
        except (TypeError, ValueError):
            return
        if short != label:
            model.splice(0, 1, [short])

    def connect_scale(widget):
        if isinstance(widget, Adw.ComboRow) and widget.get_title() == "Scale":
            widget.connect("notify::model", shorten_current_scale)
        child = widget.get_first_child()
        while child is not None:
            connect_scale(child)
            child = child.get_next_sibling()

    connect_scale(page)
    group = Adw.PreferencesGroup()
    row = Adw.ActionRow(
        title="Fractional scale (1.25×, 1.5×, 1.75×)",
        subtitle="Turned off: fractional scale crashes the display on this system (Debian #1132243)",
    )
    row.set_sensitive(False)
    group.add(row)
    page.add(group)
    return page

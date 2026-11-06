"""GTK Input plug for the admitted settings/input Caduceus route."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
from agathodaimon.gui.plugs.keyboard import SPECS as KEYBOARD_SPECS

PLUG={"id":"input","title":"Keyboard & Mouse","icon":"input-keyboard-symbolic","order":60,"parent":None}
SPECS=[
 {"field":"pointer_speed","title":"Pointer sensitivity","kind":"spin","minimum":-1,"maximum":1,"step":0.05,"digits":2},
 {"field":"natural_scroll","title":"Natural scrolling","kind":"switch"},
 {"field":"tap_to_click","title":"Tap to click","kind":"switch"},
 {"field":"accel_profile","title":"Pointer acceleration","kind":"combo","options":["flat","adaptive"]},
 {"field":"left_handed","title":"Left-handed buttons","kind":"switch"},
 {"field":"disable_while_typing","title":"Disable touchpad while typing","kind":"switch"},
]
for spec in SPECS:
    spec["absent"] = "No mouse or touchpad is connected"
def build_widget():
    page = build_settings_widget(PLUG, "keyboard", "Keyboard", KEYBOARD_SPECS,
                                 required_route="/api/v1/settings/keyboard")
    build_settings_widget(PLUG, "input", "Mouse &amp; Touchpad", SPECS,
                          required_route="/api/v1/settings/input", page=page)
    return page

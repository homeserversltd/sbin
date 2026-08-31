"""GTK Input plug for the admitted settings/input Caduceus route."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
PLUG={"id":"input","title":"Input","icon":"input-keyboard-symbolic","order":60,"parent":None}
SPECS=[
 {"field":"pointer_sensitivity","title":"Pointer sensitivity","kind":"spin","minimum":-1,"maximum":1,"step":0.05,"digits":2},
 {"field":"scroll_factor","title":"Scroll factor","kind":"spin","minimum":0.1,"maximum":10,"step":0.1,"digits":2},
 {"field":"natural_scroll","title":"Natural scrolling","kind":"switch"},
 {"field":"tap_to_click","title":"Tap to click","kind":"switch"},
 {"field":"middle_button_emulation","title":"Middle-button emulation","kind":"switch"},
]
def build_widget():
    return build_settings_widget(PLUG,"input","Input policy",SPECS,required_route="/api/v1/settings/input")

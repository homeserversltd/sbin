"""Receipt-backed input settings."""
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
 {"field":"keyboard_layout","title":"Keyboard layout"},
 {"field":"keyboard_variant","title":"Keyboard variant"},
 {"field":"key_repeat","title":"Key repeat rate","kind":"spin","minimum":1,"maximum":100,"step":1},
 {"field":"repeat_delay_ms","title":"Repeat delay (ms)","kind":"spin","minimum":100,"maximum":5000,"step":50},
 {"field":"repeat_interval_ms","title":"Repeat interval (ms)","kind":"spin","minimum":1,"maximum":1000,"step":1},
 {"field":"natural_scroll","title":"Natural scrolling","kind":"switch"},
 {"field":"tap_to_click","title":"Tap to click","kind":"switch"},
 {"field":"pointer_speed","title":"Pointer speed","kind":"spin","minimum":-1,"maximum":1,"step":0.05,"digits":2},
]
def build_widget(): return build_settings_widget(PLUG,"input","Input configuration",SPECS)

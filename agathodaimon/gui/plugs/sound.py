"""Receipt-backed sound settings."""
from __future__ import annotations
try:
    from ._common import add_manager_row, build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import add_manager_row, build_settings_widget
PLUG={"id":"sound","title":"Sound","icon":"audio-volume-high-symbolic","order":50,"parent":None}
SPECS=[
 {"field":"output_device","title":"Output device"},
 {"field":"input_device","title":"Input device"},
 {"field":"volume","title":"Output volume (%)","kind":"spin","minimum":0,"maximum":100,"step":1},
 {"field":"input_volume","title":"Input volume (%)","kind":"spin","minimum":0,"maximum":100,"step":1},
 {"field":"muted","title":"Mute output","kind":"switch"},
 {"field":"card_profile","title":"Card profile"},
 {"field":"test_tone","title":"Test tone","kind":"action","button":"Play"},
]
def build_widget():
    page = build_settings_widget(PLUG, "sound", "Sound configuration", SPECS)
    add_manager_row(page, "Advanced sound controls", "Advanced…", "pavucontrol")
    return page

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
 {"field":"resolution","title":"Resolution"},
 {"field":"refresh_rate","title":"Refresh rate (Hz)","kind":"spin","minimum":1,"maximum":360,"digits":2,"step":1},
 {"field":"scale","title":"Scale","kind":"spin","minimum":0.25,"maximum":4,"digits":2,"step":0.05},
 {"field":"orientation","title":"Orientation","kind":"combo","options":["normal","90","180","270","flipped","flipped90","flipped180","flipped270"],"aliases":{"0":"normal","1":"90","2":"180","3":"270","4":"flipped","5":"flipped90","6":"flipped180","7":"flipped270"}},
 {"field":"brightness","title":"Brightness (%)","kind":"spin","minimum":0,"maximum":100,"step":1},
 {"field":"night_light","title":"Night light","kind":"switch"},
]
def build_widget(): return build_settings_widget(PLUG,"display","Display configuration",SPECS)

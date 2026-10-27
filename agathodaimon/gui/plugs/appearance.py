"""Receipt-backed appearance settings."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
PLUG={"id":"appearance","title":"Appearance","icon":"preferences-desktop-theme-symbolic","order":40,"parent":None}
SPECS=[
 {"field":"color_scheme","title":"Color scheme","kind":"combo","options":["light","dark"]},
 {"field":"accent_color","title":"Accent color"},
 {"field":"wallpaper","title":"Wallpaper"},
 {"field":"icon_theme","title":"Icon theme"},
 {"field":"cursor_theme","title":"Cursor theme"},
 {"field":"font","title":"Interface font"},
 {"field":"cursor_size","title":"Cursor size","kind":"spin","minimum":8,"maximum":256},
 {"field":"font_size","title":"Interface font size","kind":"spin","minimum":6,"maximum":72},
 {"field":"text_scale","title":"Text scale","kind":"spin","minimum":0.5,"maximum":3,"step":0.05,"digits":2},
]
def build_widget(): return build_settings_widget(PLUG,"appearance","Theme",SPECS)

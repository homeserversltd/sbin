"""Receipt-backed appearance settings."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
PLUG={"id":"appearance","title":"Appearance","icon":"preferences-desktop-appearance-symbolic","order":40,"parent":None}
SPECS=[
 {"field":"color_scheme","title":"Color scheme","kind":"combo","options":["light","dark"],"info":"Switches apps between light and dark. Most apps follow it at once; a few older apps may not."},
 {"field":"accent_color","title":"Accent color","info":"The highlight color for buttons and selections. Not changeable here yet."},
 {"field":"wallpaper","title":"Wallpaper","info":"The picture behind your windows. Not changeable here yet."},
 {"field":"icon_theme","title":"Icon theme","kind":"choice","info":"Changes the set of icons apps and menus use. It doesn't change the look of windows or buttons."},
 {"field":"cursor_theme","title":"Cursor theme","kind":"choice","info":"Changes how the mouse pointer looks. Nothing else."},
 {"field":"text_scale","title":"Text size","kind":"spin","minimum":0.5,"maximum":3,"step":0.05,"digits":2,"info":"Makes text bigger or smaller, including in apps that choose their own font. Buttons, icons and spacing stay the same size. This is the one most people want."},
 {"field":"font","title":"Interface font","info":"The typeface used for menus, labels and buttons. Apps that pick their own font keep theirs."},
 {"field":"font_size","title":"Interface font size","kind":"spin","minimum":6,"maximum":72,"info":"The size of that interface font only. Apps that set their own text size may not follow it; to make text bigger, use Text size."},
]
def build_widget(): return build_settings_widget(PLUG,"appearance","",SPECS)

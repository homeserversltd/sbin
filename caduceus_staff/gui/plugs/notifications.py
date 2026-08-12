"""Receipt-backed notification settings."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
PLUG={"id":"notifications","title":"Notifications","icon":"preferences-system-notifications-symbolic","order":80,"parent":None}
SPECS=[
 {"field":"enabled","title":"Notifications enabled","kind":"switch"},
 {"field":"do_not_disturb","title":"Do not disturb","kind":"switch"},
 {"field":"show_banners","title":"Show banners","kind":"switch"},
 {"field":"show_on_lock_screen","title":"Show on lock screen","kind":"switch"},
 {"field":"sound_enabled","title":"Notification sounds","kind":"switch"},
]
def build_widget(): return build_settings_widget(PLUG,"notifications","Notification configuration",SPECS)

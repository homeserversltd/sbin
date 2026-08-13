"""Receipt-backed default application settings."""
from __future__ import annotations
try:
    from ._common import build_settings_widget
except ImportError:
    import importlib.util as _importlib_util, sys as _sys
    _spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _module = _importlib_util.module_from_spec(_spec); _sys.modules["_common"] = _module; _spec.loader.exec_module(_module)
    from _common import build_settings_widget
PLUG={"id":"default-applications","title":"Default Applications","icon":"applications-system-symbolic","order":90,"parent":None}
SPECS=[
 {"field":"browser","title":"Web browser"}, {"field":"mail","title":"Mail"},
 {"field":"calendar","title":"Calendar"}, {"field":"music","title":"Music"},
 {"field":"video","title":"Video"}, {"field":"photos","title":"Photos"},
 {"field":"text_editor","title":"Text editor"}, {"field":"terminal","title":"Terminal"},
 {"field":"file_manager","title":"File manager"},
]
def build_widget(): return build_settings_widget(PLUG,"default-apps","Default applications",SPECS)

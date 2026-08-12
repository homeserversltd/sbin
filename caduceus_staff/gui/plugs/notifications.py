"""Read-only notification settings."""
from __future__ import annotations
try:
    from ._common import _read,_page,_group,_missing,_row,_disabled
except ImportError:
    import importlib.util as _importlib_util
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    import sys as _sys
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _read,_page,_group,_missing,_row,_disabled
PLUG={"id":"notifications","title":"Notifications","icon":"preferences-system-notifications-symbolic","order":80,"parent":None}
def build_widget():
 import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")
 from gi.repository import Adw, Gtk
 page=_page(Adw,PLUG); group=_group(Adw,page,"Dunst")
 text=_read("~/.config/dunst/dunstrc").strip()
 added = False
 if text:
  keys=("font","format","geometry","origin","timeout","urgency_low","urgency_normal","urgency_critical")
  for line in text.splitlines():
   line=line.strip()
   if line and not line.startswith("#") and any(line.startswith(k+" ") or line.startswith(k+"=") for k in keys): group.add(_row(Adw,line)); added = True
 if not added: _missing(Adw, group)
 _disabled(Gtk, Adw, group,"Notification configuration"); return page

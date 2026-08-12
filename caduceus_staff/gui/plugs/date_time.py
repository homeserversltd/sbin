"""Read-only date and time settings."""
from __future__ import annotations
try:
    from ._common import _command,_page,_group,_missing,_row,_disabled
except ImportError:
    import importlib.util as _importlib_util
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    import sys as _sys
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _command,_page,_group,_missing,_row,_disabled
PLUG={"id":"date-time","title":"Date & Time","icon":"preferences-system-time-symbolic","order":100,"parent":None}
def build_widget():
 import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")
 from gi.repository import Adw, Gtk
 page=_page(Adw,PLUG); group=_group(Adw,page,"System clock"); text=_command("timedatectl","show","--no-pager")
 added = False
 if text:
  for line in text.splitlines():
   if line.startswith(("Timezone=","LocalRTC=","NTP=","NTPSynchronized=","TimeUSec=")): group.add(_row(Adw,line.split("=",1)[0],line.split("=",1)[1])); added = True
 if not added: _missing(Adw, group)
 _disabled(Gtk, Adw, group,"Date and time configuration"); return page

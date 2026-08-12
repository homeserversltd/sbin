"""Read-only sound settings."""
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
PLUG={"id":"sound","title":"Sound","icon":"audio-volume-high-symbolic","order":50,"parent":None}
def build_widget():
 import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")
 from gi.repository import Adw, Gtk
 page=_page(Adw,PLUG); group=_group(Adw,page,"Default output"); added = False
 sink = _command("pactl", "get-default-sink")
 if sink:
  group.add(_row(Adw, "Default sink", sink)); added = True
  volume = _command("pactl", "get-sink-volume", sink)
  mute = _command("pactl", "get-sink-mute", sink)
  if volume:
   group.add(_row(Adw, "Volume", volume)); added = True
  if mute:
   group.add(_row(Adw, "Mute", mute)); added = True
 else:
  inspected = _command("wpctl", "inspect", "@DEFAULT_AUDIO_SINK@")
  volume = _command("wpctl", "get-volume", "@DEFAULT_AUDIO_SINK@")
  if inspected or volume:
   identity = next((line.strip() for line in inspected.splitlines() if "node.name" in line or "node.description" in line), "")
   if identity:
    group.add(_row(Adw, "Default sink", identity)); added = True
   if volume:
    group.add(_row(Adw, "Volume", volume)); added = True
    muted = "yes" if "MUTED" in volume.upper() else "no"
    group.add(_row(Adw, "Mute", muted))
  else:
   pass
 if not added: _missing(Adw, group)
 _disabled(Gtk, Adw, group, "Sound configuration")
 return page

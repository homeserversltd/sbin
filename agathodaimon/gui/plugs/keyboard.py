"""Keyboard settings plug."""
try:
    from ._common import build_settings_widget
except ImportError:
    from _common import build_settings_widget

PLUG = None
SPECS = [
    {"field": "keyboard_layout", "title": "Keyboard layout", "kind": "entry"},
    {"field": "repeat_rate", "title": "Repeat rate", "kind": "spin", "minimum": 0, "maximum": 1000},
    {"field": "repeat_delay", "title": "Repeat delay (ms)", "kind": "spin", "minimum": 0, "maximum": 10000},
]

def build_widget():
    raise RuntimeError("keyboard plug is retired; use Keyboard & Mouse")

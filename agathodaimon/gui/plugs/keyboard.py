"""Keyboard settings plug."""
try:
    from ._common import build_settings_widget
except ImportError:
    from _common import build_settings_widget

PLUG = {"id": "keyboard", "title": "Keyboard", "icon": "input-keyboard-symbolic", "order": 62, "parent": None}
SPECS = [
    {"field": "keyboard_layout", "title": "Keyboard layout", "kind": "entry"},
    {"field": "repeat_rate", "title": "Repeat rate", "kind": "spin", "minimum": 0, "maximum": 1000},
    {"field": "repeat_delay", "title": "Repeat delay (ms)", "kind": "spin", "minimum": 0, "maximum": 10000},
]

def build_widget():
    return build_settings_widget(PLUG, "keyboard", "Keyboard", SPECS, required_route="/api/v1/settings/keyboard")

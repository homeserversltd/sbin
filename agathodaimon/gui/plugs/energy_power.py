"""Energy and power settings plug."""
try:
    from ._common import build_settings_widget
except ImportError:
    from _common import build_settings_widget

PLUG = {"id": "energy-power", "title": "Energy & Power", "icon": "battery-symbolic", "order": 97, "parent": None}
SPECS = [
    {"field": "screen_off_seconds", "title": "Turn screen off after", "kind": "combo", "options": [
        {"value": 0, "label": "Never"}, {"value": 300, "label": "5 minutes"},
        {"value": 600, "label": "10 minutes"}, {"value": 900, "label": "15 minutes"},
        {"value": 1800, "label": "30 minutes"}, {"value": 3600, "label": "1 hour"},
    ]},
    {"field": "sleep_seconds", "title": "Sleep timeout (seconds)", "kind": "spin", "minimum": 0, "maximum": 86400, "absent": "This TV does not sleep"},
    {"field": "power_button_action", "title": "Power button action", "kind": "combo", "options": ["poweroff", "suspend", "ignore"]},
]

def build_widget():
    return build_settings_widget(PLUG, "energy", "", SPECS, required_route="/api/v1/settings/energy")

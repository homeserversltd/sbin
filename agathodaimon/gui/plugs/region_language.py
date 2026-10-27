"""Region and language settings plug."""
try:
    from ._common import build_settings_widget
except ImportError:
    from _common import build_settings_widget

PLUG = {"id": "region-language", "title": "Region & Language", "icon": "preferences-desktop-locale-symbolic", "order": 95, "parent": None}
SPECS = [
    {"field": "locale", "title": "Locale", "kind": "entry"},
    {"field": "measurement_units", "title": "Measurement units", "kind": "combo", "options": ["metric", "imperial"]},
]

def build_widget():
    return build_settings_widget(PLUG, "region", "Region & Language", SPECS, required_route="/api/v1/settings/region")

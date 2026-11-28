"""Receipt-backed sound settings."""
from __future__ import annotations
from ._common import add_manager_row, build_settings_widget
PLUG={"id":"sound","title":"Sound","icon":"audio-volume-high-symbolic","order":50,"parent":None}
SPECS=[
 {"field":"output_device","title":"Output device","kind":"choice"},
 {"field":"input_device","title":"Input device","kind":"choice"},
 {"field":"volume","title":"Output volume (%)","kind":"spin","minimum":0,"maximum":100,"step":1},
 {"field":"input_volume","title":"Input volume (%)","kind":"spin","minimum":0,"maximum":100,"step":1},
 {"field":"muted","title":"Mute output","kind":"switch"},
 {"field":"card_profile","title":"Card profile"},
 {"field":"test_tone","title":"Test tone","kind":"action","button":"Play","door":"/api/v1/settings/sound/test-tone/play"},
]
def build_widget():
    page = build_settings_widget(PLUG, "sound", "", SPECS)
    add_manager_row(page, "Advanced sound controls", "Advanced…", "pavucontrol")
    return page

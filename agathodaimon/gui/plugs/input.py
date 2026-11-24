"""GTK Input plug for the admitted settings/input Caduceus route."""
from __future__ import annotations
from ._common import build_settings_widget
from agathodaimon.gui.plugs.keyboard import SPECS as KEYBOARD_SPECS

PLUG={"id":"input","title":"Keyboard & Mouse","icon":"input-keyboard-symbolic","order":60,"parent":None}
SPECS=[
 {"field":"pointer_speed","title":"Pointer sensitivity","kind":"spin","minimum":-1,"maximum":1,"step":0.05,"digits":2},
 {"field":"scroll_factor","title":"Scroll speed","kind":"slider","minimum":0.25,"maximum":3.0,"step":0.05,"digits":2,
  "marks":[0.5,{"value":1.0,"label":"Normal"},2.0,3.0],"snap":False,"absent":"No mouse is connected",
  "info":"How far a page moves for each click of the mouse wheel. Lower is gentler."},
 {"field":"natural_scroll","title":"Natural scrolling","kind":"switch"},
 {"field":"tap_to_click","title":"Tap to click","kind":"switch"},
 {"field":"accel_profile","title":"Pointer acceleration","kind":"combo","options":["flat","adaptive"]},
 {"field":"left_handed","title":"Left-handed buttons","kind":"switch"},
 {"field":"disable_while_typing","title":"Disable touchpad while typing","kind":"switch"},
]
for spec in SPECS:
    spec.setdefault("absent", "No mouse or touchpad is connected")
def build_widget():
    page = build_settings_widget(PLUG, "keyboard", "Keyboard", KEYBOARD_SPECS,
                                 required_route="/api/v1/settings/keyboard")
    build_settings_widget(PLUG, "input", "Mouse &amp; Touchpad", SPECS,
                          required_route="/api/v1/settings/input", page=page)
    return page

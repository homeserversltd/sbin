"""Energy and power settings plug."""
try:
    from ._common import build_settings_widget
except ImportError:
    from _common import build_settings_widget

PLUG = {"id": "energy-power", "title": "Energy & Power", "icon": "battery-symbolic", "order": 97, "parent": None}
SPECS = [
    {"field": "screen_off_seconds", "title": "Screen-off timeout (seconds)", "kind": "spin", "minimum": 0, "maximum": 86400},
    {"field": "sleep_seconds", "title": "Sleep timeout (seconds)", "kind": "spin", "minimum": 0, "maximum": 86400},
    {"field": "power_button_action", "title": "Power button action", "kind": "combo", "options": ["poweroff", "suspend", "ignore"]},
]

def build_widget():
    page = build_settings_widget(PLUG, "energy", "Energy & Power", SPECS, required_route="/api/v1/settings/energy")
    from gi.repository import Adw

    def describe_when_idle(row, _property=None):
        if not row.get_subtitle():
            row.set_subtitle("0 means never")

    def visit(widget):
        if isinstance(widget, Adw.SpinRow) and widget.get_title() == "Screen-off timeout (seconds)":
            row = widget
            row.connect("notify::subtitle", describe_when_idle)
            describe_when_idle(row)
            return
        child = widget.get_first_child()
        while child is not None:
            visit(child)
            child = child.get_next_sibling()

    visit(page)
    return page

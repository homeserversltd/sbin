"""Wi-Fi and network manager through the Caduceus face door."""
from agathodaimon.gui.plugs._common import build_manager_widget

PLUG = {"id": "wifi-network", "title": "Wi-Fi & Network", "icon": "network-wireless-symbolic", "order": 51, "parent": None}


def build_widget():
    return build_manager_widget(PLUG, "nm-connection-editor")

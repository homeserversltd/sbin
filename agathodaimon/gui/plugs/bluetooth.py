"""Bluetooth manager through the Caduceus face door."""
from agathodaimon.gui.plugs._common import build_manager_widget

PLUG = {"id": "bluetooth", "title": "Bluetooth", "icon": "bluetooth-symbolic", "order": 52, "parent": None}


def build_widget():
    return build_manager_widget(PLUG, "blueman-manager")

"""USB disk manager through the Caduceus face door."""
from agathodaimon.gui.plugs._common import build_manager_widget

PLUG = {"id": "usb-drives", "title": "USB Drives", "icon": "drive-removable-media-symbolic", "order": 53, "parent": None}


def build_widget():
    return build_manager_widget(PLUG, "gnome-disks")

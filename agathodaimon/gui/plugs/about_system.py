"""Read-only appliance system information."""
from __future__ import annotations

import platform
import socket

try:
    from ._common import _json, _page, _group, _missing, _row, _receipt_ok, _request, _signal
except ImportError:
    import importlib.util as _importlib_util
    import sys as _sys
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _json, _page, _group, _missing, _row, _receipt_ok, _request, _signal

PLUG = {"id": "about-system", "title": "About System", "icon": "computer-symbolic", "order": 110, "parent": None}


def _status() -> dict:
    try:
        return _request('/api/v1/update/status')
    except RuntimeError:
        return {}


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw

    page = _page(Adw, PLUG)
    group = _group(Adw, page, "System information")
    profile = _json("/etc/appliance/profile.json")
    values = [("Hostname", socket.gethostname()), ("Kernel", platform.release())]
    values.extend((str(k), str(v)) for k, v in profile.items() if isinstance(v, (str, int, float, bool)))
    for title, value in values:
        group.add(_row(Adw, title, value))

    update_group = _group(Adw, page, "Update status")
    receipt = _status()
    if not receipt:
        update_group.add(_row(Adw, "Appliance software", "Update status unavailable"))
    else:
        ok = _receipt_ok(receipt)
        signal = _signal(receipt)
        subtitle = "Ready" if ok else (signal or "Unavailable")
        update_group.add(_row(Adw, "Appliance software", subtitle))
    return page

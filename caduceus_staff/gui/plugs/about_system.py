"""Read-only appliance system information."""
from __future__ import annotations

import json
import os
import platform
import socket
import urllib.error
import urllib.request

try:
    from ._common import _json, _page, _group, _missing, _row
except ImportError:
    import importlib.util as _importlib_util
    import sys as _sys
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _json, _page, _group, _missing, _row

PLUG = {"id": "about-system", "title": "About System", "icon": "computer-symbolic", "order": 110, "parent": None}
CADUCEUS_URL = os.environ.get("CADUCEUS_URL", "http://127.0.0.1:8787").rstrip("/")


def _status() -> dict:
    request = urllib.request.Request(CADUCEUS_URL + "/api/v1/update/status", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(256 * 1024)
        value = json.loads(body)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


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
        ok = receipt.get("ok") is True
        signal = receipt.get("firstMissingSignal", receipt.get("first_missing_signal"))
        subtitle = "Ready" if ok else (str(signal) if signal else "Unavailable")
        update_group.add(_row(Adw, "Appliance software", subtitle))
    return page

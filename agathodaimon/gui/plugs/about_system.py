"""Read-only appliance system summary: the neofetch facts as themed rows."""
from __future__ import annotations

import os
import platform
import socket

try:
    from ._common import _command, _group, _json, _page, _read
except ImportError:
    import importlib.util as _importlib_util
    import sys as _sys
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _command, _group, _json, _page, _read

PLUG = {"id": "about-system", "title": "About System", "icon": "computer-symbolic", "order": 110, "parent": None}

PRODUCTS = {"tv": "HomeTV", "homeconsole": "HomeConsole", "homeserver": "HomeServer"}


def _os_release() -> dict[str, str]:
    fields = {}
    for line in _read("/etc/os-release").splitlines():
        key, _, value = line.partition("=")
        if value:
            fields[key] = value.strip().strip('"')
    return fields


def _uptime() -> str:
    try:
        seconds = int(float(_read("/proc/uptime").split()[0]))
    except (IndexError, ValueError):
        return ""
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    parts = [f"{days} days" if days else "", f"{hours} hours" if hours else "", f"{rest // 60} mins"]
    return ", ".join(part for part in parts if part)


def _meminfo() -> str:
    fields = {}
    for line in _read("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        if value.split():
            fields[key] = int(value.split()[0])
    if "MemTotal" not in fields or "MemAvailable" not in fields:
        return ""
    total = fields["MemTotal"] // 1024
    return f"{total - fields['MemAvailable'] // 1024}MiB / {total}MiB"


def _disk() -> str:
    try:
        stat = os.statvfs("/")
    except OSError:
        return ""
    total = stat.f_blocks * stat.f_frsize / 2**30
    used = total - stat.f_bavail * stat.f_frsize / 2**30
    return f"{used:.0f}GiB / {total:.0f}GiB"


def _packages() -> str:
    for manager, args in (("pacman", ("pacman", "-Qq")), ("dpkg", ("dpkg-query", "-f", ".\n", "-W"))):
        listing = _command(*args)
        if listing:
            return f"{len(listing.splitlines())} ({manager})"
    return ""


def _host() -> str:
    name = _read("/sys/class/dmi/id/product_name").strip()
    version = _read("/sys/class/dmi/id/product_version").strip()
    if version and version.casefold() not in {"default string", "to be filled by o.e.m.", "none"}:
        name = f"{name} {version}"
    return name


def _cpu() -> str:
    for line in _read("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            model = line.partition(":")[2].replace("(R)", "").replace("(TM)", "").strip()
            return f"{model} ({os.cpu_count()})"
    return platform.processor()


def _gpu() -> str:
    for line in _command("lspci").splitlines():
        if any(kind in line for kind in ("VGA", "3D controller", "Display controller")):
            return line.split(": ", 1)[-1]
    return ""


def _wm() -> str:
    if os.environ.get("SWAYSOCK"):
        return "Sway"
    if os.environ.get("HYPRLAND_INSTANCE_SIGNATURE"):
        return "Hyprland"
    return os.environ.get("XDG_CURRENT_DESKTOP", "")


def _resolution(Gdk) -> str:
    display = Gdk.Display.get_default()
    if display is None:
        return ""
    modes = []
    for monitor in display.get_monitors():
        geometry = monitor.get_geometry()
        scale = monitor.get_scale() if hasattr(monitor, "get_scale") else monitor.get_scale_factor()
        width, height = round(geometry.width * scale), round(geometry.height * scale)
        modes.append(f"{width}x{height} @ {monitor.get_refresh_rate() / 1000:.0f}Hz")
    return ", ".join(modes)


def _local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("10.255.255.255", 1))
            return probe.getsockname()[0]
    except OSError:
        return ""


def _groups(Gdk) -> list[tuple[str, list[tuple[str, str]]]]:
    release = _os_release()
    profile = _json("/etc/appliance/profile.json")
    return [
        ("Appliance", [
            ("Product", PRODUCTS.get(profile.get("profile"), str(profile.get("profile") or ""))),
            ("Born", str(profile.get("born_at") or "")[:10]),
            ("Hostname", socket.gethostname()),
            ("Local IP", _local_ip()),
        ]),
        ("Software", [
            ("Operating System", f"{release.get('PRETTY_NAME', platform.system())} {platform.machine()}"),
            ("Kernel", platform.release()),
            ("Packages", _packages()),
            ("Window Manager", _wm()),
            ("Uptime", _uptime()),
        ]),
        ("Hardware", [
            ("Model", _host()),
            ("Processor", _cpu()),
            ("Graphics", _gpu()),
            ("Memory", _meminfo()),
            ("Disk (/)", _disk()),
            ("Resolution", _resolution(Gdk)),
        ]),
    ]


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gtk

    page = _page(Adw, PLUG)
    for title, facts in _groups(Gdk):
        group = _group(Adw, page, title)
        for key, value in facts:
            row = Adw.ActionRow(title=key)
            value_label = Gtk.Label(label=value or "Unavailable", xalign=1)
            value_label.add_css_class("dim-label")
            row.add_suffix(value_label)
            group.add(row)
    return page

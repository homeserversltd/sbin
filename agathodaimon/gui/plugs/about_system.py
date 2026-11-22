"""Read-only appliance system summary: the neofetch facts as themed rows."""
from __future__ import annotations

import os
import platform
import re
import socket
from agathodaimon.carapace import normalize_profile

try:
    from ._common import _command, _json, _page, _read
except ImportError:
    import importlib.util as _importlib_util
    import sys as _sys
    _common_spec = _importlib_util.spec_from_file_location("_common", __file__.replace(__file__.split("/")[-1], "_common.py"))
    _common_module = _importlib_util.module_from_spec(_common_spec)
    _sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _command, _json, _page, _read

PLUG = {"id": "about-system", "title": "About System", "icon": "help-about-symbolic", "order": 0, "parent": None}

PRODUCTS = {"hometv": "HomeTV", "homeconsole": "HomeConsole", "homeserver": "HomeServer"}

_PCI_ADDRESS = re.compile(r"(?:[0-9a-f]{4,8}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]", re.IGNORECASE)
_DISPLAY_CLASSES = {"vga compatible controller", "xga compatible controller", "3d controller", "display controller"}


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
    minutes = rest // 60
    return ", ".join(
        f"{count} {unit}{'' if count == 1 else 's'}"
        for count, unit in ((days, "day"), (hours, "hour"), (minutes, "min"))
        if count or unit == "min"
    )


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


def _graphics_title(device: str) -> str:
    # A PCI display class says what the device does, not how it is fitted.
    # Use positive model/family evidence; vendors (and drivers) can span both kinds.
    model = device.casefold()
    if model.startswith("nvidia corporation "):
        if re.search(r"\b(?:geforce (?:rtx|gtx)|rtx [a-z]?\d{3,4})\b", model):
            return "Graphics card"
    elif model.startswith("intel corporation "):
        if re.search(r"\b(?:dg[12]|battlemage|arc [ab]\d{3}m?|iris xe max)\b", model):
            return "Graphics card"
        if re.search(r"\b(?:u?hd graphics|iris (?:plus|xe) graphics)\b", model):
            return "Integrated graphics"
    elif model.startswith("advanced micro devices, inc."):
        if re.search(r"\b(?:raphael|raven ridge|picasso|renoir|cezanne|rembrandt|phoenix|radeon 610m)\b", model):
            return "Integrated graphics"
        if re.search(r"\bradeon rx \d{3,4}m?\b", model):
            return "Graphics card"
    return "Graphics"


def _graphics() -> list[tuple[str, str]]:
    controllers = []
    for line in _command("lspci", "-Dnn").splitlines():
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or not _PCI_ADDRESS.fullmatch(fields[0]):
            continue
        address, description = fields
        pci_class, separator, device = description.partition(":")
        if not separator:
            continue
        pci_class = pci_class.strip().casefold()
        # Class 03 is display. Accept plain class names when IDs are omitted.
        code = re.search(r"\[([0-9a-f]{4})\]$", pci_class)
        if not (code[1].startswith("03") if code else pci_class in _DISPLAY_CLASSES):
            continue
        if address.count(":") == 1:
            address = f"0000:{address}"
        slot = tuple(int(part, 16) for part in re.split(r"[:.]", address))
        device = device.strip()
        if not re.search(r"\bDevice \[", device):
            device = re.sub(r" \[[0-9a-f]{4}:[0-9a-f]{4}\](?= \(rev |$)", "", device)
        controllers.append((slot, device))
    return [(_graphics_title(device), device) for _, device in sorted(controllers)] or [("Graphics", "")]


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
    born = profile.get("born_at")
    return [
        ("Appliance", [
            ("Product", PRODUCTS.get(normalize_profile(profile.get("profile")), str(profile.get("profile") or ""))),
            ("Born", born.strip()[:10] if isinstance(born, str) else ""),
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
            *_graphics(),
            ("Memory", _meminfo()),
            ("Disk (/)", _disk()),
            ("Resolution", _resolution(Gdk)),
        ]),
    ]


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gtk, Pango

    page = _page(Adw, PLUG)
    for title, facts in _groups(Gdk):
        group = Adw.PreferencesGroup()
        page.add(group)
        line = Gtk.Box(spacing=24)
        heading = Gtk.Label(label=title, xalign=0, valign=Gtk.Align.START, width_chars=10, margin_top=16)
        heading.add_css_class("heading")
        rows = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE, hexpand=True)
        rows.add_css_class("boxed-list")
        for key, value in facts:
            row = Gtk.ListBoxRow(activatable=False, selectable=False)
            columns = Gtk.Box(spacing=12, margin_start=12, margin_end=12, margin_top=8, margin_bottom=8)
            # The title gets spare width and can wrap only between words.
            columns.append(Gtk.Label(label=key, xalign=0, hexpand=True, wrap=True, wrap_mode=Pango.WrapMode.WORD))
            missing = "Not recorded on this device" if key == "Born" else "Not available on this device"
            value_label = Gtk.Label(
                label=value if value.strip() else missing,
                xalign=1, justify=Gtk.Justification.RIGHT,
                wrap=True, wrap_mode=Pango.WrapMode.WORD_CHAR, max_width_chars=30,
            )
            value_label.add_css_class("dim-label")
            columns.append(value_label)
            row.set_child(columns)
            rows.append(row)
        line.append(heading)
        line.append(rows)
        group.add(line)
    return page

"""Read-only view of the font families Fontconfig finds on this device."""
from __future__ import annotations

import shlex
import subprocess
import threading
from pathlib import Path

from agathodaimon._nidus.run import run as nidus_run
from agathodaimon.gui.plugs._common import _page

PLUG = {"id": "fonts", "title": "Fonts", "icon": "preferences-desktop-font-symbolic", "order": 45, "parent": None}

FontGroups = dict[Path, dict[str, tuple[set[str], set[Path]]]]


def _font_roots(data_home: Path) -> dict[Path, str]:
    home = Path.home()
    roots = {
        Path("/usr/share/fonts"): "System fonts",
        Path("/usr/local/share/fonts"): "Added fonts",
        home / ".local/share/fonts": "Your fonts",
    }
    for root in (data_home / "fonts", home / ".fonts"):
        roots.setdefault(root, f"Your fonts ({root})")
    return roots


def _configured_roots() -> set[Path]:
    """Read Fontconfig's active config files, without scanning or loading fonts."""
    from ctypes import CDLL, c_char_p, c_void_p

    try:
        fc = CDLL("libfontconfig.so.1")  # The same library fc-list already needs.
    except OSError:
        return set()

    fc.FcInitLoadConfig.argtypes, fc.FcInitLoadConfig.restype = [], c_void_p
    fc.FcConfigGetFontDirs.argtypes, fc.FcConfigGetFontDirs.restype = [c_void_p], c_void_p
    fc.FcStrListNext.argtypes, fc.FcStrListNext.restype = [c_void_p], c_char_p
    fc.FcStrListDone.argtypes, fc.FcStrListDone.restype = [c_void_p], None
    fc.FcConfigDestroy.argtypes, fc.FcConfigDestroy.restype = [c_void_p], None

    config = fc.FcInitLoadConfig()
    if not config:
        return set()
    try:
        # The config-only handle has the declared roots, but not their scanned subdirectories.
        dirs = fc.FcConfigGetFontDirs(config)
        if not dirs:
            return set()
        try:
            return {Path(raw.decode("utf-8", errors="replace"))
                    for raw in iter(lambda: fc.FcStrListNext(dirs), None) if raw}
        finally:
            fc.FcStrListDone(dirs)
    finally:
        fc.FcConfigDestroy(config)


def _installed_fonts(roots: dict[Path, str]) -> FontGroups:
    # Use primary names, not their aliases or localized spellings. Unquote data
    # with shlex, never a shell, so spaces and punctuation in paths stay intact.
    fmt = "%{file|shescape} %{family[0]|shescape} %{style[0]|shescape}\n"
    result = nidus_run(
        ["fc-list", "-f", fmt, ":", "file", "family", "style"],
        check=True, encoding="utf-8", errors="replace", timeout=10,
    )
    fields = iter(shlex.split(result.stdout))
    configured: set[Path] | None = None
    groups: FontGroups = {}
    for filename, family, style in zip(fields, fields, fields, strict=True):
        if not filename or not family:
            continue
        folder = Path(filename).parent
        # Keep the standard groups together. Otherwise match the nearest declared
        # root, or show the file's containing folder when no declaration covers it.
        ancestors = (folder, *folder.parents)
        root = next((path for path in ancestors if path in roots), None)
        if root is None:
            if configured is None:
                configured = _configured_roots()
            root = next((path for path in ancestors if path in configured), folder)
        styles, folders = groups.setdefault(root, {}).setdefault(family, (set(), set()))
        if style:
            styles.add(style)
        folders.add(folder)
    return groups


def build_widget():
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    page = _page(Adw, PLUG)
    roots = _font_roots(Path(GLib.get_user_data_dir()))
    status = Adw.PreferencesGroup()
    status_row = Adw.ActionRow(title="Reading installed fonts…", activatable=False, focusable=False)
    status.add(status_row)
    page.add(status)

    def finish(groups: FontGroups | None) -> bool:
        if page.get_root() is None:
            return GLib.SOURCE_REMOVE
        if groups is None:
            status_row.set_title("This device couldn’t list its installed fonts.")
        elif not groups:
            status_row.set_title("No installed fonts found.")
        else:
            page.remove(status)
            system = Path("/usr/share/fonts")
            added = Path("/usr/local/share/fonts")
            owner_roots = [root for root in roots if root not in (system, added)]
            ordered = (*owner_roots, added, *sorted(groups.keys() - roots.keys()), system)
            for root in ordered:
                if root not in groups:
                    continue
                group = Adw.PreferencesGroup(title=roots.get(root, str(root)))
                for family in sorted(groups[root], key=lambda name: (name.casefold(), name)):
                    styles, folders = groups[root][family]
                    row = Adw.ActionRow(
                        title=family, subtitle="\n".join(str(folder) for folder in sorted(folders)),
                        use_markup=False, activatable=False, focusable=True,
                    )
                    count = len(styles)
                    description = f"{count} {'style' if count == 1 else 'styles'}" if count else "0 named styles"
                    label = Gtk.Label(label=description)
                    label.add_css_class("dim-label")
                    row.add_suffix(label)
                    group.add(row)
                    if row.get_index() == 0:
                        # The shell should enter the first row, not the group's list box.
                        row.get_parent().set_focusable(False)
                page.add(group)
        return GLib.SOURCE_REMOVE

    def read() -> None:
        try:
            groups = _installed_fonts(roots)
        except (OSError, subprocess.SubprocessError, ValueError):
            groups = None
        GLib.idle_add(finish, groups)

    def on_map(widget) -> None:
        widget.disconnect(map_handler)
        threading.Thread(target=read, daemon=True).start()

    map_handler = page.connect("map", on_map)
    return page

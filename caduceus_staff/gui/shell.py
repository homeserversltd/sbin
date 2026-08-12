#!/usr/bin/env python3
"""GTK4/libadwaita appliance settings shell with runtime plugs."""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

PLUG_KEYS = ("id", "title", "icon", "order", "parent")
PLUGS_DIR = Path(__file__).with_name("plugs")


@dataclass(frozen=True)
class Plug:
    ident: str
    title: str
    icon: str
    order: int
    parent: str | None
    build_widget: Callable[[], Any]
    module: ModuleType


def _load_module(path: Path) -> ModuleType:
    name = f"caduceus_staff.gui.plugs.{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load {path.name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _validate(module: ModuleType, path: Path) -> Plug:
    contract = getattr(module, "PLUG", None)
    if not isinstance(contract, dict) or set(contract) != set(PLUG_KEYS):
        raise ValueError(f"{path.name}: PLUG must contain exactly {', '.join(PLUG_KEYS)}")
    ident = contract["id"]
    title = contract["title"]
    icon = contract["icon"]
    order = contract["order"]
    parent = contract["parent"]
    if not isinstance(ident, str) or not ident or not ident.replace("-", "").replace("_", "").isalnum():
        raise ValueError(f"{path.name}: invalid id")
    if not isinstance(title, str) or not title:
        raise ValueError(f"{path.name}: invalid title")
    if not isinstance(icon, str) or not icon:
        raise ValueError(f"{path.name}: invalid icon")
    if not isinstance(order, int) or isinstance(order, bool):
        raise ValueError(f"{path.name}: invalid order")
    if parent is not None and (not isinstance(parent, str) or not parent):
        raise ValueError(f"{path.name}: invalid parent")
    builder = getattr(module, "build_widget", None)
    if not callable(builder):
        raise ValueError(f"{path.name}: build_widget is not callable")
    return Plug(ident, title, icon, order, parent, builder, module)


def discover_plugs(directory: Path = PLUGS_DIR) -> dict[str, Plug]:
    registry: dict[str, Plug] = {}
    for path in sorted(directory.glob("*.py")):
        if path.name.startswith("_"):
            continue
        plug = _validate(_load_module(path), path)
        if plug.ident in registry:
            raise ValueError(f"duplicate plug id: {plug.ident}")
        registry[plug.ident] = plug
    for plug in registry.values():
        if plug.parent is not None and plug.parent not in registry:
            raise ValueError(f"{plug.ident}: missing parent {plug.parent}")
        seen = {plug.ident}
        parent = plug.parent
        while parent is not None:
            if parent in seen:
                raise ValueError(f"{plug.ident}: parent cycle")
            seen.add(parent)
            parent = registry[parent].parent
    return registry


def ordered_plugs(registry: dict[str, Plug]) -> list[tuple[Plug, int]]:
    children: dict[str | None, list[Plug]] = {}
    for plug in registry.values():
        children.setdefault(plug.parent, []).append(plug)
    for values in children.values():
        values.sort(key=lambda item: (item.order, item.title.casefold(), item.ident))
    result: list[tuple[Plug, int]] = []

    def append(parent: str | None, depth: int) -> None:
        for plug in children.get(parent, []):
            result.append((plug, depth))
            append(plug.ident, depth + 1)

    append(None, 0)
    return result


def _gtk() -> tuple[Any, Any, Any, Any]:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gio, GLib, Gtk

    return Adw, Gio, GLib, Gtk


def self_check() -> int:
    try:
        registry = discover_plugs()
        ordered = ordered_plugs(registry)
        if len(ordered) != len(registry):
            raise ValueError("plug hierarchy is incomplete")
    except Exception as error:
        print(f"plug receipt ok=false error={error}")
        return 1

    gtk_available = True
    gtk_error = ""
    try:
        Adw, _Gio, _GLib, Gtk = _gtk()
        Adw.init()
        initialized = Gtk.init_check()
        if isinstance(initialized, tuple):
            initialized = initialized[0]
        gtk_available = bool(initialized)
        if not gtk_available:
            gtk_error = "display-unavailable"
    except Exception as error:
        gtk_available = False
        gtk_error = f"{type(error).__name__}:{error}"

    failed = False
    for plug, depth in ordered:
        widget_state = "not-built"
        if gtk_available:
            try:
                widget = plug.build_widget()
                if not isinstance(widget, Gtk.Widget):
                    raise TypeError("build_widget did not return Gtk.Widget")
                widget_state = type(widget).__name__
            except Exception as error:
                failed = True
                widget_state = f"failed:{type(error).__name__}:{error}"
        else:
            widget_state = f"skipped:{gtk_error}"
        parent = plug.parent if plug.parent is not None else "root"
        print(
            f"plug receipt id={plug.ident} title={plug.title!r} parent={parent} "
            f"depth={depth} contract=ok widget={widget_state}"
        )
    if not ordered:
        print("plug receipt ok=false error=no-plugs")
        return 1
    return 1 if failed else 0


def run_application(registry: dict[str, Plug], standalone: str | None) -> int:
    Adw, Gio, _GLib, Gtk = _gtk()

    class SettingsApplication(Adw.Application):
        def __init__(self) -> None:
            suffix = standalone.replace("_", "-") if standalone is not None else "shell"
            super().__init__(application_id=f"com.homeservers.appliance.settings.{suffix}")
            self.registry = registry
            self.standalone = standalone
            self.window = None

        def install_optional_css(self) -> None:
            css_path = os.environ.get("APPLIANCE_SETTINGS_CSS")
            if not css_path or self.window is None:
                return
            provider = Gtk.CssProvider()
            provider.load_from_path(css_path)
            Gtk.StyleContext.add_provider_for_display(
                self.window.get_display(),
                provider,
                Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
            )

        def do_activate(self) -> None:
            if self.window is not None:
                self.window.present()
                return
            Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.PREFER_DARK)
            if self.standalone is not None:
                plug = self.registry[self.standalone]
                self.window = Adw.ApplicationWindow(application=self)
                self.window.set_title(plug.title)
                self.window.set_default_size(720, 640)
                self.window.set_content(plug.build_widget())
                self.install_optional_css()
                self.window.present()
                return

            split = Adw.NavigationSplitView()
            listing = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
            listing.add_css_class("navigation-sidebar")
            sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            sidebar_box.append(listing)
            sidebar_page = Adw.NavigationPage.new(sidebar_box, "Settings")
            split.set_sidebar(sidebar_page)
            rows: dict[Any, Plug] = {}
            first_row = None
            for plug, depth in ordered_plugs(self.registry):
                row = Gtk.ListBoxRow()
                line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                line.set_margin_start(12 + depth * 20)
                line.set_margin_end(12)
                line.set_margin_top(8)
                line.set_margin_bottom(8)
                line.append(Gtk.Image.new_from_icon_name(plug.icon))
                label = Gtk.Label(label=plug.title, xalign=0)
                label.set_hexpand(True)
                line.append(label)
                row.set_child(line)
                listing.append(row)
                rows[row] = plug
                if first_row is None:
                    first_row = row

            def select(_listing: Any, row: Any) -> None:
                if row is None:
                    return
                plug = rows[row]
                split.set_content(Adw.NavigationPage.new(plug.build_widget(), plug.title))
                split.set_show_content(True)

            listing.connect("row-selected", select)
            self.window = Adw.ApplicationWindow(application=self)
            self.window.set_title("Appliance Settings")
            self.window.set_default_size(1040, 720)
            self.window.set_content(split)
            self.install_optional_css()
            if first_row is not None:
                listing.select_row(first_row)
            self.window.present()

    app = SettingsApplication()
    return app.run([sys.argv[0]])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="appliance-settings")
    parser.add_argument("--standalone-plug", metavar="ID")
    parser.add_argument("--self-check", action="store_true")
    args = parser.parse_args(argv)
    if args.self_check:
        return self_check()
    try:
        registry = discover_plugs()
        if args.standalone_plug is not None and args.standalone_plug not in registry:
            parser.error(f"unknown plug: {args.standalone_plug}")
        return run_application(registry, args.standalone_plug)
    except (ImportError, ValueError) as error:
        print(f"appliance-settings: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

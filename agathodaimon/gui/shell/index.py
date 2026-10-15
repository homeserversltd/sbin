#!/usr/bin/env python3
"""GTK4/libadwaita appliance settings shell with runtime plugs."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

PLUG_KEYS = ("id", "title", "icon", "order", "parent")
PLUGS_DIR = Path(__file__).resolve().parent.parent / "plugs"


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
    name = f"agathodaimon.gui.plugs.{path.stem}"
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
        if path.name.startswith("_") or path.name == "index.py":
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


START_PLUG = "about-system"
PRODUCT_TITLES = {"tv": "HomeTV", "homeconsole": "HomeConsole", "homeserver": "HomeServer"}


def _app_title() -> str:
    try:
        profile = json.loads(Path("/etc/appliance/profile.json").read_text(encoding="utf-8")).get("profile")
    except (OSError, ValueError, AttributeError):
        profile = None
    return f"{PRODUCT_TITLES.get(profile, 'Appliance')} Settings"


def _toolbar(Adw: Any, header: Any, child: Any) -> Any:
    view = Adw.ToolbarView()
    view.add_top_bar(header)
    view.set_content(child)
    return view


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


def _visible_children(widget: Any, Gtk: Any) -> list[Any]:
    if isinstance(widget, Gtk.Stack):
        child = widget.get_visible_child()
        return [child] if child is not None else []
    children = []
    child = widget.get_first_child()
    while child is not None:
        children.append(child)
        child = child.get_next_sibling()
    return children


def _visible_widgets(root: Any, Gtk: Any, *, require_mapped: bool = False):
    if root is None or not root.get_visible() or not root.get_child_visible():
        return
    if require_mapped and not root.get_mapped():
        return
    yield root
    for child in _visible_children(root, Gtk):
        yield from _visible_widgets(child, Gtk, require_mapped=require_mapped)


def _find_visible_scroller(root: Any, Gtk: Any) -> Any | None:
    return next((widget for widget in _visible_widgets(root, Gtk)
                 if isinstance(widget, Gtk.ScrolledWindow)), None)


def _ensure_page_scroller(Gtk: Any, page: Any) -> tuple[Any, Any]:
    scroller = _find_visible_scroller(page, Gtk)
    if scroller is not None:
        return page, scroller
    scroller = Gtk.ScrolledWindow()
    scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroller.set_child(page)
    return scroller, scroller


def _is_descendant(widget: Any, ancestor: Any) -> bool:
    while widget is not None:
        if widget is ancestor:
            return True
        widget = widget.get_parent()
    return False


def _page_focusables(root: Any, Gtk: Any) -> list[Any]:
    scroller = _find_visible_scroller(root, Gtk)
    if scroller is None:
        return []
    widgets = list(_visible_widgets(root, Gtk, require_mapped=True))
    focusables = [widget for widget in widgets
                  if widget is not scroller and not isinstance(widget, Gtk.Scrollbar)
                  and widget.get_focusable() and widget.is_sensitive()]
    scroller.set_focusable(not focusables)
    if focusables:
        return focusables
    return [scroller] if scroller in widgets and scroller.is_sensitive() else []


def _focus_page(root: Any, Gtk: Any) -> bool:
    for widget in _page_focusables(root, Gtk):
        if widget.grab_focus():
            return True
    return False


def _native_horizontal_control(focus: Any, root: Any, Gtk: Any, Adw: Any) -> bool:
    controls = tuple(cls for cls in (
        Gtk.Range, Gtk.DropDown,
        getattr(Adw, "ComboRow", None), getattr(Adw, "SpinRow", None),
        getattr(Adw, "EntryRow", None),
    ) if cls is not None)
    while focus is not None and _is_descendant(focus, root):
        if isinstance(focus, (Gtk.Editable, Gtk.TextView)) or isinstance(focus, controls):
            return True
        if isinstance(focus, Gtk.Label) and focus.get_selectable():
            return True
        if focus is root:
            break
        focus = focus.get_parent()
    return False


def _install_page_keyboard(window: Any, Gtk: Any, Gdk: Any, Adw: Any,
                           get_content: Callable[[], Any], listing: Any = None,
                           get_active_row: Callable[[], Any] | None = None) -> None:
    page_keys = {
        Gdk.KEY_Page_Up, Gdk.KEY_Page_Down, Gdk.KEY_Home, Gdk.KEY_End,
        getattr(Gdk, "KEY_KP_Page_Up", -1), getattr(Gdk, "KEY_KP_Page_Down", -1),
        getattr(Gdk, "KEY_KP_Home", -1), getattr(Gdk, "KEY_KP_End", -1),
    }
    left_keys = {Gdk.KEY_Left, getattr(Gdk, "KEY_KP_Left", -1)}
    right_keys = {Gdk.KEY_Right, getattr(Gdk, "KEY_KP_Right", -1)}
    tab_keys = {Gdk.KEY_Tab, getattr(Gdk, "KEY_ISO_Left_Tab", -1)}
    blocked_tab_modifiers = (Gdk.ModifierType.CONTROL_MASK | Gdk.ModifierType.ALT_MASK |
                             Gdk.ModifierType.SUPER_MASK | Gdk.ModifierType.META_MASK |
                             Gdk.ModifierType.HYPER_MASK)

    def current_row() -> Any:
        return listing.get_selected_row() or (get_active_row() if get_active_row else None)

    def focus_current_row() -> bool:
        row = current_row()
        return bool(row is not None and row.grab_focus())

    def capture(_controller: Any, keyval: int, _keycode: int, _state: Any) -> bool:
        root = get_content()
        if keyval in page_keys:
            scroller = _find_visible_scroller(root, Gtk) if root is not None else None
            if scroller is not None:
                adjustment = scroller.get_vadjustment()
                lower = adjustment.get_lower()
                maximum = max(lower, adjustment.get_upper() - adjustment.get_page_size())
                if keyval in (Gdk.KEY_Home, getattr(Gdk, "KEY_KP_Home", -1)):
                    adjustment.set_value(lower)
                elif keyval in (Gdk.KEY_End, getattr(Gdk, "KEY_KP_End", -1)):
                    adjustment.set_value(maximum)
                else:
                    step = adjustment.get_page_increment()
                    if step <= 0:
                        step = max(adjustment.get_page_size() * 0.9, 40.0)
                    direction = -1 if keyval in (Gdk.KEY_Page_Up, getattr(Gdk, "KEY_KP_Page_Up", -1)) else 1
                    adjustment.set_value(min(maximum, max(lower, adjustment.get_value() + direction * step)))
            return True
        if listing is None or keyval not in tab_keys:
            return False
        focus = window.get_focus()
        modifiers = _state & blocked_tab_modifiers
        shift = keyval == getattr(Gdk, "KEY_ISO_Left_Tab", -1) or bool(_state & Gdk.ModifierType.SHIFT_MASK)
        if modifiers:
            return False
        if _is_descendant(focus, listing) and not shift:
            _focus_page(root, Gtk)
            return True
        if root is not None and _is_descendant(focus, root) and shift:
            focusables = _page_focusables(root, Gtk)
            if focusables and _is_descendant(focus, focusables[0]):
                focus_current_row()
                return True
        return False

    def bubble(_controller: Any, keyval: int, _keycode: int, _state: Any) -> bool:
        if listing is None:
            return False
        focus = window.get_focus()
        if keyval in right_keys and _is_descendant(focus, listing):
            _focus_page(get_content(), Gtk)
            return True
        root = get_content()
        if keyval in left_keys and root is not None and _is_descendant(focus, root):
            if _native_horizontal_control(focus, root, Gtk, Adw):
                return False
            return focus_current_row()
        return False

    capture_controller = Gtk.EventControllerKey.new()
    capture_controller.set_propagation_phase(Gtk.PropagationPhase.CAPTURE)
    capture_controller.connect("key-pressed", capture)
    window.add_controller(capture_controller)
    bubble_controller = Gtk.EventControllerKey.new()
    bubble_controller.set_propagation_phase(Gtk.PropagationPhase.BUBBLE)
    bubble_controller.connect("key-pressed", bubble)
    window.add_controller(bubble_controller)


def run_application(registry: dict[str, Plug], standalone: str | None) -> int:
    Adw, Gio, _GLib, Gtk = _gtk()
    from gi.repository import Gdk

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

        def install_shell_css(self) -> None:
            provider = Gtk.CssProvider()
            css = (
                "windowcontrols > button.close {"
                " background-color: @destructive_bg_color; color: @destructive_fg_color; }"
            )
            if hasattr(provider, "load_from_string"):
                provider.load_from_string(css)
            else:
                provider.load_from_data(css.encode("utf-8"))
            Gtk.StyleContext.add_provider_for_display(
                self.window.get_display(), provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

        def do_activate(self) -> None:
            if self.window is not None:
                self.window.present()
                return
            Adw.StyleManager.get_default().set_color_scheme(Adw.ColorScheme.PREFER_DARK)
            if self.standalone is not None:
                plug = self.registry[self.standalone]
                page, _scroller = _ensure_page_scroller(Gtk, plug.build_widget())
                self.window = Adw.ApplicationWindow(application=self)
                self.window.set_title(plug.title)
                self.window.set_default_size(720, 640)
                self.window.set_content(page)
                content = {"root": page}
                _install_page_keyboard(self.window, Gtk, Gdk, Adw, lambda: content["root"])
                self.install_optional_css()
                self.window.present()
                return

            split = Adw.NavigationSplitView()
            listing = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
            listing.set_activate_on_single_click(True)
            listing.add_css_class("navigation-sidebar")
            sidebar_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            sidebar_box.append(listing)
            app_title = _app_title()
            sidebar_bar = Adw.HeaderBar(show_end_title_buttons=False)
            sidebar_bar.set_title_widget(Adw.WindowTitle(title=app_title))
            sidebar_page = Adw.NavigationPage.new(_toolbar(Adw, sidebar_bar, sidebar_box), app_title)
            split.set_sidebar(sidebar_page)
            rows: dict[Any, Plug] = {}
            markers: dict[Any, Any] = {}
            first_row = None
            active = {"row": None, "content": None}
            for plug, depth in ordered_plugs(self.registry):
                row = Gtk.ListBoxRow()
                row.set_activatable(True)
                line = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                line.set_margin_start(12 + depth * 20)
                line.set_margin_end(12)
                line.set_margin_top(8)
                line.set_margin_bottom(8)
                line.append(Gtk.Image.new_from_icon_name(plug.icon))
                label = Gtk.Label(label=plug.title, xalign=0)
                label.set_hexpand(True)
                line.append(label)
                marker = Gtk.Image.new_from_icon_name("emblem-ok-symbolic")
                marker.set_tooltip_text("Currently displayed")
                marker.set_visible(False)
                line.append(marker)
                row.set_child(line)
                listing.append(row)
                rows[row] = plug
                markers[row] = marker
                if first_row is None or plug.ident == START_PLUG:
                    first_row = row

            def activate_row(_listing: Any, row: Any) -> None:
                plug = rows.get(row)
                if plug is None:
                    return
                page, _scroller = _ensure_page_scroller(Gtk, plug.build_widget())
                content_bar = Adw.HeaderBar(show_start_title_buttons=False, decoration_layout=":close")
                content_view = _toolbar(Adw, content_bar, page)
                split.set_content(Adw.NavigationPage.new(content_view, plug.title))
                split.set_show_content(True)
                active["content"] = page
                previous = active["row"]
                if previous is not None:
                    markers[previous].set_visible(False)
                active["row"] = row
                markers[row].set_visible(True)

            listing.connect("row-activated", activate_row)
            self.window = Adw.ApplicationWindow(application=self)
            self.window.set_title(app_title)
            self.window.set_default_size(1040, 720)
            self.window.set_content(split)
            self.install_shell_css()
            self.install_optional_css()
            _install_page_keyboard(
                self.window, Gtk, Gdk, Adw, lambda: active["content"], listing,
                lambda: active["row"],
            )
            if first_row is not None:
                listing.select_row(first_row)
                activate_row(listing, first_row)
            self.window.present()

    app = SettingsApplication()
    return app.run([sys.argv[0]])

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-gui-settings")
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
        print(f"agathodaimon-gui-settings: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

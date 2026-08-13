#!/usr/bin/env python3
"""One full-screen, two-pane Harmonia update experience.

The script deliberately uses only the engine surfaces discovered at runtime:
* /usr/local/sbin/agathodaimon/agathodaimon-harmonia-module-toggle when it is deployed;
* /usr/local/bin/harmonia interactable list/run; and
* /usr/local/bin/harmonia update --apply.

Current Harmonia exposes no interactable hide verb. Hide is local presentation
state in this script's own state file until the engine supplies a hide verb.
"""

import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

try:
    import gi
    gi.require_version("Gdk", "3.0")
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gdk, GLib, Gtk, Pango  # noqa: E402
except ImportError:
    Gdk = GLib = Gtk = Pango = None


HARMONIA = "/usr/local/bin/harmonia"
TOGGLE = "/usr/local/sbin/agathodaimon/agathodaimon-harmonia-module-toggle"
STATE_PATH = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "harmonia-update-modal/state.json"
RECEIPT_DIR = Path("/var/lib/harmonia/receipts/update-latest")
PROFILE_PATHS = (Path("/etc/profile.json"), Path("/etc/appliance/profile.json"))


RETRO_CSS = b"""
window.harmonia-update-modal {
  background-color: #d4d0c8;
  color: #202020;
}

.retro-header {
  min-height: 30px;
  padding: 2px 3px;
  background-image: linear-gradient(to bottom, #c6c3bd, #aaa7a1);
  border-top: 1px solid #f7f5ee;
  border-left: 1px solid #f7f5ee;
  border-bottom: 1px solid #6e6c67;
  border-right: 1px solid #6e6c67;
}

.retro-header-title {
  padding: 2px 6px;
  color: #202020;
  font-weight: bold;
}

.retro-close {
  min-width: 24px;
  min-height: 24px;
  padding: 0;
  font-weight: bold;
}

.pane-frame {
  margin: 10px;
  padding: 13px;
  background-color: #d4d0c8;
  border-top: 2px solid #808080;
  border-left: 2px solid #808080;
  border-bottom: 2px solid #ffffff;
  border-right: 2px solid #ffffff;
}

.pane-title {
  padding: 0 0 7px 0;
  color: #202020;
  font-weight: bold;
}

.pane-list, .pane-list row {
  background-color: #ece9df;
  color: #202020;
}

scrolledwindow.pane-scroll {
  border-top: 2px solid #808080;
  border-left: 2px solid #808080;
  border-bottom: 2px solid #ffffff;
  border-right: 2px solid #ffffff;
}

frame.diff-frame {
  padding: 2px;
  border-top: 2px solid #808080;
  border-left: 2px solid #808080;
  border-bottom: 2px solid #ffffff;
  border-right: 2px solid #ffffff;
}

textview.diff-view,
textview.diff-view text {
  font-family: monospace;
  background-color: #f4f1e8;
  color: #202020;
}

label.diff-omitted {
  color: #7d7b76;
  font-size: smaller;
}

button {
  min-height: 24px;
  padding: 3px 10px;
  border-radius: 0;
  box-shadow: none;
  background-image: none;
  background-color: #d4d0c8;
  color: #202020;
  border-top: 2px solid #ffffff;
  border-left: 2px solid #ffffff;
  border-bottom: 2px solid #70706c;
  border-right: 2px solid #70706c;
}

button:hover {
  background-image: none;
  background-color: #dfdcd4;
}

button.suggested-action {
  background-color: #4e9a06;
  color: #ffffff;
}

button.suggested-action:hover {
  background-color: #5eaf0a;
}

button:active {
  padding: 5px 8px 1px 12px;
  background-image: none;
  background-color: #bebbb4;
  border-top: 2px solid #70706c;
  border-left: 2px solid #70706c;
  border-bottom: 2px solid #ffffff;
  border-right: 2px solid #ffffff;
}

button:disabled {
  color: #7d7b76;
  background-image: none;
  background-color: #d4d0c8;
}

switch {
  border-radius: 0;
  box-shadow: none;
  background-color: #a9a69f;
  border-top: 2px solid #70706c;
  border-left: 2px solid #70706c;
  border-bottom: 2px solid #ffffff;
  border-right: 2px solid #ffffff;
}

switch slider {
  border-radius: 0;
  box-shadow: none;
  background-image: none;
  background-color: #d4d0c8;
  border-top: 2px solid #ffffff;
  border-left: 2px solid #ffffff;
  border-bottom: 2px solid #70706c;
  border-right: 2px solid #70706c;
}

paned > separator {
  min-width: 6px;
  background-color: #aaa7a1;
  border-left: 1px solid #ffffff;
  border-right: 1px solid #70706c;
}
"""


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def clean_text(value: Any, fallback: str = "") -> str:
    if isinstance(value, str):
        return value.strip()
    return fallback


def interactable_timestamp(item: dict[str, Any]) -> str:
    """Return the first engine timestamp in its declared precedence, if readable."""
    for key in ("available_at", "first_seen_at", "reported_at"):
        value = clean_text(item.get(key))
        if not value:
            continue
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.astimezone().strftime("%Y-%m-%d %H:%M %Z")
        except ValueError:
            # Preserve an engine timestamp we cannot parse rather than hiding it.
            return value
    return ""


class State:
    """Body-local presentation state, never an engine configuration surface."""

    def __init__(self) -> None:
        self.data: dict[str, Any] = {
            "schema": "harmonia.update-modal.state.v2",
            "hidden_interactables": [],
            "module_overrides": {},
        }
        try:
            value = json.loads(STATE_PATH.read_text(encoding="utf-8"))
            if isinstance(value, dict) and value.get("schema") in {
                "harmonia.update-modal.state.v1",
                self.data["schema"],
            }:
                self.data.update(value)
                self.data["schema"] = "harmonia.update-modal.state.v2"
        except (OSError, json.JSONDecodeError):
            pass

    def save(self) -> bool:
        try:
            STATE_PATH.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            temporary = STATE_PATH.with_suffix(".tmp")
            temporary.write_text(json.dumps(self.data, sort_keys=True) + "\n", encoding="utf-8")
            os.chmod(temporary, 0o600)
            temporary.replace(STATE_PATH)
            return True
        except OSError as error:
            print(f"harmonia-update-modal state write failed: {error}", file=sys.stderr)
            return False

    def hidden(self) -> set[str]:
        values = self.data.get("hidden_interactables", {})
        if isinstance(values, dict):
            return {ident for ident in values if isinstance(ident, str)}
        # Accept the v1 list written by earlier modal launches, then upgrade on hide.
        if isinstance(values, list):
            return {value for value in values if isinstance(value, str)}
        return set()

    def hidden_items(self) -> list[dict[str, Any]]:
        values = self.data.get("hidden_interactables", {})
        if isinstance(values, dict):
            return [
                item for ident, item in values.items()
                if isinstance(ident, str) and isinstance(item, dict) and clean_text(item.get("id"), ident)
            ]
        return [{"id": ident, "name": ident} for ident in sorted(self.hidden())]

    def hide(self, item: dict[str, Any]) -> bool:
        ident = clean_text(item.get("id"))
        if not ident:
            return False
        values = self.data.get("hidden_interactables", {})
        if not isinstance(values, dict):
            values = {old_ident: {"id": old_ident, "name": old_ident} for old_ident in self.hidden()}
        # Keep the complete status row so the ledger survives a changed engine response.
        values[ident] = item
        self.data["hidden_interactables"] = values
        return self.save()

    def unhide(self, ident: str) -> bool:
        values = self.data.get("hidden_interactables", {})
        if isinstance(values, dict):
            values.pop(ident, None)
            self.data["hidden_interactables"] = values
        elif isinstance(values, list):
            self.data["hidden_interactables"] = [value for value in values if value != ident]
        return self.save()

    def module_enabled(self, profile_id: str, module_id: str) -> bool:
        profiles = self.data.get("module_overrides", {})
        if not isinstance(profiles, dict):
            return True
        modules = profiles.get(profile_id, {})
        if not isinstance(modules, dict):
            return True
        value = modules.get(module_id)
        return value if isinstance(value, bool) else True

    def set_module_enabled(self, profile_id: str, module_id: str, enabled: bool) -> bool:
        profiles = self.data.setdefault("module_overrides", {})
        if not isinstance(profiles, dict):
            self.data["module_overrides"] = profiles = {}
        modules = profiles.setdefault(profile_id, {})
        if not isinstance(modules, dict):
            profiles[profile_id] = modules = {}
        modules[module_id] = enabled
        return self.save()


class HarmoniaUpdateModal(Gtk.Window):
    def __init__(self) -> None:
        super().__init__(title="Harmonia updates")
        self.install_retro_css()
        self.get_style_context().add_class("harmonia-update-modal")
        self.state = State()
        self.profile_id, self.profile = self.load_profile()
        self.modules = self.module_ids()
        self.module_enabled = self.read_module_enabled()
        self.interactables = self.read_interactables()
        self.pane_width = 0

        self.set_default_size(1280, 720)
        self.set_decorated(False)
        self.connect("destroy", Gtk.main_quit)
        self.connect("key-press-event", self.on_key_press)
        self.connect("window-state-event", self.on_window_state)

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        root.pack_start(self.make_header(), False, False, 0)
        panes = Gtk.Paned.new(Gtk.Orientation.HORIZONTAL)
        self.panes = panes
        panes.set_wide_handle(True)
        panes.add1(self.make_modules_pane())
        panes.add2(self.make_interactables_pane())
        panes.connect("size-allocate", self.center_panes)
        root.pack_start(panes, True, True, 0)
        self.add(root)
        self.show_all()
        self.fullscreen()

    @staticmethod
    def install_retro_css() -> None:
        provider = Gtk.CssProvider()
        provider.load_from_data(RETRO_CSS)
        screen = Gdk.Screen.get_default()
        if screen is not None:
            Gtk.StyleContext.add_provider_for_screen(
                screen, provider, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
            )

    def make_header(self) -> Gtk.Box:
        header = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        header.get_style_context().add_class("retro-header")
        title = Gtk.Label(label="Harmonia Update")
        title.set_xalign(0)
        title.set_hexpand(True)
        title.get_style_context().add_class("retro-header-title")
        close = Gtk.Button(label="X")
        close.set_tooltip_text("Close")
        close.get_style_context().add_class("retro-close")
        close.connect("clicked", self.on_close)
        header.pack_start(title, True, True, 0)
        header.pack_end(close, False, False, 0)
        return header

    def on_close(self, _button: Gtk.Button) -> None:
        self.destroy()

    def center_panes(self, panes: Gtk.Paned, allocation: Any) -> None:
        if allocation.width > 1 and allocation.width != self.pane_width:
            panes.set_position(allocation.width // 2)
            self.pane_width = allocation.width

    def on_window_state(self, _window: Gtk.Window, event: Any) -> bool:
        if event.new_window_state & Gdk.WindowState.FULLSCREEN:
            GLib.idle_add(self.center_current_panes)
        return False

    def center_current_panes(self) -> bool:
        width = self.panes.get_allocated_width()
        if width > 1:
            self.panes.set_position(width // 2)
            self.pane_width = width
        return False

    def on_key_press(self, _window: Gtk.Window, event: Any) -> bool:
        if event.keyval == 0xFF1B:  # Escape
            self.destroy()
            return True
        return False

    def load_profile(self) -> tuple[str, dict[str, Any]]:
        identity: dict[str, Any] = {}
        for path in PROFILE_PATHS:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(value, dict):
                    identity = value
                    break
            except (OSError, json.JSONDecodeError):
                continue
        profile_id = clean_text(identity.get("profile")) or clean_text(identity.get("id"))
        if not profile_id:
            raise RuntimeError("No profile id in /etc/profile.json or /etc/appliance/profile.json")
        index_path = Path("/etc/harmonia/profiles") / profile_id / "index.json"
        try:
            value = json.loads(index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise RuntimeError(f"Cannot read staged profile {index_path}: {error}") from error
        if not isinstance(value, dict):
            raise RuntimeError(f"Profile index is not an object: {index_path}")
        return profile_id, value

    def module_ids(self) -> list[str]:
        values = self.profile.get("modules", [])
        if not isinstance(values, list):
            return []
        return [module for module in values if isinstance(module, str) and module]

    def read_module_enabled(self) -> dict[str, bool]:
        default = {module: self.state.module_enabled(self.profile_id, module) for module in self.modules}
        if not os.path.isfile(TOGGLE) or not os.access(TOGGLE, os.X_OK):
            print(
                "harmonia-update-modal finding: module toggle actuator is not deployed; "
                "the displayed module state is local presentation state only",
                file=sys.stderr,
            )
            return default
        receipt = run(["sudo", "-n", TOGGLE, "list"])
        try:
            value = json.loads(receipt.stdout)
        except json.JSONDecodeError:
            return default
        disabled = value.get("disabled_modules", []) if isinstance(value, dict) else []
        if receipt.returncode != 0 or not isinstance(disabled, list):
            return default
        disabled_ids = {module for module in disabled if isinstance(module, str)}
        return {module: module not in disabled_ids for module in self.modules}

    def read_interactables(self) -> list[dict[str, Any]]:
        sample = os.environ.get("HARMONIA_UPDATE_MODAL_SAMPLE_JSON")
        if sample:
            try:
                value = json.loads(sample)
            except json.JSONDecodeError:
                print("harmonia-update-modal finding: invalid HARMONIA_UPDATE_MODAL_SAMPLE_JSON", file=sys.stderr)
                value = {}
        else:
            receipt = run([HARMONIA, "interactable", "list", "--json"])
            try:
                value = json.loads(receipt.stdout)
            except json.JSONDecodeError:
                print(
                    "harmonia-update-modal finding: the installed Harmonia binary does not expose "
                    "interactable list --json",
                    file=sys.stderr,
                )
                return []
        rows = value.get("interactables", []) if isinstance(value, dict) else []
        return [
            row for row in rows
            if isinstance(row, dict) and clean_text(row.get("id"))
        ]

    def pending_interactables(self) -> list[dict[str, Any]]:
        hidden = self.state.hidden()
        return [item for item in self.interactables if clean_text(item.get("id")) not in hidden]

    def pane(self, title: str) -> tuple[Gtk.Box, Gtk.ListBox]:
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        box.get_style_context().add_class("pane-frame")
        heading = Gtk.Label(label=title)
        heading.set_xalign(0)
        heading.get_style_context().add_class("pane-title")
        box.pack_start(heading, False, False, 0)
        scroll = Gtk.ScrolledWindow()
        scroll.get_style_context().add_class("pane-scroll")
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        listing = Gtk.ListBox()
        listing.get_style_context().add_class("pane-list")
        listing.set_selection_mode(Gtk.SelectionMode.NONE)
        scroll.add(listing)
        box.pack_start(scroll, True, True, 0)
        return box, listing

    def make_modules_pane(self) -> Gtk.Widget:
        pane, listing = self.pane("Modules")
        for module in self.modules:
            row = Gtk.ListBoxRow()
            content = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            name = Gtk.Label(label=module)
            name.set_xalign(0)
            name.set_hexpand(True)
            toggle = Gtk.Switch()
            toggle.set_active(self.module_enabled.get(module, True))
            toggle.connect("state-set", self.on_module_toggle, module)
            content.pack_start(name, True, True, 0)
            content.pack_end(toggle, False, False, 0)
            row.add(content)
            listing.add(row)

        self.update_button = Gtk.Button(label=self.update_label(""))
        self.update_button.connect("clicked", self.on_update)
        pane.pack_end(self.update_button, False, False, 0)
        return pane

    def make_interactables_pane(self) -> Gtk.Widget:
        pane = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        pane.get_style_context().add_class("pane-frame")
        heading = Gtk.Label(label="Updates")
        heading.set_xalign(0)
        heading.get_style_context().add_class("pane-title")
        pane.pack_start(heading, False, False, 0)
        # The notebook keeps the right side one pane while making hidden work visible.
        self.interactable_tabs = Gtk.Notebook()
        self.pending_listing = self.listing_page(self.interactable_tabs, "Pending")
        self.hidden_listing = self.listing_page(self.interactable_tabs, "Hidden ledger")
        pane.pack_start(self.interactable_tabs, True, True, 0)
        self.refresh_interactables()
        return pane

    @staticmethod
    def listing_page(notebook: Gtk.Notebook, title: str) -> Gtk.ListBox:
        scroll = Gtk.ScrolledWindow()
        scroll.get_style_context().add_class("pane-scroll")
        scroll.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        listing = Gtk.ListBox()
        listing.get_style_context().add_class("pane-list")
        listing.set_selection_mode(Gtk.SelectionMode.NONE)
        scroll.add(listing)
        notebook.append_page(scroll, Gtk.Label(label=title))
        return listing

    @staticmethod
    def clear_listing(listing: Gtk.ListBox) -> None:
        for child in listing.get_children():
            listing.remove(child)

    @staticmethod
    def diff_view(diff: str) -> Gtk.Frame:
        """Render a unified diff in a bounded, locally scrollable retro frame."""
        frame = Gtk.Frame()
        frame.set_shadow_type(Gtk.ShadowType.IN)
        frame.get_style_context().add_class("diff-frame")
        scroll = Gtk.ScrolledWindow()
        scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        scroll.set_min_content_height(120)
        scroll.set_max_content_height(360)
        scroll.set_propagate_natural_height(True)
        view = Gtk.TextView()
        view.set_editable(False)
        view.set_cursor_visible(False)
        view.set_wrap_mode(Gtk.WrapMode.NONE)
        view.set_left_margin(6)
        view.set_right_margin(6)
        view.get_style_context().add_class("diff-view")
        buffer = view.get_buffer()
        added = buffer.create_tag("added", background="#e2f0d9")
        removed = buffer.create_tag("removed", background="#f6dddd")
        hunk = buffer.create_tag("hunk", background="#dedbd3", weight=Pango.Weight.BOLD)
        for line in diff.splitlines(keepends=True):
            start_offset = buffer.get_char_count()
            buffer.insert(buffer.get_end_iter(), line)
            start = buffer.get_iter_at_offset(start_offset)
            end = buffer.get_end_iter()
            if line.startswith("@@"):
                buffer.apply_tag(hunk, start, end)
            elif line.startswith("+") and not line.startswith("+++"):
                buffer.apply_tag(added, start, end)
            elif line.startswith("-") and not line.startswith("---"):
                buffer.apply_tag(removed, start, end)
        scroll.add(view)
        frame.add(scroll)
        return frame

    def interactable_row(self, item: dict[str, Any], hidden: bool) -> Gtk.ListBoxRow:
        ident = clean_text(item.get("id"))
        name = clean_text(item.get("name"), ident)
        description = clean_text(item.get("description"), "no description provided")
        row = Gtk.ListBoxRow()
        expander = Gtk.Expander()
        expander.set_use_markup(False)
        summary = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        timestamp = interactable_timestamp(item)
        if timestamp:
            timestamp_label = Gtk.Label(label=timestamp)
            timestamp_label.set_xalign(0)
            summary.pack_start(timestamp_label, False, False, 0)
        name_label = Gtk.Label(label=name)
        name_label.set_xalign(0)
        summary.pack_start(name_label, False, False, 0)
        expander.set_label_widget(summary)
        detail = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        description_label = Gtk.Label(label=description)
        description_label.set_xalign(0)
        description_label.set_line_wrap(True)
        detail.pack_start(description_label, False, False, 0)
        diff = item.get("diff")
        if isinstance(diff, str) and diff:
            detail.pack_start(self.diff_view(diff), False, True, 0)
        elif "diff_omitted" in item:
            omitted = Gtk.Label(label=f"diff omitted: {clean_text(item.get('diff_omitted'), 'unspecified')}")
            omitted.set_xalign(0)
            omitted.get_style_context().add_class("diff-omitted")
            detail.pack_start(omitted, False, False, 0)
        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        if hidden:
            unhide = Gtk.Button(label="Un-hide")
            unhide.connect("clicked", self.on_unhide, ident)
            actions.pack_start(unhide, False, False, 0)
        else:
            agree = Gtk.Button(label="Agree")
            agree.get_style_context().add_class("suggested-action")
            agree.connect("clicked", self.on_agree, ident)
            hide = Gtk.Button(label="Hide")
            hide.connect("clicked", self.on_hide, item)
            for button in (agree, hide):
                button.set_size_request(120, -1)
            actions.pack_start(agree, False, False, 0)
            actions.pack_start(hide, False, False, 0)
        detail.pack_start(actions, False, False, 0)
        expander.add(detail)
        row.add(expander)
        return row

    def refresh_interactables(self) -> None:
        self.clear_listing(self.pending_listing)
        self.clear_listing(self.hidden_listing)
        for item in self.pending_interactables():
            self.pending_listing.add(self.interactable_row(item, hidden=False))
        live_by_id = {clean_text(item.get("id")): item for item in self.interactables}
        for stored in self.state.hidden_items():
            ident = clean_text(stored.get("id"))
            self.hidden_listing.add(self.interactable_row(live_by_id.get(ident, stored), hidden=True))
        self.pending_listing.show_all()
        self.hidden_listing.show_all()
        if hasattr(self, "update_button"):
            self.update_button.set_label(self.update_label(""))

    def update_label(self, suffix: str) -> str:
        label = f"Update Now ({len(self.pending_interactables())})"
        return f"{label} · {suffix}" if suffix else label

    def in_background(self, work: Callable[[], tuple[bool, str]]) -> None:
        def runner() -> None:
            success, detail = work()
            GLib.idle_add(self.update_button.set_label, self.update_label(detail))
            GLib.idle_add(self.update_button.set_sensitive, True)

        threading.Thread(target=runner, daemon=True).start()

    def on_module_toggle(self, toggle: Gtk.Switch, enabled: bool, module: str) -> bool:
        previous = self.module_enabled.get(module, True)
        toggle.set_sensitive(False)

        def work() -> tuple[bool, str]:
            if os.path.isfile(TOGGLE) and os.access(TOGGLE, os.X_OK):
                action = "on" if enabled else "off"
                receipt = run(["sudo", "-n", TOGGLE, module, action])
                success = receipt.returncode == 0
            else:
                success = self.state.set_module_enabled(self.profile_id, module, enabled)
            self.module_enabled[module] = enabled if success else previous
            GLib.idle_add(toggle.set_active, self.module_enabled[module])
            GLib.idle_add(toggle.set_sensitive, True)
            return success, "module changed" if success else "module refused"

        self.in_background(work)
        return True

    def on_agree(self, _button: Gtk.Button, ident: str) -> None:
        self.update_button.set_sensitive(False)

        def work() -> tuple[bool, str]:
            receipt = run(["sudo", "-n", HARMONIA, "interactable", "run", ident])
            success = receipt.returncode == 0
            if success:
                self.interactables = [item for item in self.interactables if clean_text(item.get("id")) != ident]
                GLib.idle_add(self.refresh_interactables)
            return success, "agreed" if success else "agree refused"

        self.in_background(work)

    def on_hide(self, _button: Gtk.Button, item: dict[str, Any]) -> None:
        if self.state.hide(item):
            self.refresh_interactables()
            self.update_button.set_label(self.update_label("hidden"))
        else:
            self.update_button.set_label(self.update_label("hide refused"))

    def on_unhide(self, _button: Gtk.Button, ident: str) -> None:
        if self.state.unhide(ident):
            self.refresh_interactables()
            self.update_button.set_label(self.update_label("restored"))
        else:
            self.update_button.set_label(self.update_label("un-hide refused"))

    def on_update(self, _button: Gtk.Button) -> None:
        self.update_button.set_sensitive(False)
        self.update_button.set_label(self.update_label("running"))

        def work() -> tuple[bool, str]:
            receipt = run([
                "sudo",
                "-n",
                HARMONIA,
                "update",
                "--apply",
                "--receipt-dir",
                str(RECEIPT_DIR),
            ])
            report = self.read_update_receipt()
            if report:
                return receipt.returncode == 0 and report[0], report[1]
            return receipt.returncode == 0, "complete" if receipt.returncode == 0 else "failed"

        self.in_background(work)

    def read_update_receipt(self) -> tuple[bool, str] | None:
        candidates = sorted(RECEIPT_DIR.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        for path in candidates:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or not isinstance(value.get("ok"), bool):
                continue
            signal = clean_text(value.get("first_missing_signal"))
            if value["ok"]:
                return True, "ok"
            return False, signal or "not ok"
        return None


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="agathodaimon-gui-update-modal")
    parser.parse_args(argv)
    if Gtk is None:
        print("{\"schema\":\"agathodaimon.gui.update-modal.v1\",\"ok\":true,\"mutationPerformed\":false,\"firstMissingSignal\":\"gui-runtime-unavailable\"}")
        return 0
    try:
        HarmoniaUpdateModal()
    except RuntimeError as error:
        print(f"harmonia-update-modal: {error}", file=sys.stderr)
        return 1
    Gtk.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

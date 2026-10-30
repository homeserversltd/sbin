"""Harmonia Updates plug using Caduceus HTTP doors."""
from __future__ import annotations

import importlib.util

import re
import sys
import threading
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from typing import Any, Callable

try:
    from ._common import _receipt_ok, _request, _signal
except ImportError:
    _common_path = Path(__file__).with_name("_common.py")
    _common_spec = importlib.util.spec_from_file_location("_common", _common_path)
    if _common_spec is None or _common_spec.loader is None:
        raise
    _common_module = importlib.util.module_from_spec(_common_spec)
    sys.modules["_common"] = _common_module
    _common_spec.loader.exec_module(_common_module)
    from _common import _receipt_ok, _request, _signal


PLUG = {
    "id": "harmonia-updates",
    "title": "Updates",
    "icon": "software-update-available-symbolic",
    "order": 10,
    "parent": None,
}

STATUS_DOOR = "/api/v1/update/status"
TIMER_DOOR = "/api/v1/update/service/status"
TIMER_TOGGLE_DOOR = "/api/v1/update/service/toggle"
UPDATE_DOOR = "/api/v1/update/now"
MODULES_DOOR = "/api/v1/update/modules"
HISTORY_DOOR = "/api/v1/update/history"
INTERACTABLES_DOOR = "/api/v1/interactables"
STATUS_SCHEMA = "caduceus.update.status.v1"
HISTORY_SCHEMA = "caduceus.update.history.v1"

_MODULE_CARD_CLASS: Any = None


def _module_card_class(Gtk: Any) -> Any:
    global _MODULE_CARD_CLASS
    if _MODULE_CARD_CLASS is None:
        class ModuleSquareCardLayout(Gtk.LayoutManager):
            __gtype_name__ = "AgathodaimonHarmoniaModuleSquareCardLayout"

            def do_get_request_mode(self, widget: Any) -> Any:
                return Gtk.SizeRequestMode.HEIGHT_FOR_WIDTH

            def do_measure(
                self,
                widget: Any,
                orientation: Any,
                for_size: int,
            ) -> tuple[int, int, int, int]:
                content = widget.get_first_child()
                if content is None:
                    return 0, 0, -1, -1

                if orientation == Gtk.Orientation.HORIZONTAL:
                    minimum, _, _, _ = content.measure(orientation, for_size)
                    minimum = max(176, minimum)
                    natural = max(176, minimum)
                    return minimum, natural, -1, -1

                minimum, natural, _, _ = content.measure(orientation, for_size)
                square = max(176 if for_size < 0 else for_size, minimum)
                return square, max(square, natural), -1, -1

            def do_allocate(self, widget: Any, width: int, height: int, baseline: int) -> None:
                content = widget.get_first_child()
                if content is not None:
                    content.allocate(width, height, baseline, None)

        class ModuleSquareCard(Gtk.Box):
            __gtype_name__ = "AgathodaimonHarmoniaModuleSquareCard"

            def __init__(self) -> None:
                super().__init__(orientation=Gtk.Orientation.VERTICAL)
                self.set_layout_manager(ModuleSquareCardLayout())
                self.add_css_class("card")
                self.set_hexpand(True)
                self.set_vexpand(True)
                self.content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
                self.content.set_hexpand(True)
                self.content.set_vexpand(True)
                for edge in ("top", "bottom", "start", "end"):
                    getattr(self.content, f"set_margin_{edge}")(12)
                self.append(self.content)

        _MODULE_CARD_CLASS = ModuleSquareCard
    return _MODULE_CARD_CLASS


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _duration(milliseconds: int) -> str:
    seconds = round(milliseconds / 1000)
    if seconds < 60:
        return f"{max(seconds, 1)} s" if milliseconds else "0 s"
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes} min {seconds} s" if seconds else f"{minutes} min"


def _humanize(identifier: str) -> str:
    words = [word for word in re.split(r"[-_]+", identifier) if word]
    return " ".join(word[:1].upper() + word[1:] for word in words) or identifier


def _receipt_error(receipt: Any, fallback: str) -> str:
    if isinstance(receipt, dict):
        signal = _text(_signal(receipt))
        if signal:
            return signal
    return fallback


def _parse_finished_at(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    try:
        return parsed.astimezone(timezone.utc)
    except (OverflowError, ValueError):
        return None


def _local_time(value: Any) -> str:
    parsed = _parse_finished_at(value)
    if parsed is None:
        return "Time unavailable"
    local = parsed.astimezone()
    rendered = local.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    return rendered or local.isoformat(timespec="seconds")


def _run_sort_key(run: dict[str, Any]) -> tuple[int, float]:
    parsed = _parse_finished_at(run.get("finished_at"))
    if parsed is None:
        return (1, 0.0)
    return (0, -parsed.timestamp())


def _normalise_history(runs: list[Any]) -> list[dict[str, Any]] | None:
    normalized: list[dict[str, Any]] = []
    for item in runs:
        if not isinstance(item, dict):
            return None
        if not isinstance(item.get("run_id"), str):
            return None
        finished_at = item.get("finished_at")
        outcome = item.get("outcome")
        duration = item.get("duration_ms")
        module_count = item.get("module_count")
        updated_count = item.get("updated_count")
        raw_failures = item.get("failures")
        if finished_at is not None and not isinstance(finished_at, str):
            return None
        if outcome not in (None, "ok", "failed"):
            return None
        if duration is not None and (type(duration) is not int or duration < 0):
            return None
        if module_count is not None and (type(module_count) is not int or module_count < 0):
            return None
        if updated_count is not None and (type(updated_count) is not int or updated_count < 0):
            return None
        if not isinstance(raw_failures, list):
            return None
        failures: list[dict[str, str]] = []
        for failure in raw_failures:
            if not isinstance(failure, dict):
                return None
            module = failure.get("module")
            signal = failure.get("signal")
            if not isinstance(module, str) or not isinstance(signal, str):
                return None
            failures.append({"module": module, "signal": signal})
        normalized.append(
            {
                "finished_at": finished_at,
                "outcome": outcome,
                "duration_ms": duration,
                "module_count": module_count,
                "updated_count": updated_count,
                "failures": failures,
            }
        )
    normalized.sort(key=_run_sort_key)
    return normalized[:10]


def build_widget() -> Any:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    ModuleSquareCard = _module_card_class(Gtk)

    reads = {name: 0 for name in ("status", "timer", "modules", "interactables", "history")}
    data: dict[str, Any] = {
        "alive": True,
        "status_ready": False,
        "status_error": "",
        "timer_known": False,
        "timer_enabled": False,
        "timer_busy": False,
        "timer_pending": None,
        "timer_message": "Reading Caduceus…",
        "modules_ready": False,
        "modules_error": "",
        "modules": [],
        "module_sequence": 0,
        "module_pending": {},
        "module_errors": {},
        "interactables_ready": False,
        "interactables_error": "",
        "interactables": [],
        "agree_sequence": 0,
        "agree_busy": {},
        "agree_messages": {},
        "history_ready": False,
        "history_error": "",
        "history": [],
        "update_busy": False,
        "update_sequence": 0,
        "update_message": "",
        "update_message_is_error": None,
        "refresh_source": None,
    }

    stack = Gtk.Stack(hexpand=True, vexpand=True)
    updates_page = Adw.PreferencesPage(title="Updates", icon_name=PLUG["icon"])
    history_page = Adw.PreferencesPage(title="History", icon_name=PLUG["icon"])
    stack.add_named(updates_page, "updates")
    stack.add_named(history_page, "history")
    stack.set_visible_child_name("updates")

    status_group = Adw.PreferencesGroup(title="Update status")
    updates_page.add(status_group)
    status_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    status_card.add_css_class("card")
    for edge in ("top", "bottom", "start", "end"):
        getattr(status_card, f"set_margin_{edge}")(12)
    status_group.add(status_card)
    headline_label = Gtk.Label(label="Update status unavailable", xalign=0, wrap=True)
    headline_label.add_css_class("title-4")
    status_card.append(headline_label)
    last_update_label = Gtk.Label(label="Last update time unavailable", xalign=0, wrap=True)
    last_update_label.add_css_class("dim-label")
    status_card.append(last_update_label)
    outcomes_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    status_card.append(outcomes_box)
    failure_signals_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    status_card.append(failure_signals_box)
    status_error_label = Gtk.Label(xalign=0, wrap=True)
    status_error_label.add_css_class("error")
    status_card.append(status_error_label)
    update_message_label = Gtk.Label(xalign=0, wrap=True)
    status_card.append(update_message_label)
    update_button = Gtk.Button(label="Update Now (?)", valign=Gtk.Align.CENTER)
    status_card.append(update_button)
    history_list = Gtk.ListBox()
    history_list.set_selection_mode(Gtk.SelectionMode.NONE)
    history_list.set_activate_on_single_click(True)
    history_row = Adw.ActionRow(title="History", subtitle="Last 10 update runs")
    history_row.set_activatable(True)
    history_row.add_suffix(Gtk.Image.new_from_icon_name("go-next-symbolic"))
    history_list.append(history_row)
    status_card.append(history_list)

    timer_group = Adw.PreferencesGroup(title="Automatic updates")
    updates_page.add(timer_group)
    timer_row = Adw.ActionRow(
        title="Automatic updates",
        subtitle="Install available updates automatically on schedule.",
    )
    timer_switch = Gtk.Switch(valign=Gtk.Align.CENTER)
    timer_switch.set_sensitive(False)
    timer_switch.set_visible(False)
    timer_row.add_suffix(timer_switch)
    timer_group.add(timer_row)
    timer_message_label = Gtk.Label(label="Reading Caduceus…", xalign=0, wrap=True)
    timer_group.add(timer_message_label)

    pending_group = Adw.PreferencesGroup(title="Pending updates")
    updates_page.add(pending_group)
    pending_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    pending_group.add(pending_box)

    silenced_group = Adw.PreferencesGroup(title="Silenced updates")
    updates_page.add(silenced_group)
    silenced_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    silenced_group.add(silenced_box)

    modules_group = Adw.PreferencesGroup(title="Update modules")
    updates_page.add(modules_group)
    module_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    module_flow = Gtk.FlowBox()
    module_flow.set_selection_mode(Gtk.SelectionMode.NONE)
    module_flow.set_homogeneous(True)
    module_flow.set_min_children_per_line(2)
    module_flow.set_max_children_per_line(3)
    module_flow.set_column_spacing(12)
    module_flow.set_row_spacing(12)
    module_box.append(module_flow)
    module_empty_label = Gtk.Label(label="No update modules were reported.", xalign=0, wrap=True)
    module_empty_label.add_css_class("dim-label")
    module_empty_label.set_visible(False)
    module_box.append(module_empty_label)
    module_error_label = Gtk.Label(xalign=0, wrap=True)
    module_error_label.add_css_class("error")
    module_box.append(module_error_label)
    modules_group.add(module_box)

    history_group = Adw.PreferencesGroup(title="Update history")
    history_page.add(history_group)
    back_row = Adw.ActionRow(title="Back to Updates", subtitle="Return to update status")
    back_row.set_activatable(True)
    back_row.add_suffix(Gtk.Image.new_from_icon_name("go-previous-symbolic"))
    history_group.add(back_row)
    history_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
    history_group.add(history_box)

    def clear(box: Any) -> None:
        child = box.get_first_child()
        while child is not None:
            following = child.get_next_sibling()
            box.remove(child)
            child = following

    def append_message(box: Any, message: str, *, error: bool = False) -> Any:
        label = Gtk.Label(label=message, xalign=0, wrap=True)
        label.add_css_class("error" if error else "dim-label")
        box.append(label)
        return label

    def make_card() -> Any:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.add_css_class("card")
        for edge in ("top", "bottom", "start", "end"):
            getattr(card, f"set_margin_{edge}")(12)
        return card

    def post_to_ui(callback: Callable[..., bool], *args: Any) -> None:
        try:
            GLib.idle_add(callback, *args)
        except RuntimeError:
            return

    def read_door(path: str, callback: Callable[..., bool], *args: Any) -> None:
        try:
            receipt = _request(path)
            post_to_ui(callback, receipt, None, *args)
        except Exception as error:  # transport failures remain visible in the pane
            post_to_ui(callback, None, str(error), *args)

    def mutate_door(
        path: str,
        payload: dict[str, Any] | None,
        callback: Callable[..., bool],
        *args: Any,
        empty_body: bool = False,
    ) -> None:
        try:
            receipt = _request(path, "POST", payload, empty_body=True) if empty_body else _request(path, "POST", payload)
            post_to_ui(callback, receipt, None, *args)
        except Exception as error:  # transport failures remain visible in the pane
            post_to_ui(callback, None, str(error), *args)

    def render_status() -> None:
        pending = [item for item in data["interactables"] if not item["silenced"]]
        count_text = str(len(pending)) if data["interactables_ready"] else "?"
        update_button.set_label(f"Update Now ({count_text})")
        update_button.set_sensitive(data["status_ready"] and not data["update_busy"])

        latest_failed = _latest_run_failed(data["history"]) if data["history_ready"] else None
        headline = "Update status unavailable"
        style = "error"
        if data["status_ready"] and data["interactables_ready"] and data["history_ready"]:
            if latest_failed is True:
                headline = "Last update failed"
                style = "error"
            elif latest_failed is None and data["history"]:
                headline = "Update status unavailable"
                style = "error"
            elif pending:
                headline = f"{len(pending)} updates waiting"
                style = ""
            else:
                headline = "Up to date"
                style = "success"
        headline_label.set_text(headline)
        for css_class in ("success", "error"):
            headline_label.remove_css_class(css_class)
        if style:
            headline_label.add_css_class(style)

        history = data["history"] if data["history_ready"] else []
        if history and isinstance(history[0].get("finished_at"), str):
            last_update_label.set_text(f"Last update: {_local_time(history[0]['finished_at'])}")
        else:
            last_update_label.set_text("Last update time unavailable")

        clear(outcomes_box)
        if not data["history_ready"]:
            label = Gtk.Label(label="History unavailable")
            label.add_css_class("error")
            outcomes_box.append(label)
        elif not history:
            label = Gtk.Label(label="No update runs recorded")
            label.add_css_class("dim-label")
            outcomes_box.append(label)
        else:
            for run in history[:10]:
                outcome = run["outcome"]
                label_text = {"ok": "OK", "failed": "Failed", None: "Unknown"}[outcome]
                label = Gtk.Label(label=label_text)
                label.add_css_class(
                    "success" if outcome == "ok" else "error" if outcome == "failed" else "dim-label"
                )
                outcomes_box.append(label)

        clear(failure_signals_box)
        if latest_failed is True and history:
            failures = history[0]["failures"]
            if failures:
                for failure in failures[:3]:
                    module = _text(failure["module"]) or "Unknown module"
                    signal = _text(failure["signal"]) or "No signal returned"
                    if len(module) > 64:
                        module = module[:61].rstrip() + "…"
                    if len(signal) > 180:
                        signal = signal[:177].rstrip() + "…"
                    label = Gtk.Label(label=f"{module}: {signal}", xalign=0, wrap=True)
                    label.add_css_class("error")
                    failure_signals_box.append(label)
                if len(failures) > 3:
                    more_label = Gtk.Label(label="Further failure signals are in History.", xalign=0, wrap=True)
                    more_label.add_css_class("dim-label")
                    failure_signals_box.append(more_label)
            else:
                append_message(failure_signals_box, "No failure signal was returned.", error=True)

        status_error = data["status_error"]
        if not data["status_ready"] and not status_error:
            status_error = "Update status unavailable."
        status_error_label.set_text(status_error)
        status_error_label.set_visible(bool(status_error))
        update_message_label.set_text(data["update_message"])
        update_message_label.set_visible(bool(data["update_message"]))
        update_message_label.remove_css_class("success")
        update_message_label.remove_css_class("error")
        update_message_label.remove_css_class("dim-label")
        if data["update_message"]:
            is_error = data["update_message_is_error"]
            update_message_label.add_css_class(
                "error" if is_error is True else "success" if is_error is False else "dim-label"
            )

    def _latest_run_failed(runs: list[dict[str, Any]]) -> bool | None:
        if not runs:
            return False
        if any(_parse_finished_at(run["finished_at"]) is None for run in runs):
            return None
        outcome = runs[0]["outcome"]
        return None if outcome is None else outcome == "failed"

    def render_timer() -> None:
        known = data["timer_known"]
        timer_switch.set_visible(known)
        timer_switch.set_sensitive(known and not data["timer_busy"] and data["timer_pending"] is None)
        if known:
            timer_switch.set_active(data["timer_enabled"])
        message = data["timer_message"]
        timer_message_label.set_text(message)
        timer_message_label.set_visible(bool(message))
        timer_message_label.remove_css_class("success")
        timer_message_label.remove_css_class("error")
        if message:
            timer_message_label.add_css_class(
                "error" if "unavailable" in message.lower() or "refus" in message.lower() else "dim-label"
            )

    def render_modules() -> None:
        clear(module_flow)
        module_empty_label.set_visible(False)
        if not data["modules_ready"]:
            module_error_label.set_text(data["modules_error"] or "Update modules unavailable.")
            module_error_label.set_visible(True)
            return
        module_error_label.set_text(data["modules_error"])
        module_error_label.set_visible(bool(data["modules_error"]))
        module_empty_label.set_visible(data["modules_ready"] and not data["modules"])
        if not data["modules"]:
            return

        for item in data["modules"]:
            identifier = item["id"]
            pending = data["module_pending"].get(identifier)
            known = type(item["enabled"]) is bool
            enabled = item["enabled"] if known else False
            if pending is not None:
                enabled = pending["requested"]
            card = ModuleSquareCard()
            content = card.content

            title = _text(item["title"]) or _humanize(identifier)
            title_label = Gtk.Label(label=title, xalign=0, wrap=True)
            title_label.add_css_class("title-4")
            content.append(title_label)
            summary = _text(item["summary"])
            if summary:
                summary_label = Gtk.Label(label=summary, xalign=0, wrap=True)
                summary_label.add_css_class("dim-label")
                content.append(summary_label)

            if pending is not None:
                setting_message = "Waiting for Caduceus confirmation…"
            elif not known:
                setting_message = "Module setting unavailable."
            else:
                setting_message = ""
            setting_label = Gtk.Label(label=setting_message, xalign=0, wrap=True)
            setting_label.add_css_class("error" if not known and pending is None else "dim-label")
            setting_label.set_visible(bool(setting_message))
            content.append(setting_label)

            control_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            control_row.set_vexpand(True)
            control_row.set_valign(Gtk.Align.END)
            module_switch = Gtk.Switch(active=enabled, valign=Gtk.Align.CENTER)
            module_switch.update_property(
                [Gtk.AccessibleProperty.LABEL],
                [f"Enable {title} module"],
            )
            module_switch.set_sensitive(known and pending is None)
            control_row.append(module_switch)
            content.append(control_row)
            module_switch.connect("state-set", toggle_module, identifier)

            error_message = data["module_errors"].get(identifier, "")
            if error_message:
                error_label = Gtk.Label(label=error_message, xalign=0, wrap=True)
                error_label.add_css_class("error")
                content.append(error_label)
            module_flow.append(card)

    def render_pending() -> None:
        clear(pending_box)
        if not data["interactables_ready"]:
            append_message(
                pending_box,
                data["interactables_error"] or "Pending updates unavailable.",
                error=True,
            )
            render_silenced()
            return
        visible_items = [item for item in data["interactables"] if not item["silenced"]]
        if not visible_items:
            append_message(pending_box, "No pending updates.")
        for item in visible_items:
            identifier = item["id"]
            card = make_card()
            title = item["name"] or _humanize(identifier)
            title_label = Gtk.Label(label=title, xalign=0, wrap=True)
            title_label.add_css_class("title-4")
            card.append(title_label)
            summary = item["summary"]
            if summary:
                summary_label = Gtk.Label(label=summary, xalign=0, wrap=True)
                summary_label.add_css_class("dim-label")
                card.append(summary_label)
            message = data["agree_messages"].get(identifier, "")
            if message:
                message_label = Gtk.Label(label=message, xalign=0, wrap=True)
                message_label.add_css_class("error" if "refus" in message.lower() else "dim-label")
                card.append(message_label)

            actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            agree_button = Gtk.Button(label="Agree", valign=Gtk.Align.CENTER)
            agree_button.set_sensitive(identifier not in data["agree_busy"])
            agree_button.connect("clicked", agree, identifier)
            disagree_button = Gtk.Button(label="Disagree", valign=Gtk.Align.CENTER)
            disagree_button.set_sensitive(False)
            disagree_button.set_tooltip_text("No admitted Disagree door.")
            silence_button = Gtk.Button(label="Silence", valign=Gtk.Align.CENTER)
            silence_button.set_sensitive(identifier not in data["agree_busy"])
            silence_button.connect("clicked", set_silence, identifier, True)
            actions.append(agree_button)
            actions.append(disagree_button)
            actions.append(silence_button)
            card.append(actions)
            pending_box.append(card)
        render_silenced()

    def render_silenced() -> None:
        clear(silenced_box)
        items = [item for item in data["interactables"] if item["silenced"]] if data["interactables_ready"] else []
        silenced_group.set_visible(bool(items))
        for item in items:
            identifier = item["id"]
            card = make_card()
            title = item.get("name") or _humanize(identifier)
            title_label = Gtk.Label(label=title, xalign=0, wrap=True)
            title_label.add_css_class("title-4")
            card.append(title_label)
            summary = item.get("summary", "")
            if summary:
                summary_label = Gtk.Label(label=summary, xalign=0, wrap=True)
                summary_label.add_css_class("dim-label")
                card.append(summary_label)
            message = data["agree_messages"].get(identifier, "")
            if message:
                append_message(card, message, error=True)
            restore = Gtk.Button(label="Unsilence", valign=Gtk.Align.CENTER)
            restore.set_sensitive(identifier not in data["agree_busy"])
            restore.connect("clicked", set_silence, identifier, False)
            card.append(restore)
            silenced_box.append(card)

    def render_history() -> None:
        clear(history_box)
        if not data["history_ready"]:
            append_message(
                history_box,
                data["history_error"] or "Update history unavailable.",
                error=True,
            )
            return
        if not data["history"]:
            append_message(history_box, "No update runs are recorded.")
            return
        for run in data["history"][:10]:
            card = make_card()
            outcome = run["outcome"]
            title_text = {"ok": "Update completed", "failed": "Update failed", None: "Outcome unavailable"}[outcome]
            title_label = Gtk.Label(label=title_text, xalign=0, wrap=True)
            title_label.add_css_class("title-4")
            title_label.add_css_class(
                "success" if outcome == "ok" else "error" if outcome == "failed" else "dim-label"
            )
            card.append(title_label)
            time_label = Gtk.Label(label=_local_time(run["finished_at"]), xalign=0, wrap=True)
            time_label.add_css_class("dim-label")
            card.append(time_label)

            duration = run["duration_ms"]
            module_count = run["module_count"]
            updated_count = run["updated_count"]
            details = [f"took {_duration(duration)}" if duration is not None else "Duration unavailable"]
            details.append(f"{module_count} modules" if module_count is not None else "Module count unavailable")
            details.append(f"{updated_count} updated" if updated_count is not None else "Updated count unavailable")
            details_label = Gtk.Label(label=" · ".join(details), xalign=0, wrap=True)
            details_label.add_css_class("dim-label")
            card.append(details_label)

            if outcome == "failed" and not run["failures"]:
                append_message(card, "No failure signal was returned.", error=True)
            for failure in run["failures"]:
                failure_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                failure_text = f"{failure['module']}: {failure['signal']}"
                signal_label = Gtk.Label(label=failure_text, xalign=0, wrap=True, selectable=True, hexpand=True)
                signal_label.add_css_class("monospace")
                failure_row.append(signal_label)
                copy_button = Gtk.Button(label="Copy", valign=Gtk.Align.CENTER)
                clipboard_text = f"{run['finished_at'] or ''} {failure['module']}: {failure['signal']}"
                copy_button.connect("clicked", copy_failure, clipboard_text)
                failure_row.append(copy_button)
                card.append(failure_row)
            history_box.append(card)

    def copy_failure(_button: Any, text: str) -> None:
        display = _button.get_display()
        if display is not None:
            display.get_clipboard().set(text)

    def _refresh_headline() -> None:
        render_status()

    def finish_status(receipt: Any, error: str | None, generation: int) -> bool:
        if generation != reads["status"] or not data["alive"]:
            return False
        data["status_ready"] = False
        data["status_error"] = ""
        if error:
            data["status_error"] = error
        elif not isinstance(receipt, dict) or receipt.get("schema") != STATUS_SCHEMA or not _receipt_ok(receipt):
            data["status_error"] = _receipt_error(receipt, "Update status read refused.")
        elif any(receipt.get(field) is not True for field in ("profilePresent", "statePresent", "routePresent")):
            data["status_error"] = _receipt_error(receipt, "Update status prerequisites are unavailable.")
        else:
            data["status_ready"] = True
        _refresh_headline()
        return False

    def finish_timer(receipt: Any, error: str | None, generation: int) -> bool:
        if generation != reads["timer"] or not data["alive"] or data["timer_busy"]:
            return False
        data["timer_known"] = False
        if error:
            data["timer_message"] = error
        elif not isinstance(receipt, dict) or not _receipt_ok(receipt):
            data["timer_message"] = _receipt_error(receipt, "Automatic-update status read refused.")
        elif type(receipt.get("enabled")) is not bool:
            data["timer_message"] = _receipt_error(receipt, "Automatic-update status unavailable: enabled is not a boolean.")
        else:
            enabled = receipt["enabled"]
            pending = data["timer_pending"]
            data["timer_enabled"] = enabled
            data["timer_known"] = True
            if pending is not None:
                if enabled != pending["requested"]:
                    data["timer_message"] = "Automatic-update change was not confirmed by Caduceus."
                else:
                    data["timer_message"] = "Automatic-update setting confirmed."
                data["timer_pending"] = None
            else:
                data["timer_message"] = "Automatic updates are on." if enabled else "Automatic updates are off."
        render_timer()
        return False

    def finish_modules(receipt: Any, error: str | None, generation: int) -> bool:
        if generation != reads["modules"] or not data["alive"]:
            return False
        data["modules_ready"] = False
        data["modules_error"] = ""
        if error:
            data["modules_error"] = error
        elif not isinstance(receipt, dict) or not _receipt_ok(receipt) or not isinstance(receipt.get("modules"), list):
            data["modules_error"] = _receipt_error(receipt, "Update-module read refused.")
        else:
            modules: list[dict[str, Any]] = []
            seen: set[str] = set()
            for item in receipt["modules"]:
                if not isinstance(item, dict):
                    continue
                identifier = _text(item.get("id"))
                if not identifier or identifier in seen:
                    continue
                seen.add(identifier)
                enabled = item.get("enabled") if type(item.get("enabled")) is bool else None
                title = item.get("title") if isinstance(item.get("title"), str) else ""
                summary = item.get("summary") if isinstance(item.get("summary"), str) else ""
                modules.append(
                    {
                        "id": identifier,
                        "enabled": enabled,
                        "title": title,
                        "summary": summary,
                    }
                )
            data["modules"] = modules
            data["modules_ready"] = True
            for identifier, pending in list(data["module_pending"].items()):
                observed = next((item["enabled"] for item in modules if item["id"] == identifier), None)
                if pending["phase"] == "confirming" and type(observed) is bool:
                    data["module_pending"].pop(identifier, None)
                    if observed != pending["requested"]:
                        data["module_errors"][identifier] = "Module change was not confirmed by Caduceus."
                    else:
                        data["module_errors"].pop(identifier, None)
        render_modules()
        return False

    def _normalise_interactables(receipt: Any) -> list[dict[str, Any]] | None:
        if not isinstance(receipt, dict) or receipt.get("ok") is False:
            return None
        values = receipt.get("interactables")
        if not isinstance(values, list):
            return None
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in values:
            if not isinstance(item, dict):
                return None
            identifier = _text(item.get("id"))
            if not identifier:
                return None
            if identifier in seen:
                continue
            seen.add(identifier)
            raw_name = item.get("name")
            raw_summary = item.get("description")
            name = raw_name if isinstance(raw_name, str) else ""
            summary = raw_summary if isinstance(raw_summary, str) else ""
            result.append({"id": identifier, "name": name, "summary": summary, "silenced": item.get("silenced") is True})
        return result

    def finish_interactables(receipt: Any, error: str | None, generation: int) -> bool:
        if generation != reads["interactables"] or not data["alive"]:
            return False
        data["interactables_ready"] = False
        data["interactables_error"] = ""
        if error:
            data["interactables_error"] = error
        else:
            values = _normalise_interactables(receipt)
            if values is None:
                data["interactables_error"] = _receipt_error(receipt, "Interactable list unavailable.")
            else:
                data["interactables"] = values
                data["interactables_ready"] = True
        render_pending()
        _refresh_headline()
        return False

    def finish_history(receipt: Any, error: str | None, generation: int) -> bool:
        if generation != reads["history"] or not data["alive"]:
            return False
        data["history_ready"] = False
        data["history_error"] = ""
        if error:
            data["history_error"] = error
        elif (
            not isinstance(receipt, dict)
            or receipt.get("ok") is not True
            or receipt.get("schema") != HISTORY_SCHEMA
            or not isinstance(receipt.get("runs"), list)
        ):
            data["history_error"] = _receipt_error(receipt, "Update history unavailable.")
        else:
            runs = _normalise_history(receipt["runs"])
            if runs is None:
                data["history_error"] = "Update history response was invalid."
            else:
                data["history"] = runs
                data["history_ready"] = True
        render_history()
        _refresh_headline()
        return False

    def request_read(name: str, path: str, callback: Callable[..., bool]) -> None:
        reads[name] += 1
        generation = reads[name]
        threading.Thread(
            target=read_door,
            args=(path, callback, generation),
            daemon=True,
        ).start()

    def request_timer() -> None:
        if data["timer_busy"]:
            return
        request_read("timer", TIMER_DOOR, finish_timer)

    def refresh_all() -> None:
        if not data["alive"]:
            return
        request_read("status", STATUS_DOOR, finish_status)
        request_read("modules", MODULES_DOOR, finish_modules)
        request_read("interactables", INTERACTABLES_DOOR, finish_interactables)
        request_read("history", HISTORY_DOOR, finish_history)
        request_timer()

    def toggle_timer(_switch: Any, requested: bool) -> bool:
        if (
            type(requested) is not bool
            or not data["timer_known"]
            or data["timer_busy"]
            or data["timer_pending"] is not None
        ):
            return True
        previous = data["timer_enabled"]
        if requested == previous:
            return True
        data["timer_busy"] = True
        data["timer_pending"] = {"requested": requested}
        data["timer_message"] = "Saving automatic-update setting…"
        reads["timer"] += 1
        render_timer()
        payload = {"state": "on" if requested else "off"}

        def finish(receipt: Any, error: str | None) -> bool:
            data["timer_busy"] = False
            if error or not _receipt_ok(receipt or {}):
                data["timer_pending"] = None
                data["timer_known"] = True
                data["timer_enabled"] = previous
                data["timer_message"] = error or _receipt_error(receipt, "Automatic-update change refused.")
            else:
                data["timer_known"] = False
                data["timer_message"] = "Confirming automatic-update setting with Caduceus…"
            if data["alive"]:
                render_timer()
                request_timer()
            return False

        threading.Thread(
            target=mutate_door,
            args=(TIMER_TOGGLE_DOOR, payload, finish),
            daemon=True,
        ).start()
        return True

    def toggle_module(_switch: Any, requested: bool, identifier: str) -> bool:
        if type(requested) is not bool or identifier in data["module_pending"]:
            return True
        item = next((module for module in data["modules"] if module["id"] == identifier), None)
        if item is None or type(item["enabled"]) is not bool:
            return True
        previous = item["enabled"]
        if requested == previous:
            return True
        data["module_sequence"] += 1
        sequence = data["module_sequence"]
        data["module_pending"][identifier] = {
            "sequence": sequence,
            "requested": requested,
            "phase": "saving",
        }
        data["module_errors"].pop(identifier, None)
        render_modules()
        path = f"{MODULES_DOOR}/{urllib.parse.quote(identifier, safe='')}"

        def finish(receipt: Any, error: str | None) -> bool:
            current = data["module_pending"].get(identifier)
            if current is None or current["sequence"] != sequence:
                return False
            if error or not _receipt_ok(receipt or {}):
                data["module_pending"].pop(identifier, None)
                data["module_errors"][identifier] = error or _receipt_error(receipt, "Module change refused.")
                if data["alive"]:
                    render_modules()
                    request_read("modules", MODULES_DOOR, finish_modules)
            else:
                current["phase"] = "confirming"
                if data["alive"]:
                    render_modules()
                    request_read("modules", MODULES_DOOR, finish_modules)
            return False

        payload = {"enabled": requested}
        threading.Thread(target=mutate_door, args=(path, payload, finish), daemon=True).start()
        return True

    def agree(_button: Any, identifier: str) -> None:
        if identifier in data["agree_busy"]:
            return
        data["agree_sequence"] += 1
        sequence = data["agree_sequence"]
        data["agree_busy"][identifier] = sequence
        data["agree_messages"].pop(identifier, None)
        render_pending()
        path = f"{INTERACTABLES_DOOR}/{urllib.parse.quote(identifier, safe='')}/run"

        def finish(receipt: Any, error: str | None) -> bool:
            if data["agree_busy"].get(identifier) != sequence:
                return False
            data["agree_busy"].pop(identifier, None)
            if error or not _receipt_ok(receipt or {}):
                data["agree_messages"][identifier] = error or _receipt_error(receipt, "Agree request refused.")
            else:
                data["agree_messages"].pop(identifier, None)
            if data["alive"]:
                render_pending()
                request_read("interactables", INTERACTABLES_DOOR, finish_interactables)
            return False

        threading.Thread(target=mutate_door, args=(path, None, finish), daemon=True).start()

    def set_silence(_button: Any, identifier: str, silenced: bool) -> None:
        if identifier in data["agree_busy"]:
            return
        data["agree_sequence"] += 1
        sequence = data["agree_sequence"]
        data["agree_busy"][identifier] = sequence
        data["agree_messages"].pop(identifier, None)
        render_pending()
        action = "silence" if silenced else "unsilence"
        path = f"{INTERACTABLES_DOOR}/{urllib.parse.quote(identifier, safe='')}/{action}"

        def finish(receipt: Any, error: str | None) -> bool:
            if data["agree_busy"].get(identifier) != sequence:
                return False
            data["agree_busy"].pop(identifier, None)
            if error or not _receipt_ok(receipt or {}):
                data["agree_messages"][identifier] = error or _receipt_error(receipt, f"{action.capitalize()} request refused.")
            if data["alive"]:
                render_pending()
                if not error and _receipt_ok(receipt or {}):
                    request_read("interactables", INTERACTABLES_DOOR, finish_interactables)
            return False

        threading.Thread(target=mutate_door, args=(path, None, finish), kwargs={"empty_body": True}, daemon=True).start()

    def update_now(_button: Any) -> None:
        if data["update_busy"] or not data["status_ready"]:
            return
        data["update_sequence"] += 1
        sequence = data["update_sequence"]
        data["update_busy"] = True
        data["update_message"] = "Update request sent; waiting for Caduceus…"
        data["update_message_is_error"] = None
        render_status()

        def finish(receipt: Any, error: str | None) -> bool:
            if sequence != data["update_sequence"]:
                return False
            data["update_busy"] = False
            state = (receipt or {}).get("state") if isinstance(receipt, dict) else None
            failed = bool(error or not _receipt_ok(receipt or {}))
            data["update_message_is_error"] = failed and state != "busy"
            if state == "busy":
                data["update_message"] = "An update is already running. Its result will appear in History."
            elif failed:
                data["update_message"] = error or _receipt_error(receipt, "Update request refused.")
            elif state in ("started", "unknown"):
                data["update_message"] = "Update started. Its result will appear in History when it finishes."
            else:
                data["update_message"] = "Update completed."
            if data["alive"]:
                render_status()
                refresh_all()
            return False

        threading.Thread(target=mutate_door, args=(UPDATE_DOOR, None, finish), daemon=True).start()

    def show_history(_row: Any) -> None:
        stack.set_visible_child_name("history")

    def show_updates(_row: Any) -> None:
        stack.set_visible_child_name("updates")

    def on_unmap(_widget: Any) -> None:
        if not data["alive"]:
            return
        data["alive"] = False
        if data["refresh_source"] is not None:
            GLib.source_remove(data["refresh_source"])
            data["refresh_source"] = None
        for name in reads:
            reads[name] += 1

    def periodic_refresh() -> bool:
        if not data["alive"]:
            data["refresh_source"] = None
            return False
        refresh_all()
        return True

    def on_map(_widget: Any) -> None:
        data["alive"] = True
        if data["refresh_source"] is None:
            data["refresh_source"] = GLib.timeout_add_seconds(30, periodic_refresh)
        refresh_all()

    timer_switch.connect("state-set", toggle_timer)
    update_button.connect("clicked", update_now)
    history_row.connect("activated", show_history)
    back_row.connect("activated", show_updates)
    stack.connect("map", on_map)
    stack.connect("unmap", on_unmap)

    render_status()
    render_timer()
    render_modules()
    render_pending()
    render_history()
    refresh_all()
    return stack

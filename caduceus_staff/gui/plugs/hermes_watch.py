"""Read-only Hermes Watch plug using the existing LAN service."""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

PLUG = {
    "id": "hermes-watch",
    "title": "Hermes Watch",
    "icon": "utilities-system-monitor-symbolic",
    "order": 20,
    "parent": None,
}

BASE_URL = os.environ.get("HERMES_WATCH_URL", "http://hermes.home.arpa:9131").rstrip("/")


def _request(path: str) -> dict[str, Any]:
    request = urllib.request.Request(BASE_URL + path, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=3) as response:
            body = response.read(256 * 1024)
    except (OSError, urllib.error.URLError) as error:
        raise RuntimeError("Hermes Watch is unavailable") from error
    try:
        value = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("Hermes Watch returned unreadable data") from error
    if not isinstance(value, dict):
        raise RuntimeError("Hermes Watch returned invalid data")
    return value


def _age(value: Any) -> str:
    try:
        seconds = max(0, int(value))
    except (TypeError, ValueError):
        return "unknown"
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {seconds}s"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h"


def _text(value: Any, fallback: str = "unknown") -> str:
    rendered = str(value or "").strip()
    return rendered or fallback


def _is_stale(status: dict[str, Any]) -> bool:
    try:
        observed = dt.datetime.fromisoformat(str(status["observed_at"]).replace("Z", "+00:00"))
        limit = max(0, float(status["stale_after_seconds"]))
        return (dt.datetime.now(dt.timezone.utc) - observed).total_seconds() > limit
    except (KeyError, TypeError, ValueError):
        return True


def build_widget() -> Any:
    import gi

    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gtk

    page = Adw.PreferencesPage(title=PLUG["title"], icon_name=PLUG["icon"])
    observatory = Adw.PreferencesGroup(title="Observatory")
    count_rows = {}
    for key, title in (
        ("active_agents", "Agents"),
        ("gateways", "Gateways"),
        ("model_seats", "Model seats"),
        ("tmux_sessions", "tmux"),
    ):
        row = Adw.ActionRow(title=title, subtitle="–")
        observatory.add(row)
        count_rows[key] = row
    observed_row = Adw.ActionRow(title="Observation", subtitle="Awaiting Hermes Watch…")
    observed_icon = Gtk.Image.new_from_icon_name("content-loading-symbolic")
    observed_row.add_prefix(observed_icon)
    observatory.add(observed_row)
    page.add(observatory)

    estate = Adw.PreferencesGroup(title="Active estate")
    estate_placeholder = Adw.ActionRow(title="Reading active entities…")
    estate.add(estate_placeholder)
    page.add(estate)
    activity_group = Adw.PreferencesGroup(title="Activity feed")
    activity_placeholder = Adw.ActionRow(title="Reading activity…")
    activity_group.add(activity_placeholder)
    page.add(activity_group)
    stray_group = Adw.PreferencesGroup(title="Stranded Hermes sessions")
    stray_row = Adw.ActionRow(title="Checking…", subtitle="Read-only status")
    stray_group.add(stray_row)
    page.add(stray_group)

    state = {
        "busy": False,
        "cursor": None,
        "estate_rows": [estate_placeholder],
        "activity_rows": [activity_placeholder],
    }

    def replace_rows(group: Any, key: str, rows: list[Any]) -> None:
        for row in state[key]:
            group.remove(row)
        for row in rows:
            group.add(row)
        state[key] = rows

    def make_entity_rows(status: dict[str, Any], stale: bool) -> list[Any]:
        rows = []
        prefix = "Last observed; " if stale else ""
        for agent in status.get("agents", []):
            if isinstance(agent, dict):
                rows.append(Adw.ActionRow(
                    title=f"Agent — {_text(agent.get('profile'))}",
                    subtitle=(f"{prefix}mode {_text(agent.get('mode'))} · "
                              f"pid {agent.get('pid', '?')} · age {_age(agent.get('age_seconds'))}"),
                ))
        for gateway in status.get("gateways", []):
            if isinstance(gateway, dict):
                rows.append(Adw.ActionRow(
                    title=f"Gateway — {_text(gateway.get('profile'))}",
                    subtitle=f"{prefix}pid {gateway.get('pid', '?')} · age {_age(gateway.get('age_seconds'))}",
                ))
        for seat in status.get("model_seats", []):
            if isinstance(seat, dict):
                processing = "processing" if seat.get("is_processing") else "idle"
                rows.append(Adw.ActionRow(
                    title=f"Model seat — {_text(seat.get('name'), _text(seat.get('seat_id')))}",
                    subtitle=(f"{prefix}{_text(seat.get('endpoint_state'))} · {processing} · "
                              f"slots {seat.get('active_slots', '?')}/{seat.get('total_slots', '?')}"),
                ))
        for session in status.get("tmux_sessions", []):
            if isinstance(session, dict):
                rows.append(Adw.ActionRow(title="tmux session", subtitle=f"{prefix}{_text(session.get('name'))}"))
        return rows or [Adw.ActionRow(title="No active entities")]

    def make_activity_rows(activity: dict[str, Any] | None) -> list[Any]:
        rows = []
        if isinstance(activity, dict):
            execution = activity.get("execution_activity")
            if isinstance(execution, dict):
                cursor = execution.get("cursor")
                if isinstance(cursor, str) and cursor:
                    state["cursor"] = cursor
                rows.append(Adw.ActionRow(
                    title="Unio",
                    subtitle=(f"{execution.get('running_now', 0)} running · "
                              f"{execution.get('ran_since_refresh', 0)} ran · "
                              f"{execution.get('failed_since_refresh', 0)} failed · "
                              f"{execution.get('cancelled_since_refresh', 0)} canceled"),
                ))
            for item in activity.get("events", activity.get("activity", [])):
                if isinstance(item, dict):
                    value = _text(item.get("message") or item.get("summary") or item.get("event"),
                                  json.dumps(item, sort_keys=True))
                else:
                    value = _text(item)
                rows.append(Adw.ActionRow(title=value))
        return rows or [Adw.ActionRow(title="Activity unavailable")]

    def finish(status: dict[str, Any] | None, activity: dict[str, Any] | None,
               stray: dict[str, Any] | None, error: str | None) -> bool:
        state["busy"] = False
        if error is not None:
            for row in count_rows.values():
                row.set_subtitle("–")
            observed_row.set_subtitle(error)
            observed_icon.set_from_icon_name("dialog-warning-symbolic")
            replace_rows(estate, "estate_rows", [Adw.ActionRow(title="Server unreachable")])
            stray_row.set_title("Stranded session status unavailable")
            return False
        assert status is not None
        if status.get("schema") != "hermes-watch.status.v1":
            observed_row.set_subtitle("Unsupported status response")
            observed_icon.set_from_icon_name("dialog-warning-symbolic")
            return False
        counts = status.get("counts", {})
        stale = _is_stale(status)
        for key, row in count_rows.items():
            row.set_subtitle("–" if stale else str(counts.get(key, "–")))
        observed = _text(status.get("observed_at"))
        observed_row.set_subtitle(f"STALE — last observation {observed}" if stale else f"Observed {observed}")
        observed_icon.set_from_icon_name("dialog-warning-symbolic" if stale else "emblem-ok-symbolic")
        replace_rows(estate, "estate_rows", make_entity_rows(status, stale))
        replace_rows(activity_group, "activity_rows", make_activity_rows(activity))
        if isinstance(stray, dict) and stray.get("schema") == "hermes-watch.stray-status.v1":
            count = stray.get("proven_stranded_count")
            if isinstance(count, int) and not isinstance(count, bool) and count >= 0:
                stray_row.set_title(f"{count} proven stranded session{'s' if count != 1 else ''}")
                return False
        stray_row.set_title("Stranded session status unavailable")
        return False

    def worker() -> None:
        try:
            status = _request("/status")
            suffix = f"?cursor={urllib.parse.quote(str(state['cursor']))}" if state["cursor"] else ""
            try:
                activity = _request(f"/activity{suffix}")
            except RuntimeError:
                activity = None
            try:
                stray = _request("/stray/status")
            except RuntimeError:
                stray = None
            GLib.idle_add(finish, status, activity, stray, None)
        except RuntimeError as error:
            GLib.idle_add(finish, None, None, None, str(error))

    def refresh() -> bool:
        if not state["busy"]:
            state["busy"] = True
            threading.Thread(target=worker, daemon=True).start()
        return True

    refresh()
    GLib.timeout_add_seconds(5, refresh)
    return page

"""Command helpers for desktop settings."""
from __future__ import annotations

import json
import os
import pwd
import subprocess
from typing import Sequence


def owner_session_command(argv: Sequence[str]) -> tuple[list[str], dict[str, str] | None]:
    command_argv = list(argv)
    if os.geteuid() != 0 or not command_argv or command_argv[0] not in OWNER_SESSION_TOOLS:
        return command_argv, None
    owner_uid = pwd.getpwnam(OWNER_USER).pw_uid
    environment = os.environ.copy()
    environment["XDG_RUNTIME_DIR"] = f"/run/user/{owner_uid}"
    environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{owner_uid}/bus"
    environment["HOME"] = str(OWNER_HOME)
    return ["runuser", "-u", OWNER_USER, "--", *command_argv], environment


def run_command(argv: Sequence[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    command_argv, environment = owner_session_command(argv)
    try:
        return subprocess.run(command_argv, input=input_text, capture_output=True, text=True, timeout=8, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command_argv, 127, "", str(exc))


def _default_card() -> tuple[str | None, str | None]:
    ok, sink_name, _ = command(["pactl", "get-default-sink"])
    good, text, _ = command(["pactl", "-f", "json", "list", "sinks"])
    cards_ok, cards_text, _ = command(["pactl", "-f", "json", "list", "cards"])
    if not ok or not good or not cards_ok:
        return None, None
    try:
        sinks, cards = json.loads(text), json.loads(cards_text)
        sink = next(item for item in sinks if isinstance(item, dict) and item.get("name") == sink_name)
        card_id = sink.get("card")
        card = next(item for item in cards if isinstance(item, dict) and item.get("index") == card_id)
        active = card.get("active_profile")
        profile = active.get("name") if isinstance(active, dict) else active
        return (card.get("name") if isinstance(card.get("name"), str) else None,
                profile if isinstance(profile, str) else None)
    except (ValueError, TypeError, StopIteration):
        return None, None


def command(argv: Sequence[str]):
    return _shared.command(argv)


from agathodaimon.settings import _shared
OWNER_USER = _shared.OWNER_USER
OWNER_HOME = _shared.OWNER_HOME
OWNER_SESSION_TOOLS = _shared.OWNER_SESSION_TOOLS

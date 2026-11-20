"""Derive the exact restart inventory from the appliance's declarations."""
from __future__ import annotations

import json
from pathlib import Path
import re

from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon.xenos._launcher import REGISTER_PATH


# Guard the literal systemctl operand, not the register's admission rules.
_LITERAL_GUEST_ID = re.compile(r"[a-z0-9][a-z0-9-]*")


def _gui_face(path: Path) -> str | None:
    try:
        config = json.loads(path.read_bytes())
    except (OSError, ValueError, RecursionError):
        return None
    syzygy = config.get("syzygy") if isinstance(config, dict) else None
    face = syzygy.get("gui_face") if isinstance(syzygy, dict) else None
    return face if isinstance(face, str) else None


def _row(name: str, label: str, kind: str) -> dict[str, str]:
    return {"name": name, "label": label, "unit": f"{name}.service", "kind": kind}


def list_restartable() -> tuple[list[dict[str, str]], str]:
    config_path = appliance_runtime_path("config")
    rows: list[dict[str, str]] = []
    face = _gui_face(config_path)
    if face is not None and (name := face.lower()) in {"coronatio", "noesis"}:
        rows.append(_row(name, face, "face"))

    # The Xenia register is a sibling of config on the body and in scratch.
    try:
        register = json.loads(config_path.with_name(REGISTER_PATH.name).read_bytes())
    except FileNotFoundError:
        return rows, "none"
    except (OSError, ValueError, RecursionError):
        return rows, "appliance-restart-register-unreadable"
    xenoi = register.get("xenoi") if isinstance(register, dict) else None
    if not isinstance(xenoi, dict):
        return rows, "appliance-restart-register-unreadable"

    for name, entry in xenoi.items():
        if name == "caduceus" or _LITERAL_GUEST_ID.fullmatch(name) is None:
            continue
        display = entry.get("display") if isinstance(entry, dict) else None
        label = display if isinstance(display, str) and display else name
        rows.append(_row(name, label, "guest"))
    return rows, "none"

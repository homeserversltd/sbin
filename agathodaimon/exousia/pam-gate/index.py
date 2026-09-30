"""Root-only PAM switch reader for the household PIN gate."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Sequence

_CONFIG = Path("/etc/appliance/config.json")
_SCHEMA = "agathodaimon.exousia.pam-gate.v1"


def pin_required() -> bool:
    """Read only JSON true; an absent or unreadable switch fails open."""
    try:
        with _CONFIG.open("r", encoding="utf-8") as source:
            document = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    if not isinstance(document, dict):
        return False
    global_config = document.get("global")
    admin_config = global_config.get("admin") if isinstance(global_config, dict) else None
    return isinstance(admin_config, dict) and admin_config.get("pin_required") is True


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        return 1
    if args == ["--probe"]:
        print(json.dumps({
            "schema": _SCHEMA,
            "ok": True,
            "pin_required": pin_required(),
            "firstMissingSignal": "none",
        }, separators=(",", ":")))
        return 0
    if args or os.environ.get("PAM_USER") != "owner":
        return 1
    return 1 if pin_required() else 0


if __name__ == "__main__":
    raise SystemExit(main())

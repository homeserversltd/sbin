from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def emit(receipt: dict[str, Any]) -> int:
    receipt.setdefault("ok", True)
    receipt.setdefault("timestamp", now_iso())
    receipt.setdefault("host", socket.gethostname())
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt.get("ok") else 1


def path_state(path: str) -> dict[str, Any]:
    p = Path(path)
    return {
        "path": path,
        "exists": p.exists(),
        "is_file": p.is_file(),
        "is_dir": p.is_dir(),
        "executable": p.exists() and p.is_file() and bool(p.stat().st_mode & 0o111),
    }

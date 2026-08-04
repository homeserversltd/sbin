from __future__ import annotations

import json
import os
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4


RECEIPT_ROOT = Path("/var/lib/caduceus/receipts")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def emit(receipt: dict[str, Any]) -> int:
    receipt.setdefault("ok", True)
    receipt.setdefault("timestamp", now_iso())
    receipt.setdefault("host", socket.gethostname())
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt.get("ok") else 1


def emit_actuator(actuator: str, schema: str, action: str, result: Any, *, ok: bool = True, first_missing_signal: str = "none") -> int:
    receipt = {"schema": schema, "actuator": actuator, "action": action, "ok": ok, "result": result, "firstMissingSignal": first_missing_signal, "mutationPerformed": False, "timestamp": now_iso(), "host": socket.gethostname()}
    root = Path(os.environ.get("CADUCEUS_RECEIPT_DIR", RECEIPT_ROOT))
    try:
        receipt_dir = root / f"{receipt['timestamp'].replace(':', '').replace('+', '').replace('.', '')}-{uuid4().hex}"
        receipt_dir.mkdir(parents=True, exist_ok=False)
        receipt_path = receipt_dir / "run.json"
        receipt_path.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
        receipt["receipt"] = str(receipt_path)
    except OSError as exc:
        receipt["ok"] = False
        receipt["firstMissingSignal"] = f"receipt-write-failed: {exc}"
    return emit(receipt)


def path_state(path: str) -> dict[str, Any]:
    p = Path(path)
    return {"path": path, "exists": p.exists(), "is_file": p.is_file(), "is_dir": p.is_dir(), "executable": p.exists() and p.is_file() and bool(p.stat().st_mode & 0o111)}

"""Caduceus wipe-only disk actuator, retained for legacy callers."""
from __future__ import annotations

import json
import sys
from typing import Any, Sequence

from agathodaimon.storage.disk.wipe import index as wipe

MAX_INPUT_BYTES = 64 * 1024
Refusal = wipe.Refusal


def _fail(signal: str, failed_step: str | None = None, return_code: int | None = None) -> dict[str, Any]:
    receipt = wipe._fail(signal, failed_step, return_code)
    return receipt


def dispatch(value: dict[str, Any]) -> dict[str, Any]:
    body = value.get("payload")
    actuator = value["actuator"] if "actuator" in value else body.get("actuator") if isinstance(body, dict) else None
    if actuator != "disk-doors":
        raise Refusal("agathodaimon-disk-request-invalid")
    payload = value["metadata"] if "metadata" in value else body.get("metadata") if isinstance(body, dict) else None
    if not isinstance(payload, dict):
        raise Refusal("agathodaimon-disk-request-invalid")
    action = payload.get("action")
    planned = payload.get("dryRun", payload.get("planned", False))
    if not isinstance(planned, bool):
        raise Refusal("agathodaimon-disk-planned-invalid")
    if action == "wipe":
        receipt = wipe.wipe_disk(payload, planned)
        return receipt
    raise Refusal("agathodaimon-disk-action-invalid")


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise Refusal("agathodaimon-disk-request-too-large")
        value = json.loads(raw.decode())
        receipt = dispatch(value) if isinstance(value, dict) else _fail("agathodaimon-disk-request-invalid")
    except Refusal as error:
        receipt = _fail(error.signal, error.failed_step, error.return_code)
    except (UnicodeDecodeError, json.JSONDecodeError):
        receipt = _fail("agathodaimon-disk-request-invalid")
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

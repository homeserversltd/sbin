"""Root-only, single-door NAS disk setup transaction."""
from __future__ import annotations
import json
import signal
import sys
from typing import Any, Sequence
from agathodaimon.storage.nas.setup import _setup

Interrupted = _setup.Interrupted
Refusal = _setup.Refusal
SCHEMA = _setup.SCHEMA
MAX_INPUT = _setup.MAX_INPUT
dispatch = _setup.dispatch

def _handle_signal(signum: int, _frame: Any) -> None:
    raise Interrupted("agathodaimon-nas-interrupted", "signal-interrupted", signum)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, _handle_signal)
    try:
        try:
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
            if not raw or len(raw) > MAX_INPUT:
                raise Refusal("agathodaimon-nas-request-invalid", "request")
            receipt = dispatch(raw)
        except (UnicodeError, json.JSONDecodeError, Refusal):
            receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-request-invalid",
                       "role": None, "device": None, "partition": None, "partlabel": None, "mapper": None,
                       "mountpoint": None, "steps": [{"step": "request", "ok": False, "readback": {}}],
                       "servicesStarted": [], "servicesNotRunning": [],
                       "rolledBack": False, "rollbackSteps": []}
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0 if receipt["ok"] else 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())

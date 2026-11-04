"""Root-only, single-door NAS disk setup transaction."""
from __future__ import annotations
import io
import json
import signal
import sys
from typing import Any, Sequence
from _envelope import EnvelopeError, read as read_envelope
from agathodaimon.storage.nas.setup import _setup

Interrupted = _setup.Interrupted
Refusal = _setup.Refusal
SCHEMA = _setup.SCHEMA
MAX_INPUT = _setup.MAX_INPUT
dispatch = _setup.dispatch
PORTAL_FOLDER_LAYOUT = _setup.PORTAL_FOLDER_LAYOUT
_open_directory_nofollow = _setup._open_directory_nofollow
_read_regular_nofollow = _setup._read_regular_nofollow
_apply_permissions = _setup._apply_permissions
_load_config = _setup._load_config
_seed_portal_layout = _setup._seed_portal_layout

def _read_request(raw: bytes):
    text = raw.decode("utf-8")
    previous_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(text)
        return read_envelope(known_fields=("device", "role"))
    finally:
        sys.stdin = previous_stdin


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
            try:
                request = _read_request(raw)
            except EnvelopeError as error:
                failure = _setup._envelope_refusal(error)
                receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": failure.signal_name,
                           "role": None, "device": None, "partition": None, "partlabel": None, "mapper": None,
                           "mountpoint": None, "steps": [{"step": failure.step, "ok": False,
                           "readback": {"rc": None}}], "servicesStarted": [],
                           "servicesNotRunning": [], "rolledBack": False, "rollbackSteps": []}
            except UnicodeError:
                receipt = dispatch(raw)
            else:
                receipt = dispatch(request)
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

"""Envelope entry point for the sync-hold integral bands."""
from __future__ import annotations

import json
from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.nas.sync_switch import perform


def main_for(action):
    request = None
    try:
        request = read(known_fields=("hold_id",) if action == "release" else ())
        receipt = perform(action, request=request.intent_id, **request.payload)
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"schema": f"caduceus.nas-sync.{action}.v1", "ok": False,
                   "firstMissingSignal": "agathodaimon-nas-request-invalid", "failedStep": "request", "steps": []}
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1

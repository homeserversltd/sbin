"""Envelope-facing NAS sync stops, sharing the legacy act and deed."""
import json
import time
from importlib import import_module
from agathodaimon import _envelope

_sync = import_module("agathodaimon.storage.backup.nas-sync._sync")


def run(request, planned):
    started = time.monotonic()
    metadata = {"action": "sync", "dryRun": planned,
                "acceptShrink": request.payload.get("accept-shrink", False),
                "baseline": request.payload.get("baseline")}
    try:
        result = _sync.dispatch({"actuator": "nas-sync", "metadata": metadata})
    except _sync.Refusal as exc:
        result = _sync.refused("sync", str(exc))
    except Exception as exc:
        result = _sync.receipt("sync", "failed", reason="agathodaimon-nas-unexpected:" + _sync.bounded(exc))
    if not planned:
        _sync.record_deed(result, started)
    result = _envelope.attach(result, request)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["outcome"] == "ok" else int(result.get("exitCode", 1)) or 1


def invalid_envelope():
    result = _sync.refused("sync", "agathodaimon-nas-request-invalid")
    print(json.dumps(result, sort_keys=True))
    return 1

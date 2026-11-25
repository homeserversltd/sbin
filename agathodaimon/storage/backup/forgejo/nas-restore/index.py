"""Start the Forgejo NAS restore's R3a preflight and transient worker."""
import json
from importlib import import_module
from agathodaimon import _envelope

_worker = import_module("agathodaimon.storage.backup.forgejo.nas-restore._worker")


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except (Exception, _envelope.EnvelopeError):
        result = {"ok": False, "step": "preflight", "reason": "launch-failed",
                  "firstMissingSignal": "forgejo-nas-restore-launch-failed"}
        _worker._deed_once("launch-failed")
        print(json.dumps(result, separators=(",", ":")))
        return 1
    result = _worker.launch()
    result = _envelope.attach(result, request)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1

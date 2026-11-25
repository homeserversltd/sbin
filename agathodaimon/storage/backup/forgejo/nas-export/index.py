"""Start the unattended Forgejo NAS export."""
import json
from importlib import import_module
from agathodaimon import _envelope

_worker = import_module("agathodaimon.storage.backup.forgejo.nas-export._worker")


def main(argv=None):
    try:
        request = _envelope.read_fields()
        result = _worker.launch()
        result = _envelope.attach(result, request)
    except (Exception, _envelope.EnvelopeError):
        result = {"ok": False, "step": "launch", "reason": "launch-failed",
                  "firstMissingSignal": "forgejo-nas-export-launch-failed"}
        _worker.deed("refused", "forgejo-nas-export-launch-failed", 0, 0)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1

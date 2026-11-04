"""Plan a Forgejo backup for a bucket."""
from importlib import import_module
from agathodaimon import _envelope

_stop = import_module("agathodaimon.storage.backup.forgejo.backup-b2._stop")


def main(argv=None):
    try:
        request = _envelope.read_fields("bucket")
    except _envelope.EnvelopeError:
        return _stop.finish("plan", {"ok": False, "firstMissingSignal": "forgejo-backup-b2-plan-envelope-invalid"})
    return _stop.dispatch("plan", request)

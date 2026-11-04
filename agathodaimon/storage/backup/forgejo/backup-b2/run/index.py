"""Run a Forgejo backup for bucket; exclude and days are not supported."""
from importlib import import_module
from agathodaimon import _envelope

_stop = import_module("agathodaimon.storage.backup.forgejo.backup-b2._stop")


def main(argv=None):
    try:
        request = _envelope.read_fields("bucket", "exclude", "days")
    except _envelope.EnvelopeError:
        return _stop.finish("run", {"ok": False, "firstMissingSignal": "forgejo-backup-b2-run-envelope-invalid"})
    return _stop.dispatch("run", request)

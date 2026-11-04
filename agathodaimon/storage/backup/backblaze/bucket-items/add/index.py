"""Add path to bucket; expected optionally guards against stale state."""
from importlib import import_module
from agathodaimon import _envelope

_stop = import_module("agathodaimon.storage.backup.backblaze.bucket-items._stop")


def main(argv=None):
    try:
        request = _envelope.read_fields("bucket", "path", "expected", "dry-run")
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "firstMissingSignal": "backblaze-bucket-items-add-envelope-invalid"}
    else:
        receipt = _stop.run("add", request)
    return _stop.finish("add", receipt)

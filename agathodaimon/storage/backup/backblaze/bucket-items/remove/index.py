"""Remove path from bucket; expected optionally guards against stale state."""
from importlib import import_module
from agathodaimon import _envelope

_stop = import_module("agathodaimon.storage.backup.backblaze.bucket-items._stop")


def main(argv=None):
    try:
        request = _envelope.read_fields("bucket", "path", "expected")
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "firstMissingSignal": "backblaze-bucket-items-remove-envelope-invalid"}
    else:
        receipt = _stop.run("remove", request)
    return _stop.finish("remove", receipt)

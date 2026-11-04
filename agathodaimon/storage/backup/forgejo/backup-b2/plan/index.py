"""Plan a Forgejo backup for a bucket."""
from importlib import import_module
from agathodaimon import _envelope

_stop = import_module("agathodaimon.storage.backup.forgejo.backup-b2._stop")


def main(argv=None):
    return _stop.invoke("plan", lambda: _envelope.read_fields("bucket"))

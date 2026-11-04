"""Synchronize the NAS using an optional baseline and shrink override."""
from importlib import import_module
from agathodaimon import _envelope

_stop = import_module("agathodaimon.storage.backup.nas-sync._stop")


def main(argv=None):
    try:
        request = _envelope.read_fields("baseline", "accept-shrink")
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope()
    return _stop.run(request, planned=False)

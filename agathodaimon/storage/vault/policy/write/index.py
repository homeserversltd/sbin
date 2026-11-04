"""Write the unlock policy of a mounted vault mapper."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.policy import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields("mapper", "unlock", "keyfile")
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope("write")
    return _stop.run(request, "write")

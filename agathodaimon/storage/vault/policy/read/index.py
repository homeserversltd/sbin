"""Read the policy of a mounted vault mapper."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.policy import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields("mapper")
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope("read")
    return _stop.run(request, "read")

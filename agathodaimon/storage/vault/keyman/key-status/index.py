"""key-status: plan or execute the Keyman act; secret fields are stdin-only."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.keyman import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('device', 'dry-run', secret=())
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope('key-status')
    return _stop.run('key-status', request)

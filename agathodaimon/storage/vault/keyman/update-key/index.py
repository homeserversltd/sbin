"""update-key: plan or execute the Keyman act; secret fields are stdin-only."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.keyman import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('device', 'strategy', 'currentPassword', 'flexibleOption', 'keySlot', 'dry-run', secret=('currentPassword',))
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope('update-key')
    return _stop.run('update-key', request)

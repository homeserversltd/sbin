"""create-key: plan or execute the Keyman act; secret fields are stdin-only."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.keyman import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('target', 'strategy', 'password', 'devices', 'vaultPassword', 'flexibleOption', 'keySlot', 'devicePasswords', 'dry-run', secret=('password', 'vaultPassword', 'devicePasswords'))
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope('create-key')
    return _stop.run('create-key', request)

"""admin-password: plan or execute the Keyman act; secret fields are stdin-only."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.keyman import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields('oldPassword', 'newPassword', 'sambaUser', 'dry-run', secret=('oldPassword', 'newPassword'))
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope('admin-password')
    return _stop.run('admin-password', request)

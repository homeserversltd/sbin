"""One envelope-only admin password act."""
from agathodaimon import _envelope
from agathodaimon.storage.vault.keyman import _stop


def main(argv=None):
    try:
        request = _envelope.read_fields("sambaUser", "dry-run", secret=("oldPassword", "newPassword"))
    except _envelope.EnvelopeError:
        return _stop.invalid_envelope('admin-password.rotate-suite')
    return _stop.run('admin-password.rotate-suite', request)

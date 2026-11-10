"""Read Samba service status without changing it."""
import json

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.samba import _acts as samba


def main(argv=None):
    try:
        request = read()
    except EnvelopeError:
        receipt = samba._receipt(ok=False, signal="agathodaimon-settings-samba-envelope-read-failed", readback=None)
        print(json.dumps(receipt, sort_keys=True))
        return 1
    receipt = attach(samba.status(), request)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1

"""Read SSH exposure status without changing it."""
import json

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.ssh import _acts as ssh


def main(argv=None):
    try:
        request = read()
    except EnvelopeError as error:
        print(json.dumps({"ok": False, "firstMissingSignal": str(error)}, sort_keys=True))
        return 1
    receipt = attach(ssh.status(), request)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1

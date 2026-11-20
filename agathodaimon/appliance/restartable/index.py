"""List the configured face and Xenia guests that the appliance can restart."""
import json

from agathodaimon import _envelope
from agathodaimon.appliance._restartable import list_restartable


def main(argv=None):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "firstMissingSignal": "appliance-restartable-request-invalid"}
    else:
        rows, signal = list_restartable()
        receipt = _envelope.attach({
            "ok": True,
            "firstMissingSignal": signal,
            "restartable": rows,
        }, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

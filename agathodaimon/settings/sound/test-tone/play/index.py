"""Play the sound test tone."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared


def main(argv=None):
    try:
        request = read(known_fields=())
        receipt = _shared.Receipt("sound", ["test_tone"])
        try:
            _shared.set_value("sound", "test_tone", True, receipt)
            result = receipt.finish(True, receipt.changed)
        except Exception as error:
            receipt.restore_backups()
            result = receipt.finish(False, False, str(error))
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

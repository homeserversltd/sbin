"""Read keyboard settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _options, _parity


def main(argv=None):
    try:
        request = read(known_fields=())
        result = {"ok": True, "values": _parity.get_values("keyboard"), "options": _options.options("keyboard"), "mutationPerformed": False}
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

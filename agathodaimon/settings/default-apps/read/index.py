"""Read default-apps settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _options, _shared


def main(argv=None):
    try:
        request = read(known_fields=())
        result = {"ok": True, "values": _shared.get_values("default-apps"), "options": _options.options("default-apps"), "mutationPerformed": False}
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

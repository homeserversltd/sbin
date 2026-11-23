"""Read datetime settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _options, _shared


def main(argv=None):
    try:
        request = read(known_fields=())
        result = {"ok": True, "values": _shared.get_values("datetime"), "options": _options.options("datetime"), "mutationPerformed": False}
        result = attach(result, request)
    except (EnvelopeError, OSError, ValueError, RecursionError) as error:
        signal = str(error) if isinstance(error, ValueError) else "datetime-observation-failed"
        result = {"ok": False, "firstMissingSignal": signal, "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

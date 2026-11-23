"""Read datetime settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _options
from agathodaimon.settings.datetime._acts import read_settings


def main(argv=None):
    try:
        request = read(known_fields=())
        values, readonly = read_settings()
        result = {"ok": True, "values": values, "options": _options.options("datetime"), "mutationPerformed": False}
        if readonly:
            result["readonly"] = readonly
        result = attach(result, request)
    except (EnvelopeError, OSError, ValueError, RecursionError) as error:
        signal = str(error) if isinstance(error, ValueError) else "datetime-observation-failed"
        result = {"ok": False, "firstMissingSignal": signal, "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

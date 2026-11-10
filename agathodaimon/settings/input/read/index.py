"""Read input settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.input import _acts as input_settings


def main(argv=None):
    try:
        request = read(known_fields=())
        result = {"schema": "caduceus.settings.input.read.v1", "ok": True, "mutationPerformed": False, **input_settings.read_values()}
        result = attach(result, request)
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

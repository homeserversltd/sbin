"""Set one field through the existing display policy."""
import json
import time
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _family
from agathodaimon.settings.display import backends, _acts as display

FIELDS = ("output", "resolution", "refresh_rate", "scale", "orientation")
SCHEMA = "caduceus.settings.display.set.v1"


def run(request, fields, schema):
    try:
        source = request.value.get("payload", {}) if request.envelope else request.value
        if not isinstance(source, dict):
            source = {}
        rejected = next((field for field in source if field not in fields), None)
        changes = {field: request.payload[field] for field in fields if field in request.payload}
        started = time.monotonic()
        if rejected is not None:
            result = {"ok": False, "firstMissingSignal": "unknown-field:" + rejected, "mutationPerformed": False}
        elif not changes:
            result = {"ok": False, "firstMissingSignal": "no-fields-supplied", "mutationPerformed": False}
        elif len(changes) != 1:
            result = {"ok": False, "firstMissingSignal": "mixed-display-fields", "mutationPerformed": False}
        else:
            selected = backends.select_backend()
            if selected is None:
                result = _family.set_family("display", changes, schema=schema)
            else:
                result = display._apply(selected, "set", changes, display._display_settings(selected), schema=schema)
        display._log_mutation("set", result, started)
        result = attach(result, request)
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


def main(argv=None):
    try:
        request = read(known_fields=("output", "resolution", "refresh_rate", "scale", "orientation"))
    except (EnvelopeError, ValueError) as error:
        print(json.dumps({"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}, sort_keys=True))
        return 1
    return run(request, FIELDS, SCHEMA)

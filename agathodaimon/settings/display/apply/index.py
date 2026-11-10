"""Reapply saved display policy."""
import json
import time
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.display import backends, _acts as display

SCHEMA = "caduceus.settings.display.apply.v1"


def main(argv=None):
    try:
        request = read(known_fields=())
        source = request.value.get("payload", {}) if request.envelope else request.value
        selected = backends.select_backend()
        started = time.monotonic()
        if not isinstance(source, dict) or source:
            supplied = {field: source[field] for field in display.DISPLAY_FIELDS if field in source} if isinstance(source, dict) else {}
            result = display._failure("apply-does-not-accept-payload", requested=supplied, backend=selected)
        elif selected is None:
            result = {"ok": False, "firstMissingSignal": "no-fields-supplied", "mutationPerformed": False}
        else:
            result = display._apply(selected, "apply", {}, display._display_settings(selected), schema=SCHEMA)
        display._log_mutation("apply", result, started)
        result = attach(result, request)
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

"""Set timezone, ntp_enabled, automatic_timezone, time_format or local_time (YYYY-MM-DD HH:MM)."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.datetime._acts import set_values


def main(argv=None):
    try:
        request = read(known_fields=("timezone", "ntp_enabled", "automatic_timezone", "time_format", "local_time"))
        source = request.value.get("payload", {}) if request.envelope else request.value
        if not isinstance(source, dict):
            source = {}
        changes = {field: request.payload[field] for field in source if field in request.payload}
        rejected = next((field for field in source if field not in request.payload), None)
        if rejected is not None:
            result = {"ok": False, "firstMissingSignal": "unknown-field:" + rejected, "mutationPerformed": False}
        elif not changes:
            result = {"ok": False, "firstMissingSignal": "no-fields-supplied", "mutationPerformed": False}
        else:
            result = set_values(changes)
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

"""Set whether the face follows its household timezone."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.datetime import _zone_mode


def main(argv=None):
    try:
        request = read(known_fields=("zoneMode",))
        try:
            mode = request.payload.get("zoneMode")
            changed = _zone_mode.set_mode(mode)
            value = {"ok": True, "changed": changed, "mode": mode, "firstMissingSignal": "none"}
        except (OSError, UnicodeError, ValueError) as error:
            value = {"ok": False, "changed": False, "firstMissingSignal": str(error)}
        value = attach(value, request)
    except EnvelopeError as error:
        value = {"ok": False, "changed": False, "firstMissingSignal": str(error)}
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1

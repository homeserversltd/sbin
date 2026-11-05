"""Read whether the face follows its household timezone."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.datetime import _zone_mode


def main(argv=None):
    try:
        request = read()
        try:
            value = {"schema": "caduceus.settings.datetime.zone-mode.read.v1", "ok": True, "changed": False, "mode": _zone_mode.read_mode(), "firstMissingSignal": "none"}
        except (OSError, UnicodeError, ValueError) as error:
            value = {"schema": "caduceus.settings.datetime.zone-mode.read.v1", "ok": False, "changed": False, "firstMissingSignal": str(error)}
        value = attach(value, request)
    except EnvelopeError as error:
        value = {"ok": False, "changed": False, "firstMissingSignal": str(error)}
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1

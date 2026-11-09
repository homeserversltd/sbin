"""Read the selected display through the existing display policy."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared
from agathodaimon.settings.display import backends, index as display


def main(argv=None):
    try:
        request = read(known_fields=())
        selected = backends.select_backend()
        if selected is None:
            result = {"ok": True, "values": _shared.get_values("display"), "mutationPerformed": False}
        else:
            result = display._get_reply(display._display_settings(selected), selected)
        result["schema"] = "caduceus.settings.display.read.v1"
        result = attach(result, request)
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

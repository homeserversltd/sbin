"""Set the selected display's adaptive-sync feature."""
from agathodaimon.settings.display.set.index import run
from agathodaimon._envelope import EnvelopeError, read
import json


def main(argv=None):
    try:
        request = read(known_fields=("adaptive_sync",))
    except (EnvelopeError, ValueError) as error:
        print(json.dumps({"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}, sort_keys=True))
        return 1
    return run(request, ("adaptive_sync",))

"""Read the household time state."""
import json
import subprocess
from importlib import import_module
from agathodaimon._envelope import EnvelopeError, attach, read

household = import_module("agathodaimon.settings.datetime.household-time._household")


def main(argv=None):
    try:
        request = read()
    except EnvelopeError as error:
        value = household.receipt("invalid", ok=False, changed=False, first_missing_signal=str(error))
        print(json.dumps(value, sort_keys=True))
        return 1
    try:
        value = (lambda request: household.receipt("state", ok=True, changed=False, state=household.sanitized_state()))(request)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        value = household.receipt("invalid", ok=False, changed=False, first_missing_signal=str(error))
    value = attach(value, request)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1

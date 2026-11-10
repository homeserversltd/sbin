"""Read shortcut settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.shortcuts import _acts as shortcuts


def main(argv=None):
    try:
        request = read(known_fields=())
        result = {'schema': 'caduceus.settings.shortcuts.read.v1', 'ok': True, 'values': shortcuts.values(), 'mutationPerformed': False}
        result = attach(result, request)
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = {'ok': False, 'firstMissingSignal': str(error), 'mutationPerformed': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('ok') else 1

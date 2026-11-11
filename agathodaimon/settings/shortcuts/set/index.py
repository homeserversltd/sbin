"""Set a shortcut using flat from/to fields."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared
from agathodaimon.settings.shortcuts import _acts as shortcuts


def main(argv=None):
    try:
        request = read(known_fields=('from', 'to'))
        source = request.value.get('payload', {}) if request.envelope else request.value
        if not isinstance(source, dict):
            source = {}
        rejected = next((field for field in source if field not in request.payload), None)
        if rejected is not None:
            result = {'ok': False, 'firstMissingSignal': 'unknown-field:' + rejected, 'mutationPerformed': False}
        elif 'from' not in request.payload or 'to' not in request.payload:
            result = {'ok': False, 'firstMissingSignal': 'invalid:request', 'mutationPerformed': False}
        else:
            try:
                result = shortcuts.set_shortcut(request.payload['from'], request.payload['to'])
            except (ValueError, OSError, TypeError) as error:
                result = error.reply() if isinstance(error, _shared.ReceiptFailure) else {'ok': False, 'firstMissingSignal': str(error), 'mutationPerformed': False}
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {'ok': False, 'firstMissingSignal': str(error), 'mutationPerformed': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('ok') else 1

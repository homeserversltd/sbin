"""Set input settings using the selected backend."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared
from agathodaimon.settings.input import _acts as input_settings


def main(argv=None):
    try:
        request = read(known_fields=('pointer_sensitivity', 'scroll_factor', 'natural_scroll', 'tap_to_click', 'middle_button_emulation', 'pointer_speed', 'accel_profile', 'left_handed', 'disable_while_typing'))
        source = request.value.get('payload', {}) if request.envelope else request.value
        if not isinstance(source, dict):
            source = {}
        changes = {field: request.payload[field] for field in source if field in request.payload}
        rejected = next((field for field in source if field not in request.payload), None)
        if rejected is not None:
            result = {'ok': False, 'firstMissingSignal': 'unknown-field:' + rejected, 'mutationPerformed': False}
        elif not changes:
            result = {'ok': False, 'firstMissingSignal': 'no-fields-supplied', 'mutationPerformed': False}
        else:
            try:
                result = input_settings.apply_changes(changes)
            except (ValueError, OSError, TypeError) as error:
                result = error.reply() if isinstance(error, _shared.ReceiptFailure) else {'ok': False, 'firstMissingSignal': str(error), 'mutationPerformed': False}
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {'ok': False, 'firstMissingSignal': str(error), 'mutationPerformed': False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get('ok') else 1

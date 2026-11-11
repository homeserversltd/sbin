"""Set appearance settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared


def main(argv=None):
    try:
        request = read(known_fields=('color_scheme', 'icon_theme', 'cursor_theme', 'font', 'cursor_size', 'font_size', 'text_scale'))
        source = request.value.get("payload", {}) if request.envelope else request.value
        if not isinstance(source, dict):
            source = {}
        changes = {field: request.payload[field] for field in source if field in request.payload}
        rejected = next((field for field in source if field in _shared.FIELDS["appearance"] and field not in request.payload), None)
        if rejected is not None:
            result = {"ok": False, "firstMissingSignal": "unknown-field:" + rejected, "mutationPerformed": False}
        elif not changes:
            result = {"ok": False, "firstMissingSignal": "no-fields-supplied", "mutationPerformed": False}
        else:
            receipt = _shared.Receipt("appearance", list(changes))
            try:
                for field, value in changes.items():
                    _shared.set_value("appearance", field, value, receipt)
                result = receipt.finish(True, receipt.changed)
            except Exception as error:
                receipt.restore_backups()
                result = receipt.finish(False, False, str(error))
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

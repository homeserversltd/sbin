"""Set default-apps settings."""
import json
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings import _shared


def main(argv=None):
    try:
        request = read(known_fields=('browser', 'email', 'image_viewer', 'media_player', 'text_editor', 'terminal'))
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
            receipt = _shared.Receipt("default-apps", list(changes), schema="caduceus.settings.default-apps.set.v1")
            try:
                for field, value in changes.items():
                    _shared.set_value("default-apps", field, value, receipt)
                result = receipt.finish(True, receipt.changed)
            except Exception as error:
                receipt.restore_backups()
                result = receipt.finish(False, False, str(error))
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        result = {"ok": False, "firstMissingSignal": str(error), "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

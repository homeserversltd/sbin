"""Envelope-facing Keyman stops over the unchanged legacy acts."""
import json

from agathodaimon import _envelope
from agathodaimon.keyman import _common
from agathodaimon.storage.vault.keyman import _core


_ACTS = {
    "create-key": _core.create,
    "update-key": _core.update,
    "admin-password": _core.admin_password,
    "rotate-capability": _core.rotate_capability,
    "key-status": _core.key_status,
}


def run(action, request):
    fields = dict(request.payload)
    planned = fields.pop("dry-run", False)
    try:
        if not isinstance(planned, bool):
            raise _core.Refusal("agathodaimon-keyman-dry-run-invalid")
        receipt = _ACTS[action](fields, planned=planned)
    except _core.Refusal as error:
        receipt = _core._receipt(action, False, planned=planned is True, commands=[], signal=str(error))
    receipt["schema"] = f"caduceus.storage.vault.keyman.{action}.v1"
    secrets = set()
    _common._collect_secret_values(request.value, secrets)
    receipt = _common._scrub(_envelope.attach(receipt, request), secrets)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


def invalid_envelope(action):
    receipt = _core._receipt(action, False, planned=False, commands=[],
                             signal="agathodaimon-keyman-request-invalid")
    receipt["schema"] = f"caduceus.storage.vault.keyman.{action}.v1"
    print(json.dumps(receipt, sort_keys=True))
    return 1

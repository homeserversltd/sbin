"""Child-device whitelist get stop."""
import json
import os
from importlib import import_module
from pathlib import Path
from agathodaimon import _envelope

_registry = import_module("agathodaimon.network.child-device._registry")

def main(argv=None):
    try:
        request = _envelope.read_fields('mac')
    except _envelope.EnvelopeError:
        result = _registry.receipt('whitelist get', False, error="child-device-envelope-invalid")
    else:
        try:
            result = _registry._dispatch('whitelist get', request.payload, Path(os.environ.get("CADUCEUS_CHILD_DEVICE_STATE", _registry.DEFAULT_STATE)), Path(os.environ.get("CADUCEUS_KEA_CONFIG", _registry.DEFAULT_KEA_CONFIG)))
        except _registry.Refused as error:
            result = _registry.receipt('whitelist get', False, error=str(error))
        result = _envelope.attach(result, request)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1

"""Atomic Caduceus ownership of the Harmonia module disable list.

This actuator is deliberately the narrow live writer for
``/etc/appliance/config.json``.  It parses the document for validity, changes
only ``harmonia.disabled_modules``, and splices that member into the original
JSON bytes so every unrelated field remains byte-for-byte intact.
"""
import json

from agathodaimon import _envelope
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    try:
        payload = _envelope.read_fields("id", "state").payload
    except _envelope.EnvelopeError:
        payload = {}
    module, state = payload.get("id"), payload.get("state")
    if (not isinstance(module, str) or not isinstance(state, str) or module == "list"
            or module.startswith("-") or state not in ("on", "off")):
        print(json.dumps({"ok": False, "firstMissingSignal": "agathodaimon-update-module-toggle-arguments-invalid",
                          "mutationPerformed": False}))
        return 2
    return run_stop("update/module-toggle", [module, state])

"""Common entry points for the existing settings families."""
from __future__ import annotations

from typing import Any

from agathodaimon.settings import _parity, _shared

_PARITY_FAMILIES = frozenset({"keyboard", "region", "energy"})


def set_family(kind: str, changes: dict[str, Any], schema: str | None = None) -> dict[str, Any]:
    if kind in _PARITY_FAMILIES:
        return _parity._set(kind, changes, schema=schema)
    if not changes:
        return {"ok": False, "firstMissingSignal": "no-fields-supplied", "mutationPerformed": False}
    receipt = _shared.Receipt(kind, list(changes), schema=schema)
    try:
        for field, value in changes.items():
            _shared.set_value(kind, field, value, receipt)
        return receipt.finish(True, receipt.changed)
    except Exception as error:
        receipt.restore_backups()
        return receipt.finish(False, False, str(error))

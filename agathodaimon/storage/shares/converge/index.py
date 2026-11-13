"""Rebuild the Samba share file for attached drives."""
from __future__ import annotations

import json
import time

from _envelope import EnvelopeError, attach, read
from agathodaimon import _deed
from agathodaimon.storage.drive import _shares


def main(argv=None):
    del argv
    started = time.monotonic()
    request = None
    try:
        request = read(known_fields=())
        receipt = _shares.rebuild()
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"ok": False, "firstMissingSignal": "agathodaimon-drive-shares-request-invalid", "failedStep": "request", "changed": False, "mutationPerformed": False, "reloaded": False, "file": _shares.FILE, "includedBySmbConf": False, "shares": [], "pruned": [], "steps": []}
    if receipt.get("changed") or not receipt.get("ok"):
        _deed.send("sbin", "drive-shares-rebuild", bool(receipt.get("ok")), target="drive-shares", duration_ms=int((time.monotonic() - started) * 1000), signal=receipt.get("firstMissingSignal", "operation-failed"))
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

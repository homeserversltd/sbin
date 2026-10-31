"""Explicitly seat the configured layout on an attached NAS role."""
from __future__ import annotations

import json
import time
from typing import Any, Sequence

from _envelope import EnvelopeError, attach as attach_envelope
from agathodaimon.storage.nas import deed
from agathodaimon.storage.nas.folders.index import _attached_info, _observe_layout, _raw_config, _read_request
from agathodaimon.storage.nas.runtime import Refusal, _role_info, guarded_drive
from agathodaimon.storage.nas.setup.index import _apply_permissions, _load_config, _seed_portal_layout

SCHEMA = "caduceus.nas.seat.v1"


def _failure(signal: str, step: str, role: str | None = None) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": False, "firstMissingSignal": signal, "role": role,
            "partition": None, "mapper": None, "mountpoint": None, "applications": 0,
            "steps": [], "failedStep": step, "mutationPerformed": False,
            "paths": [], "differences": [], "absent": [], "changedPaths": []}


@guarded_drive
def _seat(role: str, receipt: dict[str, Any]) -> None:
    info = _attached_info(role, receipt)
    entries, included = _raw_config(receipt, info["mountpoint"])
    try:
        _observe_layout(receipt, role, info["mountpoint"], entries, included)
    except Refusal as failure:
        # An explicit seat is also the cure for a missing application path.
        if failure.signal_name != "agathodaimon-nas-layout-absent":
            raise
    info.update(role=role, config=_load_config(receipt, info["mountpoint"]))
    receipt["applications"] = len(info["config"]["applications"])
    receipt["_seatDetails"] = True
    _apply_permissions(receipt, info)
    _seed_portal_layout(receipt, info)
    receipt.update(ok=True, firstMissingSignal="none", failedStep=None)


def dispatch(request: Any) -> dict[str, Any]:
    started = time.monotonic()
    role = request.payload.get("role")
    receipt = _failure("agathodaimon-nas-not-complete", "request", role if isinstance(role, str) else None)
    try:
        if "role" not in request.payload:
            raise Refusal("agathodaimon-nas-invalid-envelope", "request")
        _role_info(role)
        _seat(role, receipt)
    except Refusal as failure:
        receipt.update(ok=False, firstMissingSignal=failure.signal_name, failedStep=failure.step)
    except OSError as failure:
        receipt.update(ok=False, firstMissingSignal="agathodaimon-nas-permission-change-failed",
                       failedStep="permissions-apply", failedPath=failure.filename, errno=failure.errno)
    except Exception:
        receipt.update(ok=False, firstMissingSignal="agathodaimon-nas-seat-aborted", failedStep="seat")
    receipt.pop("_seatDetails", None)
    if receipt["mutationPerformed"]:
        deed.finish("nas-seat", "nas-" + role, receipt, started, request=request.intent_id)
    return attach_envelope(receipt, request)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        receipt = dispatch(_read_request())
    except (ValueError, UnicodeError, json.JSONDecodeError, EnvelopeError):
        receipt = _failure("agathodaimon-nas-invalid-envelope", "request-envelope")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

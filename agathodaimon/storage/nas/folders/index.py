"""Seat configured NAS folders on an already attached role, never attach it."""
from __future__ import annotations

import io
import json
import sys
import time
from typing import Any, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.storage.nas import deed
from agathodaimon.storage.nas.runtime import (
    MAX_INPUT, Refusal, _info_for, _mount_for_target, _mount_readback, _mountinfo,
    _observed_holder_info, _record, _require_root, _role_info, guarded_drive, role_partition,
)
from agathodaimon.storage.nas.setup.index import _apply_permissions, _load_config, _seed_portal_layout

SCHEMA = "caduceus.nas.folders.v1"


def _failure(signal: str, step: str, role: str | None = None) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": False, "firstMissingSignal": signal, "role": role,
            "partition": None, "mapper": None, "mountpoint": None, "applications": 0,
            "steps": [], "failedStep": step, "mutationPerformed": False}


def _read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError("request-size-invalid")
    previous = sys.stdin
    try:
        sys.stdin = io.StringIO(raw.decode("utf-8"))
        return read_envelope(known_fields=("role",))
    finally:
        sys.stdin = previous


@guarded_drive
def _seat(role: str, receipt: dict[str, Any]) -> None:
    _require_root(receipt)
    role_info = _role_info(role)
    receipt.update(mapper=role_info["mapper"], mountpoint=role_info["mountpoint"])
    # Establish absence before touching the partition or configuration.
    mount = _mount_for_target(_mountinfo(), role_info["mountpoint"])
    if mount is None:
        raise Refusal("agathodaimon-nas-folders-mount-absent", "mount-readback")
    if mount["fstype"] != "xfs":
        raise Refusal("agathodaimon-nas-folders-filesystem-not-xfs", "mount-readback")
    partition = role_partition(role)
    receipt["partition"] = partition
    info = _observed_holder_info(receipt, _info_for(role, partition))
    receipt["mapper"] = info["mapper"]
    observed = _mount_readback(info)
    _record(receipt, "mount-readback", bool(observed.get("sourceMatches")), **observed)
    if observed.get("mounted") is not True:
        raise Refusal("agathodaimon-nas-folders-mount-absent", "mount-readback")
    if observed.get("fstype") != "xfs":
        raise Refusal("agathodaimon-nas-folders-filesystem-not-xfs", "mount-readback")
    if observed.get("sourceMatches") is not True:
        raise Refusal("agathodaimon-nas-folders-mapper-mismatch", "mount-readback")
    info.update(role=role, config=_load_config(receipt, info["mountpoint"]))
    receipt["applications"] = len(info["config"]["applications"])
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
    except Exception:
        receipt.update(ok=False, firstMissingSignal="agathodaimon-nas-folders-aborted", failedStep="folders")
    if receipt["mutationPerformed"]:
        deed.finish("nas-folders", "nas-" + role, receipt, started, request=request.intent_id)
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

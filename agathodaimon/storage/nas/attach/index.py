"""Attach one fixed NAS mount unit and optionally start its dependent services."""
from __future__ import annotations

import io
import json
import sys
from typing import Any, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.storage.nas.runtime import MAX_INPUT, Refusal, attach_role

SCHEMA = "caduceus.nas.attach.v1"


def _failure(signal_name: str, step: str, role: str | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "ok": False, "firstMissingSignal": signal_name,
        "role": role, "partlabel": None, "partition": None, "mapper": None,
        "mountpoint": None, "alreadyMounted": False, "steps": [],
        "unitsStarted": [], "unitStatesBefore": {}, "services": [],
        "servicesStarted": [], "mapperReadback": None, "mountReadback": None,
        "failedStep": step,
    }


def _read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError("request-size-invalid")
    text = raw.decode("utf-8")
    previous = sys.stdin
    try:
        sys.stdin = io.StringIO(text)
        return read_envelope(known_fields=("role",))
    finally:
        sys.stdin = previous


def _role(request: Any) -> str:
    payload = getattr(request, "payload", None)
    role = payload.get("role") if isinstance(payload, dict) else None
    if not isinstance(role, str) or role not in {"primary", "backup"}:
        raise Refusal("agathodaimon-nas-role-invalid", "request")
    return role


def dispatch(request: Any) -> dict[str, Any]:
    role = None
    try:
        role = _role(request)
        receipt = attach_role(role)
    except Refusal as failure:
        receipt = failure.receipt or _failure(failure.signal_name, failure.step, role)
    return attach_envelope(receipt, request)


def _envelope_failure(error: Exception) -> dict[str, Any]:
    if isinstance(error, EnvelopeError):
        message = str(error)
        if "foreign envelope schema" in message:
            return _failure("agathodaimon-nas-envelope-schema-foreign", "request-envelope")
        if "missing envelope kernel keys" in message:
            return _failure("agathodaimon-nas-envelope-kernel-missing", "request-envelope")
    return _failure("agathodaimon-nas-request-invalid", "request")


def main(argv: Sequence[str] | None = None) -> int:
    del argv  # The role is read only from stdin, never argv or environment.
    try:
        receipt = dispatch(_read_request())
    except (ValueError, UnicodeError, json.JSONDecodeError, EnvelopeError) as error:
        receipt = _envelope_failure(error)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

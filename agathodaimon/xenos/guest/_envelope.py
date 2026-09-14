"""Shared reader and additive receipt custody for staff envelopes."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import json, re, sys
from typing import Any, Mapping, Sequence
SCHEMA = "caduceus.staff.v1"
KERNEL_KEYS = ("schema", "intent_id", "transition", "version", "timestamp")
class EnvelopeError(ValueError): pass
@dataclass(frozen=True)
class Request:
    value: dict[str, Any]
    envelope: bool
    payload: dict[str, Any]
    raw_envelope: str
    intent_id: Any = None
    transition: Any = None
    version: Any = None
    timestamp: Any = None
    @property
    def verb(self) -> str:
        if isinstance(self.transition, str) and self.transition:
            parts = [p for p in re.split(r"[./:]", self.transition) if p]
            return parts[-1] if parts else "unknown"
        return "unknown"
def _selected(source: Mapping[str, Any], names: Sequence[str]) -> dict[str, Any]:
    return {k: source[k] for k in names if k in source}
def read(*, known_fields: Sequence[str] = (), declared_flags: Sequence[str] = (), rooms: Sequence[str] = ()) -> Request:
    try:
        raw = sys.stdin.read(); value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise EnvelopeError("invalid JSON") from exc
    if not isinstance(value, dict): raise EnvelopeError("JSON object required")
    if "schema" not in value:
        return Request(value, False, _selected(value, known_fields), raw)
    if value.get("schema") != SCHEMA: raise EnvelopeError("foreign envelope schema")
    missing = [k for k in KERNEL_KEYS if k not in value]
    if missing: raise EnvelopeError("missing envelope kernel keys: " + ",".join(missing))
    source = value.get("payload") if isinstance(value.get("payload"), Mapping) else {}
    payload = _selected(source, tuple(known_fields) + tuple(declared_flags) + tuple(rooms))
    for group, names in (("flags", declared_flags), ("rooms", rooms)):
        candidates = []
        for container in (source, value):
            nested = container.get(group) if isinstance(container, Mapping) else None
            if isinstance(nested, Mapping):
                scoped = nested.get("exousia")
                if isinstance(scoped, Mapping): candidates.append(scoped)
                candidates.append(nested)
        for candidate in candidates: payload.update(_selected(candidate, names))
    return Request(value, True, payload, raw, value["intent_id"], value["transition"], value["version"], value["timestamp"])
def _outcome(receipt: Mapping[str, Any]) -> str:
    return "failed" if receipt.get("ok") is False or receipt.get("verified") is False or receipt.get("firstMissingSignal") else "ok"
def attach(receipt: dict[str, Any], request: Request) -> dict[str, Any]:
    if not request.envelope: return receipt
    result = dict(receipt); prior = request.value.get("stamps"); prior = list(prior) if isinstance(prior, list) else []
    stamp = {"verb": request.verb, "outcome": _outcome(result), "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    envelope = dict(request.value)
    # Absent/list stamps are an additive custody lane. Preserve malformed
    # caller data in the carried envelope while top-level custody stays usable.
    if "stamps" not in request.value or isinstance(request.value.get("stamps"), list):
        envelope["stamps"] = prior + [dict(stamp)]
    result.update(intent_id=request.intent_id, raw_envelope=request.raw_envelope, envelope=envelope, stamps=prior + [dict(stamp)], staff=dict(stamp))
    return result
def read_fields(*fields: str, flags: Sequence[str] = (), rooms: Sequence[str] = ()) -> Request:
    return read(known_fields=fields, declared_flags=flags, rooms=rooms)

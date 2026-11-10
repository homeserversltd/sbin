"""Shared reader and additive receipt custody for staff envelopes."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone
import copy, json, os, re, sys
from pathlib import Path
from threading import Lock
from typing import Any, Mapping, Sequence

from agathodaimon import _load_trace
from agathodaimon._nidus.path import appliance_runtime_path
SCHEMA = "caduceus.staff.v1"
_seat_lock = Lock()
_seat_loaded = False
_seat_required: tuple[str, ...] = ()
_seat_foreign: Any = None
_PIN_FIELDS = ("pin", "oldPin", "newPin")
_REDACTED_PIN = "[REDACTED]"


class EnvelopeError(ValueError): pass


def _envelope_kernel() -> tuple[str, ...]:
    """Read the local seat once; an unavailable or malformed seat is primitive."""
    global _seat_loaded, _seat_required, _seat_foreign
    with _seat_lock:
        if not _seat_loaded:
            path = appliance_runtime_path("seats") / (SCHEMA + ".json")
            try:
                seat = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, ValueError, RecursionError):
                seat = None
            if isinstance(seat, dict):
                if isinstance(seat.get("schema"), str) and seat["schema"] != SCHEMA:
                    _seat_foreign = repr(seat["schema"])
                elif seat.get("schema") == SCHEMA:
                    kernel = seat.get("kernel")
                    required = kernel.get("required") if isinstance(kernel, dict) else None
                    if isinstance(required, list) and all(isinstance(k, str) for k in required):
                        _seat_required = tuple(required)
            _seat_loaded = True
        if _seat_foreign is not None:
            raise EnvelopeError(f"foreign seat {SCHEMA}: {_seat_foreign}")
        return _seat_required


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
    load_context_present: bool = False
    load_context: Any = None
    returned_load_context: Any = None
    secret_fields: tuple[str, ...] = ()
    @property
    def verb(self) -> str:
        if isinstance(self.transition, str) and self.transition:
            parts = [p for p in re.split(r"[./:]", self.transition) if p]
            return parts[-1] if parts else "unknown"
        return "unknown"
def _selected(source: Mapping[str, Any], names: Sequence[str]) -> dict[str, Any]:
    return {k: source[k] for k in names if k in source}
def read(*, known_fields: Sequence[str] = (), declared_flags: Sequence[str] = (), rooms: Sequence[str] = (), secret: Sequence[str] = ()) -> Request:
    try:
        raw = sys.stdin.read(); value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise EnvelopeError("invalid JSON") from exc
    if not isinstance(value, dict): raise EnvelopeError("JSON object required")
    load_context_present, load_context = _load_trace.extract_load_context(value)
    if "schema" not in value:
        return Request(
            value, False, _selected(value, tuple(known_fields) + tuple(secret)), raw,
            load_context_present=load_context_present, load_context=load_context, secret_fields=tuple(secret),
        )
    if value.get("schema") != SCHEMA: raise EnvelopeError("foreign envelope schema")
    missing = [k for k in _envelope_kernel() if k not in value]
    if missing: raise EnvelopeError("missing envelope kernel keys: " + ",".join(missing))
    source = value.get("payload") if isinstance(value.get("payload"), Mapping) else {}
    payload = _selected(source, tuple(known_fields) + tuple(declared_flags) + tuple(rooms) + tuple(secret))
    for group, names in (("flags", declared_flags), ("rooms", rooms)):
        candidates = []
        for container in (source, value):
            nested = container.get(group) if isinstance(container, Mapping) else None
            if isinstance(nested, Mapping):
                scoped = nested.get("exousia")
                if isinstance(scoped, Mapping): candidates.append(scoped)
                candidates.append(nested)
        for candidate in candidates: payload.update(_selected(candidate, names))
    return Request(
        value, True, payload, raw, value.get("intent_id"), value.get("transition"),
        value.get("version"), value.get("timestamp"), load_context_present, load_context,
        secret_fields=tuple(secret),
    )
def _outcome(receipt: Mapping[str, Any]) -> str:
    first_missing_signal = receipt.get("firstMissingSignal")
    return "failed" if receipt.get("ok") is False or receipt.get("verified") is False or (first_missing_signal and first_missing_signal != "none") else "ok"


def _pin_carriers(value: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Return only the declared PIN carrier locations, without walking unknown data."""
    containers = [value]
    payload = value.get("payload")
    if isinstance(payload, Mapping):
        containers.append(payload)
    carriers = list(containers)
    for container in containers:
        flags = container.get("flags")
        if isinstance(flags, Mapping):
            carriers.append(flags)
            exousia = flags.get("exousia")
            if isinstance(exousia, Mapping):
                carriers.append(exousia)
    return carriers


def _pin_bearing_exousia(value: Mapping[str, Any]) -> bool:
    # Do not infer the action from transition: lawful callers can use an
    # unqualified "verify" or "change" transition while carrying a PIN.
    return any(
        any(name in carrier for name in _PIN_FIELDS)
        for carrier in _pin_carriers(value)
    )


def _redact_pin_carriers(value: dict[str, Any]) -> dict[str, Any]:
    redacted = copy.deepcopy(value)
    for carrier in _pin_carriers(redacted):
        if not isinstance(carrier, dict):
            continue
        for name in _PIN_FIELDS:
            if name in carrier:
                carrier[name] = _REDACTED_PIN
    return redacted


def _redact_declared(value: Any, names: Sequence[str]) -> Any:
    if isinstance(value, dict):
        return {key: _REDACTED_PIN if key in names else _redact_declared(child, names)
                for key, child in value.items()}
    if isinstance(value, list):
        return [_redact_declared(child, names) for child in value]
    return value


def attach(receipt: dict[str, Any], request: Request) -> dict[str, Any]:
    explicit_context = (
        request.returned_load_context
        if request.returned_load_context is not None
        else request.load_context if request.load_context_present else None
    )
    if request.secret_fields:
        explicit_context = _redact_declared(explicit_context, request.secret_fields)
    if not request.envelope:
        return _load_trace.attach_context(receipt, explicit_context)
    result = dict(receipt)
    stamp = {"verb": request.verb, "outcome": _outcome(result), "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    pin_bearing = _pin_bearing_exousia(request.value)
    carried = _redact_pin_carriers(request.value) if pin_bearing else copy.deepcopy(request.value)
    if request.secret_fields:
        carried = _redact_declared(carried, request.secret_fields)
    prior = carried.get("stamps"); prior = list(prior) if isinstance(prior, list) else []
    raw_envelope = json.dumps(carried, separators=(",", ":")) if pin_bearing or request.secret_fields else request.raw_envelope
    envelope = carried
    # Absent/list stamps are an additive custody lane. Preserve malformed
    # caller data in the carried envelope while top-level custody stays usable.
    if "stamps" not in request.value or isinstance(request.value.get("stamps"), list):
        envelope["stamps"] = prior + [dict(stamp)]
    result.update(intent_id=request.intent_id, raw_envelope=raw_envelope, envelope=envelope, stamps=prior + [dict(stamp)], staff=dict(stamp))
    return _load_trace.attach_context(result, explicit_context)
def read_fields(*fields: str, flags: Sequence[str] = (), rooms: Sequence[str] = (), secret: Sequence[str] = ()) -> Request:
    return read(known_fields=fields, declared_flags=flags, rooms=rooms, secret=secret)

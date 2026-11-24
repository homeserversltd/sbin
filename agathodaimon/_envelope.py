"""Shared reader and additive receipt custody for staff envelopes."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
import copy, json, os, re, sys
from contextvars import ContextVar
from contextlib import contextmanager
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
_gate_pin = ContextVar("staff_gate_pin_present", default=False)
_sensitive_echo = ContextVar("staff_sensitive_echo", default=False)
_INPUT_CHUNK_BYTES = 64 * 1024


@contextmanager
def echo_scope():
    """Keep non-secret presence and trace policy local to one invocation."""
    gate_token = _gate_pin.set(False)
    echo_token = _sensitive_echo.set(False)
    try:
        yield
    finally:
        _sensitive_echo.reset(echo_token)
        _gate_pin.reset(gate_token)


def mark_gate_pin_present(present: bool) -> None:
    if present:
        _gate_pin.set(True)
        _sensitive_echo.set(True)


def sensitive_echo() -> bool:
    return _sensitive_echo.get()


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
    known_fields: tuple[str, ...] = ()
    declared_flags: tuple[str, ...] = ()
    rooms: tuple[str, ...] = ()
    gate_pin_present: bool = False
    secret_bytes: dict[str, bytearray] = field(default_factory=dict, repr=False, compare=False)

    @property
    def verb(self) -> str:
        if isinstance(self.transition, str) and self.transition:
            parts = [p for p in re.split(r"[./:]", self.transition) if p]
            return parts[-1] if parts else "unknown"
        return "unknown"
def _selected(source: Mapping[str, Any], names: Sequence[str]) -> dict[str, Any]:
    return {k: source[k] for k in names if k in source}


def wipe_bytes(buffer: bytearray) -> None:
    """Zero the contents of a caller-owned buffer in place."""
    for offset in range(0, len(buffer), _INPUT_CHUNK_BYTES):
        count = min(_INPUT_CHUNK_BYTES, len(buffer) - offset)
        buffer[offset:offset + count] = b"\0" * count


def _read_bytes(data: bytearray, limit: int | None) -> None:
    stream = getattr(sys.stdin, "buffer", None)
    text_fallback = stream is None
    if text_fallback:
        stream = sys.stdin
    while True:
        size = _INPUT_CHUNK_BYTES if limit is None else min(_INPUT_CHUNK_BYTES, limit + 1 - len(data))
        # A text stream reads characters, not bytes. Near the boundary its
        # smallest unit is one character, even if that takes several bytes.
        block = stream.read(max(1, size // 4) if text_fallback else size)
        if block is None:
            raise BlockingIOError("stdin not ready")
        if not block:
            return
        if isinstance(block, str):
            block = block.encode("utf-8")
        if limit is not None and len(data) + len(block) > limit:
            del block
            raise EnvelopeError("agathodaimon-envelope-input-too-large")
        data.extend(block)
        del block


def _read_secret_input(limit: int | None) -> Any:
    data = bytearray()
    try:
        _read_bytes(data, limit)
        return json.loads(data.decode("utf-8"))
    except EnvelopeError:
        raise
    except (ValueError, OSError, RecursionError):
        # Decoder exceptions can hold the whole input. Do not chain them.
        pass
    finally:
        wipe_bytes(data)
    raise EnvelopeError("invalid JSON")


def _take_secret_bytes(
    source: dict[str, Any], names: Sequence[str], material: dict[str, bytearray],
) -> bool:
    invalid = False
    for name in names:
        if name not in source:
            continue
        text = source.pop(name)
        try:
            if isinstance(text, str):
                material[name] = bytearray(text, "utf-8")
            else:
                invalid = True
        except UnicodeEncodeError:
            invalid = True
        finally:
            del text
    return invalid


def read(
    *,
    known_fields: Sequence[str] = (),
    declared_flags: Sequence[str] = (),
    rooms: Sequence[str] = (),
    secret: Sequence[str] = (),
    secret_bytes: Sequence[str] = (),
    max_input_bytes: int | None = None,
    byte_stream: bool = False,
    quiet_on_tty: bool = False,
) -> Request:
    """Read stdin as before unless a caller opts into a different intake.

    A quiet TTY supplies the empty primitive without being read. Byte-stream
    input (implicit with a byte limit or secret_bytes) is decoded as UTF-8.
    The limit is inclusive and checked before parsing, using byte lookahead.

    secret_bytes names string fields in the payload (or flat request). They
    are removed from the request and its echo; the caller owns the buffers
    in Request.secret_bytes and must wipe them with wipe_bytes in a finally.
    The input buffer is wiped after parsing. Python's temporary decoded
    strings and storage owned by the input stream are not wipeable here.
    """
    if max_input_bytes is not None and (
        type(max_input_bytes) is not int or not 0 <= max_input_bytes < sys.maxsize
    ):
        raise EnvelopeError("agathodaimon-envelope-input-bound-invalid")
    byte_fields = tuple(secret_bytes)
    try:
        if quiet_on_tty and sys.stdin.isatty():
            raw = "{}"
            value = json.loads(raw)
        elif byte_fields:
            value = _read_secret_input(max_input_bytes)
            raw = ""  # Rebuilt from the value only after extracting secrets.
        else:
            if byte_stream or max_input_bytes is not None:
                data = bytearray()
                try:
                    _read_bytes(data, max_input_bytes)
                except UnicodeEncodeError as exc:
                    raise EnvelopeError("invalid JSON") from exc
                raw = data.decode("utf-8")
                del data
            else:
                raw = sys.stdin.read()
            value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, OSError) as exc:
        raise EnvelopeError("invalid JSON") from exc
    if not isinstance(value, dict):
        if byte_fields:
            del value
        raise EnvelopeError("JSON object required")
    if secret or byte_fields or _gate_pin.get() or _pin_bearing_exousia(value):
        _sensitive_echo.set(True)
    envelope = "schema" in value
    source = value.get("payload") if envelope else value
    material: dict[str, bytearray] = {}
    try:
        invalid_secret = bool(byte_fields) and isinstance(source, dict) and _take_secret_bytes(source, byte_fields, material)
        load_context_present, load_context = _load_trace.extract_load_context(value)
        if envelope:
            if value.get("schema") != SCHEMA: raise EnvelopeError("foreign envelope schema")
            missing = [k for k in _envelope_kernel() if k not in value]
            if missing: raise EnvelopeError("missing envelope kernel keys: " + ",".join(missing))
        if invalid_secret:
            raise EnvelopeError("agathodaimon-vault-open-request-invalid")
        if byte_fields:
            raw = json.dumps(value, ensure_ascii=True, separators=(",", ":"))

        if envelope:
            source = source if isinstance(source, Mapping) else {}
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
        else:
            payload = _selected(value, tuple(known_fields) + tuple(secret))
        for name in byte_fields:
            payload.pop(name, None)
        return Request(
            value, envelope, payload, raw,
            value.get("intent_id") if envelope else None, value.get("transition") if envelope else None,
            value.get("version") if envelope else None, value.get("timestamp") if envelope else None,
            load_context_present, load_context, secret_fields=tuple(secret) + byte_fields,
            known_fields=tuple(known_fields), declared_flags=tuple(declared_flags), rooms=tuple(rooms),
            gate_pin_present=_gate_pin.get(), secret_bytes=material,
        )
    except BaseException:
        for buffer in material.values():
            wipe_bytes(buffer)
        raise


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


def _leaf_only(value: Any) -> Any:
    """A field declaration names no children; never infer their names."""
    if isinstance(value, dict):
        return {}
    if isinstance(value, list):
        return [_leaf_only(item) for item in value]
    return copy.deepcopy(value)


def _declared_echo(request: Request) -> dict[str, Any]:
    value = request.value
    names = set(request.known_fields + request.declared_flags + request.rooms + request.secret_fields)

    def field(name: str, item: Any) -> Any:
        if name in request.secret_fields or name in _PIN_FIELDS:
            return _REDACTED_PIN
        return _leaf_only(item)

    def group(source: Any, allowed: Sequence[str]) -> dict[str, Any]:
        if not isinstance(source, Mapping):
            return {}
        result = {key: field(key, item) for key, item in source.items() if key in allowed}
        scoped = source.get("exousia")
        if isinstance(scoped, Mapping):
            children = {key: field(key, item) for key, item in scoped.items() if key in allowed}
            if children:
                result["exousia"] = children
        return result

    carried = {key: _leaf_only(value[key]) for key in (_envelope_kernel() or ("schema",)) if key in value}
    if "stamps" in value:
        stamps = value["stamps"]
        carried["stamps"] = [
            ({key: _leaf_only(stamp[key]) for key in ("verb", "outcome", "timestamp") if key in stamp}
             or {"undeclared_keys_left_out": True})
            if isinstance(stamp, Mapping) else _leaf_only(stamp)
            for stamp in stamps
        ] if isinstance(stamps, list) else _leaf_only(stamps)
    source = value.get("payload")
    if isinstance(source, Mapping):
        payload = {key: field(key, item) for key, item in source.items() if key in names and key not in ("flags", "rooms")}
        for key, allowed in (("flags", request.declared_flags), ("rooms", request.rooms)):
            nested = group(source.get(key), allowed)
            if nested:
                payload[key] = nested
        carried["payload"] = payload
    for key, allowed in (("flags", request.declared_flags), ("rooms", request.rooms)):
        nested = group(value.get(key), allowed)
        if nested:
            carried[key] = nested
    if request.gate_pin_present:
        carried.setdefault("flags", {}).setdefault("exousia", {})["pin"] = _REDACTED_PIN
    return carried


def echo_undeclared(value: dict[str, Any]) -> dict[str, Any]:
    """Project a front-door echo where no stop has declared any fields."""
    pin_present = _gate_pin.get() or _pin_bearing_exousia(value)
    if not pin_present and not _sensitive_echo.get():
        return value
    _sensitive_echo.set(True)
    request = Request(value, True, {}, "", gate_pin_present=pin_present)
    projected = _declared_echo(request)
    return {key: item for key, item in projected.items()
            if key in _envelope_kernel() or key == "flags"}


def attach(receipt: dict[str, Any], request: Request) -> dict[str, Any]:
    explicit_context = (
        request.returned_load_context
        if request.returned_load_context is not None
        else request.load_context if request.load_context_present else None
    )
    protected = request.gate_pin_present or _pin_bearing_exousia(request.value) or bool(request.secret_fields)
    if protected:
        _sensitive_echo.set(True)
    if not request.envelope:
        return _load_trace.attach_context(receipt, explicit_context, protected=protected,
                                          returned_context=request.returned_load_context is not None)
    result = dict(receipt)
    stamp = {"verb": request.verb, "outcome": _outcome(result), "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    carried = _declared_echo(request) if protected else copy.deepcopy(request.value)
    prior = carried.get("stamps"); prior = list(prior) if isinstance(prior, list) else []
    raw_envelope = json.dumps(carried, separators=(",", ":")) if protected else request.raw_envelope
    envelope = carried
    # Absent/list stamps are an additive custody lane. Preserve malformed
    # caller data in the carried envelope while top-level custody stays usable.
    if "stamps" not in request.value or isinstance(request.value.get("stamps"), list):
        envelope["stamps"] = prior + [dict(stamp)]
    result.update(intent_id=carried.get("intent_id") if protected else request.intent_id, raw_envelope=raw_envelope, envelope=envelope, stamps=prior + [dict(stamp)], staff=dict(stamp))
    return _load_trace.attach_context(result, explicit_context, protected=protected,
                                      returned_context=request.returned_load_context is not None)
def read_fields(
    *fields: str,
    flags: Sequence[str] = (),
    rooms: Sequence[str] = (),
    secret: Sequence[str] = (),
    secret_bytes: Sequence[str] = (),
    max_input_bytes: int | None = None,
    byte_stream: bool = False,
    quiet_on_tty: bool = False,
) -> Request:
    return read(
        known_fields=fields, declared_flags=flags, rooms=rooms, secret=secret,
        secret_bytes=secret_bytes,
        max_input_bytes=max_input_bytes, byte_stream=byte_stream, quiet_on_tty=quiet_on_tty,
    )

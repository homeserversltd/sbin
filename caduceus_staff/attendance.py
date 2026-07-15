"""In-memory, document-bound attendance for the Caduceus staff daemon.

This module deliberately owns no browser session and persists no attendance,
challenge, ticket, capability, PIN, signature, or key material. A daemon restart
therefore starts with empty maps and fails closed. Callers may return successful
secret-bearing values only over Caduceus's private socket; public receipts must
use :meth:`public_error` and contain no request material.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

CHALLENGE_TTL_SECONDS = 30
CAPABILITY_TTL_SECONDS = 60
DOMAIN = b"caduceus.document-attendance.v1\x00"
PIN_ROTATION_ACTION = "pin.rotate"
PIN_ROTATION_TARGET = "homeserver.global.admin.pin"
PURPOSES = frozenset({
    "session.mint", "session.prove", "session.clear", "capability.mint", "pin.change"
})


class AccessRefused(Exception):
    """A deliberately detail-free refusal safe for public/error transports."""

    def __init__(self, code: str = "access-refused") -> None:
        super().__init__(code)
        self.code = code


def public_error(_: Exception | None = None) -> dict[str, object]:
    """Return the only public failure shape; never echo secret-bearing input."""
    return {"schema": "caduceus.staff.attendance.error.v1", "ok": False, "error": "access-refused"}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 1024:
        raise AccessRefused()
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:  # no decoder details across the membrane
        raise AccessRefused() from exc


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _bounded_text(value: object, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AccessRefused()
    return value


def _p256_key(jwk: Mapping[str, Any]) -> tuple[ec.EllipticCurvePublicKey, str]:
    if not isinstance(jwk, Mapping) or set(jwk) != {"kty", "crv", "x", "y"}:
        raise AccessRefused()
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise AccessRefused()
    x = int.from_bytes(_unb64u(jwk["x"]), "big")
    y = int.from_bytes(_unb64u(jwk["y"]), "big")
    try:
        key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise AccessRefused() from exc
    thumbprint = _b64u(hashlib.sha256(_canonical({"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]})).digest())
    return key, thumbprint


def _context(purpose: str, raw: Mapping[str, Any]) -> dict[str, Any]:
    if purpose not in PURPOSES or not isinstance(raw, Mapping):
        raise AccessRefused()
    if purpose == "session.mint":
        if set(raw) != {"public_jwk"}:
            raise AccessRefused()
        _, thumbprint = _p256_key(raw["public_jwk"])
        return {"public_jwk": dict(raw["public_jwk"]), "thumbprint": thumbprint}
    if purpose == "session.clear":
        if set(raw) != {"ticket"}:
            raise AccessRefused()
        return {"ticket": _bounded_text(raw["ticket"], maximum=512)}
    if purpose == "session.prove":
        if set(raw) != {"ticket", "read", "method", "target"}:
            raise AccessRefused()
        return {k: _bounded_text(raw[k], maximum=512 if k == "ticket" else 256) for k in ("ticket", "read", "method", "target")}
    if purpose == "capability.mint":
        if set(raw) != {"ticket", "action", "target"}:
            raise AccessRefused()
        return {k: _bounded_text(raw[k], maximum=512 if k == "ticket" else 256) for k in ("ticket", "action", "target")}
    if set(raw) != {"ticket", "action", "target"}:
        raise AccessRefused()
    context = {k: _bounded_text(raw[k], maximum=512 if k == "ticket" else 256) for k in ("ticket", "action", "target")}
    if context["action"] != PIN_ROTATION_ACTION or context["target"] != PIN_ROTATION_TARGET:
        raise AccessRefused()
    return context


class KeymanCustody(Protocol):
    """Existing staff custody: no raw PIN fallback is permitted."""

    def verify_pin(self, pin: str) -> bool: ...
    def rotate_pin(self, new_pin: str) -> bool: ...


@dataclass(frozen=True)
class Capability:
    token: str
    attendance_ticket: str
    action: str
    target: str
    expires_at: int


class CapabilityAuthority:
    """Bounded one-use capability store; it remains subordinate to attendance."""

    def __init__(self, *, clock: Callable[[], float] = time.time, token_factory: Callable[[], str] | None = None) -> None:
        self._clock, self._token_factory = clock, token_factory or (lambda: secrets.token_urlsafe(32))
        self._capabilities: dict[str, Capability] = {}
        self._lock = threading.RLock()

    def mint(self, *, attendance_ticket: str, action: str, target: str) -> Capability:
        with self._lock:
            token = self._token_factory()
            cap = Capability(token, attendance_ticket, action, target, int(self._clock()) + CAPABILITY_TTL_SECONDS)
            self._capabilities[token] = cap
            return cap

    def consume(self, token: str, *, attendance_ticket: str, action: str, target: str) -> bool:
        with self._lock:
            cap = self._capabilities.pop(token, None)
            if cap is None or cap.expires_at <= self._clock():
                return False
            return (cap.attendance_ticket, cap.action, cap.target) == (attendance_ticket, action, target)


@dataclass(frozen=True)
class _Challenge:
    purpose: str
    context: dict[str, Any]
    challenge: str
    expires_at: int


@dataclass(frozen=True)
class _Attendance:
    thumbprint: str
    public_key: ec.EllipticCurvePublicKey


class AttendanceStaff:
    """The persistent daemon-process state holder for document attendance."""

    def __init__(
        self,
        custody: KeymanCustody,
        *,
        capability_authority: CapabilityAuthority | None = None,
        clock: Callable[[], float] = time.time,
        token_factory: Callable[[], str] | None = None,
    ) -> None:
        self._custody = custody
        self._clock = clock
        self._token_factory = token_factory or (lambda: secrets.token_urlsafe(32))
        self._capabilities = capability_authority or CapabilityAuthority(clock=clock, token_factory=self._token_factory)
        self._challenges: dict[str, _Challenge] = {}
        self._attendances: dict[str, _Attendance] = {}
        self._lock = threading.RLock()

    def _reap(self) -> None:
        now = self._clock()
        self._challenges = {key: item for key, item in self._challenges.items() if item.expires_at > now}

    def challenge_mint(self, purpose: str, context: Mapping[str, Any]) -> dict[str, object]:
        validated = _context(purpose, context)
        with self._lock:
            self._reap()
            challenge_id, challenge = self._token_factory(), self._token_factory()
            expires_at = int(self._clock()) + CHALLENGE_TTL_SECONDS
            self._challenges[challenge_id] = _Challenge(purpose, validated, challenge, expires_at)
            return {"schema": "caduceus.staff.attendance.challenge.v1", "challenge_id": challenge_id, "challenge": challenge, "expires_at": expires_at}

    def _consume_challenge(self, purpose: str, challenge_id: str, expected: Mapping[str, Any] | None = None) -> _Challenge:
        with self._lock:
            self._reap()
            item = self._challenges.pop(_bounded_text(challenge_id, maximum=512), None)
            if item is None or item.purpose != purpose:
                raise AccessRefused()
            if expected is not None and item.context != _context(purpose, expected):
                raise AccessRefused()
            return item

    @staticmethod
    def _message(challenge_id: str, item: _Challenge) -> bytes:
        return DOMAIN + _canonical({"challenge_id": challenge_id, "challenge": item.challenge, "purpose": item.purpose, "context": item.context})

    def _verify(self, attendance: _Attendance, challenge_id: str, item: _Challenge, signature: str) -> None:
        try:
            attendance.public_key.verify(_unb64u(signature), self._message(challenge_id, item), ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError, AccessRefused) as exc:
            raise AccessRefused() from exc

    def _active(self, ticket: str) -> _Attendance:
        with self._lock:
            attendance = self._attendances.get(_bounded_text(ticket, maximum=512))
            if attendance is None:
                raise AccessRefused()
            return attendance

    def session_mint(self, *, pin: str, challenge_id: str, signature: str) -> dict[str, object]:
        item = self._consume_challenge("session.mint", challenge_id)
        key, thumbprint = _p256_key(item.context["public_jwk"])
        candidate = _Attendance(thumbprint, key)
        self._verify(candidate, challenge_id, item, signature)
        if not isinstance(pin, str) or not self._custody.verify_pin(pin):
            raise AccessRefused()
        with self._lock:
            ticket = self._token_factory()
            self._attendances[ticket] = candidate
        return {"schema": "caduceus.staff.attendance.session-mint.v1", "ticket": ticket, "thumbprint": thumbprint}

    def session_prove(self, *, ticket: str, challenge_id: str, signature: str, read: str, method: str, target: str) -> dict[str, object]:
        expected = {"ticket": ticket, "read": read, "method": method, "target": target}
        item = self._consume_challenge("session.prove", challenge_id, expected)
        attendance = self._active(ticket)
        self._verify(attendance, challenge_id, item, signature)
        return {"schema": "caduceus.staff.attendance.session-prove.v1", "ok": True}

    def capability_mint(self, *, ticket: str, challenge_id: str, signature: str, action: str, target: str) -> dict[str, object]:
        expected = {"ticket": ticket, "action": action, "target": target}
        item = self._consume_challenge("capability.mint", challenge_id, expected)
        attendance = self._active(ticket)
        self._verify(attendance, challenge_id, item, signature)
        cap = self._capabilities.mint(attendance_ticket=ticket, action=action, target=target)
        return {"schema": "caduceus.staff.attendance.capability-mint.v1", "capability": cap.token, "expires_at": cap.expires_at}

    def session_clear(self, *, ticket: str, challenge_id: str, signature: str) -> dict[str, object]:
        item = self._consume_challenge("session.clear", challenge_id, {"ticket": ticket})
        attendance = self._active(ticket)
        self._verify(attendance, challenge_id, item, signature)
        with self._lock:
            self._attendances.pop(ticket, None)
        return {"schema": "caduceus.staff.attendance.session-clear.v1", "ok": True}

    def consume_capability(self, *, ticket: str, capability: str, action: str, target: str) -> bool:
        """Admission seam for the existing one-use capability actuator path.

        The attendance check remains here, so a retained capability cannot cross
        an actuator boundary after its parent attendance is cleared.
        """
        self._active(ticket)
        return self._capabilities.consume(capability, attendance_ticket=ticket, action=action, target=target)

    def pin_change(self, *, ticket: str, challenge_id: str, signature: str, capability: str, new_pin: str) -> dict[str, object]:
        expected = {"ticket": ticket, "action": PIN_ROTATION_ACTION, "target": PIN_ROTATION_TARGET}
        item = self._consume_challenge("pin.change", challenge_id, expected)
        attendance = self._active(ticket)
        self._verify(attendance, challenge_id, item, signature)
        if not isinstance(new_pin, str) or not 4 <= len(new_pin) <= 128:
            raise AccessRefused()
        if not self._capabilities.consume(capability, attendance_ticket=ticket, action=PIN_ROTATION_ACTION, target=PIN_ROTATION_TARGET):
            raise AccessRefused()
        if not self._custody.rotate_pin(new_pin):
            raise AccessRefused()
        return {"schema": "caduceus.staff.attendance.pin-change.v1", "ok": True}

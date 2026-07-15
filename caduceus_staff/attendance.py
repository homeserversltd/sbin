"""Document-bound attendance state and private staff-socket dispatcher.

The staff process is the only holder of the Keyman-derived Ed25519 signer.  Its
maps are deliberately process-local: a restart invalidates every attendance and
capability.  Browser proof uses WebCrypto's 64-byte P-256 IEEE-P1363 format.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
import secrets
import select
import socket
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

CHALLENGE_TTL_SECONDS = 30
CAPABILITY_TTL_SECONDS = 60
MAX_REQUEST_BYTES = 8192
MAX_REGISTRY_ITEMS = 1024
DOMAIN = b"caduceus.document-attendance.v2\x00"
PIN_ROTATION_ACTION = "global.admin.pin.rotate"
PIN_ROTATION_TARGET = "global.admin.pin"
PURPOSES = frozenset({"session.mint", "session.prove", "session.clear", "capability.mint", "pin.change"})


class AccessRefused(Exception):
    def __init__(self, code: str = "access-refused") -> None:
        super().__init__(code)
        self.code = code


def public_error(_: Exception | None = None) -> dict[str, object]:
    return {"schema": "caduceus.staff.attendance.error.v1", "ok": False, "error": "access-refused"}


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(value: object, *, exact: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise AccessRefused()
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise AccessRefused() from exc
    if exact is not None and len(raw) != exact:
        raise AccessRefused()
    return raw


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _bounded_text(value: object, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise AccessRefused()
    return value


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _p256_key(jwk: object) -> tuple[ec.EllipticCurvePublicKey, str]:
    if not isinstance(jwk, Mapping) or set(jwk) != {"kty", "crv", "x", "y"}:
        raise AccessRefused()
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise AccessRefused()
    x_raw, y_raw = _unb64u(jwk["x"], exact=32), _unb64u(jwk["y"], exact=32)
    try:
        key = ec.EllipticCurvePublicNumbers(int.from_bytes(x_raw, "big"), int.from_bytes(y_raw, "big"), ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise AccessRefused() from exc
    canonical_jwk = {"crv": "P-256", "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    return key, _b64u(hashlib.sha256(_canonical(canonical_jwk)).digest())


def challenge_message(challenge_id: str, challenge: str, purpose: str, context: Mapping[str, Any]) -> bytes:
    """Exact browser signing equation: DOMAIN || canonical JSON challenge tuple."""
    return DOMAIN + _canonical({"challenge_id": challenge_id, "challenge": challenge, "context": dict(context), "purpose": purpose})


def _context(purpose: str, raw: object) -> dict[str, Any]:
    if purpose not in PURPOSES or not isinstance(raw, Mapping):
        raise AccessRefused()
    if purpose == "session.mint":
        if set(raw) != {"document_public_key"}:
            raise AccessRefused()
        _, thumbprint = _p256_key(raw["document_public_key"])
        return {"document_public_key": dict(raw["document_public_key"]), "document_key_thumbprint": thumbprint}
    fields = {"session.prove": ("ticket", "read", "method", "target"), "session.clear": ("ticket",), "capability.mint": ("ticket", "action", "target"), "pin.change": ("ticket", "action", "target")}[purpose]
    if set(raw) != set(fields):
        raise AccessRefused()
    result = {key: _bounded_text(raw[key], maximum=4096 if key == "ticket" else 256) for key in fields}
    if purpose == "pin.change" and (result["action"], result["target"]) != (PIN_ROTATION_ACTION, PIN_ROTATION_TARGET):
        raise AccessRefused()
    return result


class DerivedSigner(Protocol):
    public_key_hex: str
    epoch: object
    signer_epoch: object
    def private_key(self) -> Any: ...
    def close(self) -> None: ...


class KeymanAdapter:
    """Imports exactly the root-only Keyman module; never exports or derives keys."""
    def __init__(self, module_path: str = "/opt/keyman/runtime/lib/keyman_caduceus_access.py") -> None:
        self.module_path = module_path
        self._module: Any | None = None

    def _load(self) -> Any:
        if self._module is None:
            name = "_caduceus_keyman_" + hashlib.sha256(os.fsencode(self.module_path)).hexdigest()
            spec = importlib.util.spec_from_file_location(name, self.module_path)
            if spec is None or spec.loader is None:
                raise AccessRefused("unbound")
            module = importlib.util.module_from_spec(spec)
            sys.modules[name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                if sys.modules.get(name) is module:
                    del sys.modules[name]
                raise
            self._module = module
        return self._module

    def bind_derived_caduceus(self) -> DerivedSigner:
        return self._load().bind_derived_caduceus()

    def verify_and_derive_caduceus(self, pin: str) -> DerivedSigner:
        return self._load().verify_and_derive_caduceus(pin)

    def change_caduceus_pin(self, old_pin: str, new_pin: str) -> None:
        self._load().change_caduceus_pin(old_pin, new_pin)


def _signer_public(signer: Any) -> bytes:
    value = getattr(signer, "public_key_hex", None)
    if callable(value): value = value()
    if not isinstance(value, str) or len(value) != 64:
        raise AccessRefused("unbound")
    try:
        public = bytes.fromhex(value)
    except ValueError as exc:
        raise AccessRefused("unbound") from exc
    if len(public) != 32:
        raise AccessRefused("unbound")
    return public


def _signer_epoch(signer: Any) -> str:
    values = []
    for name in ("signer_epoch", "epoch"):
        value = getattr(signer, name, None)
        if callable(value): value = value()
        if isinstance(value, bytes): value = _b64u(value)
        if value is not None:
            if not isinstance(value, (str, int)):
                raise AccessRefused("unbound")
            values.append(str(value))
    if not values or any(value != values[0] for value in values[1:]):
        raise AccessRefused("unbound")
    return values[0]


def redacted_journal_sink(event: Mapping[str, object]) -> None:
    """Bounded Hyalos-friendly JSON line without private request material."""
    allowed = {"operation", "outcome", "epoch", "attendance_digest", "jti_digest", "scope"}
    safe = {key: value for key, value in event.items() if key in allowed and isinstance(value, (str, int, float, bool, type(None)))}
    wire = _canonical(safe)
    if len(wire) > 1024:
        wire = b'{"operation":"audit","outcome":"redacted"}'
    sys.stderr.buffer.write(wire + b"\n")
    sys.stderr.flush()


def _close(signer: Any) -> None:
    closer = getattr(signer, "close", None)
    if callable(closer):
        try: closer()
        except Exception: pass


@dataclass(frozen=True)
class _Challenge:
    purpose: str
    context: dict[str, Any]
    challenge: str
    expires_at: int


@dataclass(frozen=True)
class _Attendance:
    ticket: str
    thumbprint: str
    public_key: ec.EllipticCurvePublicKey
    epoch: str
    jti: str


@dataclass(frozen=True)
class _Capability:
    token: str
    parent_ticket: str
    action: str
    target: str
    expires_at: int
    jti: str


class AttendanceStaff:
    def __init__(self, keyman: Any | None = None, *, clock: Callable[[], float] = time.time, token_factory: Callable[[], str] | None = None, audit_sink: Callable[[dict[str, object]], None] | None = None) -> None:
        self._keyman, self._clock = keyman or KeymanAdapter(), clock
        self._token_factory, self._audit_sink = token_factory or (lambda: secrets.token_urlsafe(32)), audit_sink or (lambda _: None)
        self._lock = threading.RLock(); self._challenges: dict[str, _Challenge] = {}; self._attendances: dict[str, _Attendance] = {}; self._capabilities: dict[str, _Capability] = {}
        self._signer: Any | None = None; self._posture = "UNBOUND"; self._epoch: str | None = None; self._public: bytes | None = None
        self._bind_startup()

    def _audit(self, operation: str, outcome: str, *, attendance: str | None = None, jti: str | None = None, scope: str | None = None) -> None:
        event: dict[str, object] = {"operation": operation, "outcome": outcome, "epoch": self._epoch}
        if attendance: event["attendance_digest"] = _digest(attendance)
        if jti: event["jti_digest"] = _digest(jti)
        if scope: event["scope"] = scope
        try: self._audit_sink(event)
        except Exception: pass

    def _bind_startup(self) -> bool:
        old = self._signer
        try:
            signer = self._keyman.bind_derived_caduceus(); public, epoch = _signer_public(signer), _signer_epoch(signer)
        except Exception:
            self._signer = None; self._public = None; self._epoch = None; self._posture = "UNBOUND" if old is None else "STALE_DERIVED"; self._audit("signing.bind", self._posture); return False
        self._signer, self._public, self._epoch, self._posture = signer, public, epoch, "BOUND"
        if old is not signer:
            _close(old)
        self._audit("signing.bind", "BOUND"); return True

    def signing_status(self) -> dict[str, object]:
        if self._posture != "BOUND" or self._public is None or self._epoch is None: return {"schema": "caduceus.staff.signing.status.v1", "posture": self._posture}
        return {"schema": "caduceus.staff.signing.status.v1", "posture": "BOUND", "public_key": _b64u(self._public), "epoch": self._epoch}

    def _bound(self, operation: str) -> None:
        if self._posture != "BOUND" or self._signer is None: self._audit(operation, self._posture); raise AccessRefused()

    def _reap(self) -> None:
        now = self._clock()
        self._challenges = {k:v for k,v in self._challenges.items() if v.expires_at > now}
        self._capabilities = {k:v for k,v in self._capabilities.items() if v.expires_at > now}

    def _room(self, registry: dict[str, Any]) -> None:
        if len(registry) >= MAX_REGISTRY_ITEMS: raise AccessRefused()

    def _token(self, claims: Mapping[str, Any]) -> str:
        self._bound("token.sign")
        signer = self._signer
        if signer is None:
            raise AccessRefused()
        payload = _canonical(claims)
        try: signature = signer.private_key().sign(payload)
        except Exception as exc: raise AccessRefused() from exc
        if not isinstance(signature, bytes) or len(signature) != 64: raise AccessRefused()
        return _b64u(_canonical({"payload": _b64u(payload), "signature": _b64u(signature)}))

    def challenge_mint(self, purpose: str, context: Mapping[str, Any]) -> dict[str, object]:
        self._bound("challenge.mint"); validated = _context(purpose, context)
        with self._lock:
            self._reap(); self._room(self._challenges); cid, challenge = self._token_factory(), self._token_factory(); expires = int(self._clock()) + CHALLENGE_TTL_SECONDS
            self._challenges[cid] = _Challenge(purpose, validated, challenge, expires)
        self._audit("challenge.mint", "OK", scope=purpose)
        return {"schema":"caduceus.staff.attendance.challenge.v1", "challenge_id":cid, "challenge":challenge, "expires_at":expires}

    def _consume(self, purpose: str, challenge_id: str, expected: Mapping[str, Any] | None = None) -> _Challenge:
        with self._lock:
            self._reap(); item = self._challenges.pop(_bounded_text(challenge_id, maximum=512), None)
        if item is None or item.purpose != purpose or (expected is not None and item.context != _context(purpose, expected)):
            self._audit(purpose, "REPLAY_OR_SCOPE"); raise AccessRefused()
        return item

    def _verify(self, attendance: _Attendance, challenge_id: str, item: _Challenge, signature: object) -> None:
        raw = _unb64u(signature, exact=64)
        der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
        try: attendance.public_key.verify(der, challenge_message(challenge_id, item.challenge, item.purpose, item.context), ec.ECDSA(hashes.SHA256()))
        except (InvalidSignature, ValueError, TypeError) as exc: self._audit(item.purpose, "WRONG_PROOF"); raise AccessRefused() from exc

    def _active(self, ticket: str) -> _Attendance:
        self._bound("attendance.current")
        with self._lock: attendance = self._attendances.get(_bounded_text(ticket, maximum=4096))
        if attendance is None: self._audit("attendance.current", "INACTIVE", attendance=ticket); raise AccessRefused()
        return attendance

    def session_mint(self, *, pin: str, challenge_id: str, signature: str) -> dict[str, object]:
        self._bound("session.mint"); item = self._consume("session.mint", challenge_id); key, thumbprint = _p256_key(item.context["document_public_key"])
        candidate = _Attendance("", thumbprint, key, self._epoch or "", self._token_factory()); self._verify(candidate, challenge_id, item, signature)
        if not isinstance(pin, str) or not 4 <= len(pin) <= 128: raise AccessRefused()
        try: derived = self._keyman.verify_and_derive_caduceus(pin); same = hmac.compare_digest(_signer_public(derived), self._public or b"") and hmac.compare_digest(_signer_epoch(derived).encode(), (self._epoch or "").encode())
        except Exception: same = False; derived = None
        finally:
            if 'derived' in locals() and derived is not None: _close(derived)
        if not same: self._audit("session.mint", "WRONG_PIN"); raise AccessRefused()
        claims = {"kind":"attendance","version":1,"attendance_id":candidate.jti,"document_key_thumbprint":thumbprint,"signer_epoch":self._epoch,"issued_at":int(self._clock()),"jti":candidate.jti}
        ticket = self._token(claims); candidate = _Attendance(ticket, thumbprint, key, self._epoch or "", candidate.jti)
        with self._lock: self._room(self._attendances); self._attendances[ticket] = candidate
        self._audit("session.mint", "OK", attendance=ticket, jti=candidate.jti)
        return {"schema":"caduceus.staff.attendance.session-mint.v1","ticket":ticket,"document_key_thumbprint":thumbprint,"epoch":self._epoch}

    def session_prove(self, *, ticket: str, challenge_id: str, signature: str, read: str, method: str, target: str) -> dict[str, object]:
        item = self._consume("session.prove", challenge_id, {"ticket":ticket,"read":read,"method":method,"target":target}); attendance = self._active(ticket); self._verify(attendance, challenge_id, item, signature); self._audit("session.prove", "OK", attendance=ticket); return {"ok":True}

    def capability_mint(self, *, ticket: str, challenge_id: str, signature: str, action: str, target: str) -> dict[str, object]:
        item = self._consume("capability.mint", challenge_id, {"ticket":ticket,"action":action,"target":target}); attendance = self._active(ticket); self._verify(attendance, challenge_id, item, signature)
        jti, expires = self._token_factory(), int(self._clock()) + CAPABILITY_TTL_SECONDS; claims = {"kind":"capability","version":1,"parent_attendance_id":attendance.jti,"action":action,"target":target,"signer_epoch":self._epoch,"exp":expires,"jti":jti}; token = self._token(claims)
        with self._lock: self._room(self._capabilities); self._capabilities[token] = _Capability(token,ticket,action,target,expires,jti)
        self._audit("capability.mint", "OK", attendance=ticket, jti=jti, scope=f"{action}:{target}"); return {"capability":token,"expires_at":expires}

    def session_clear(self, *, ticket: str, challenge_id: str, signature: str) -> dict[str, object]:
        item = self._consume("session.clear", challenge_id, {"ticket":ticket}); attendance = self._active(ticket); self._verify(attendance, challenge_id, item, signature)
        with self._lock: self._attendances.pop(ticket, None); self._capabilities = {k:v for k,v in self._capabilities.items() if v.parent_ticket != ticket}
        self._audit("session.clear", "OK", attendance=ticket); return {"ok":True}

    def consume_capability(self, *, ticket: str, capability: str, action: str, target: str) -> bool:
        self._active(ticket)
        with self._lock: self._reap(); item = self._capabilities.pop(capability, None)
        ok = item is not None and (item.parent_ticket,item.action,item.target) == (ticket,action,target)
        self._audit("capability.consume", "OK" if ok else "REPLAY_OR_SCOPE", attendance=ticket, jti=item.jti if item else None, scope=f"{action}:{target}"); return ok

    def pin_change(self, *, ticket: str, challenge_id: str, signature: str, capability: str, old_pin: str, new_pin: str) -> dict[str, object]:
        item = self._consume("pin.change", challenge_id, {"ticket":ticket,"action":PIN_ROTATION_ACTION,"target":PIN_ROTATION_TARGET}); attendance = self._active(ticket); self._verify(attendance, challenge_id, item, signature)
        if not all(isinstance(pin,str) and 4 <= len(pin) <= 128 for pin in (old_pin,new_pin)): raise AccessRefused()
        with self._lock:
            self._reap(); cap = self._capabilities.pop(capability, None)
        if cap is None or (cap.parent_ticket, cap.action, cap.target) != (ticket, PIN_ROTATION_ACTION, PIN_ROTATION_TARGET):
            self._audit("pin.change", "REPLAY_OR_SCOPE", attendance=ticket); raise AccessRefused()
        try: self._keyman.change_caduceus_pin(old_pin,new_pin)
        except Exception: self._audit("pin.change","WRONG_OLD_PIN",attendance=ticket); raise AccessRefused()
        # A successful Keyman change is the epoch transition.  The capability
        # was already spent for this single Keyman actuator attempt.
        with self._lock: self._attendances.clear(); self._challenges.clear(); self._capabilities.clear()
        old = self._signer; self._signer = None; self._posture = "STALE_DERIVED"; _close(old)
        if not self._bind_startup(): self._audit("pin.change","STALE_DERIVED"); raise AccessRefused()
        self._audit("pin.change","OK",jti=attendance.jti); return {"ok":True,"public_key":_b64u(self._public or b""),"epoch":self._epoch}

    def attendance_current(self, ticket: str) -> dict[str, object]:
        attendance = self._active(ticket); return {"current":True,"epoch":attendance.epoch}

    def dispatch(self, request: Mapping[str, Any]) -> dict[str, object]:
        op = request.get("op")
        if op == "signing.status": return self.signing_status()
        if not isinstance(op,str): raise AccessRefused()
        if op == "challenge.mint": return self.challenge_mint(_bounded_text(request.get("purpose")), request.get("context"))
        if op == "session.mint": return self.session_mint(pin=request.get("pin"),challenge_id=request.get("challenge_id"),signature=request.get("signature"))
        if op == "session.prove": return self.session_prove(ticket=request.get("ticket"),challenge_id=request.get("challenge_id"),signature=request.get("signature"),read=request.get("read"),method=request.get("method"),target=request.get("target"))
        if op == "session.clear": return self.session_clear(ticket=request.get("ticket"),challenge_id=request.get("challenge_id"),signature=request.get("signature"))
        if op == "capability.mint": return self.capability_mint(ticket=request.get("ticket"),challenge_id=request.get("challenge_id"),signature=request.get("signature"),action=request.get("action"),target=request.get("target"))
        if op == "pin.change": return self.pin_change(ticket=request.get("ticket"),challenge_id=request.get("challenge_id"),signature=request.get("signature"),capability=request.get("capability"),old_pin=request.get("old_pin"),new_pin=request.get("new_pin"))
        if op == "attendance.current": return self.attendance_current(request.get("ticket"))
        raise AccessRefused()


class StaffSocketDaemon:
    def __init__(self, staff: AttendanceStaff, path: str = "/run/caduceus/caduceus-staff.sock") -> None: self.staff, self.path, self._stop = staff, path, threading.Event()
    def serve_forever(self) -> None:
        directory = os.path.dirname(self.path) or "."; os.makedirs(directory, mode=0o700, exist_ok=True)
        try: os.unlink(self.path)
        except FileNotFoundError: pass
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(self.path); os.chmod(self.path,0o600); server.listen(16); server.settimeout(0.2)
            while not self._stop.is_set():
                try: conn,_ = server.accept()
                except TimeoutError: continue
                threading.Thread(target=self._handle,args=(conn,),daemon=True).start()
        try: os.unlink(self.path)
        except FileNotFoundError: pass
    def stop(self) -> None: self._stop.set()
    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                conn.settimeout(2); raw = bytearray()
                while b"\n" not in raw:
                    chunk = conn.recv(MAX_REQUEST_BYTES + 1 - len(raw))
                    if not chunk:
                        raise AccessRefused()
                    raw.extend(chunk)
                    if len(raw) > MAX_REQUEST_BYTES:
                        raise AccessRefused()
                if raw.count(b"\n") != 1 or not raw.endswith(b"\n"):
                    raise AccessRefused()
                if select.select([conn], [], [], 0)[0] and conn.recv(1):
                    raise AccessRefused()
                request = json.loads(bytes(raw[:-1]).decode("utf-8")); response = self.staff.dispatch(request) if isinstance(request,dict) else (_ for _ in ()).throw(AccessRefused())
            except Exception as exc: response = public_error(exc)
            wire = _canonical(response) + b"\n"
            conn.sendall(wire if len(wire) <= MAX_REQUEST_BYTES else _canonical(public_error()) + b"\n")

"""Admin-admittance PIN actuator faces."""
from __future__ import annotations
import hmac
import json
import sys
from collections.abc import Mapping
from typing import Any, Callable

from agathodaimon.lib import keyman_caduceus_access as keyman
from agathodaimon.lib.sacred_credential import index as sacred_credential


def _failure(exc: BaseException) -> dict[str, object]:
    code = getattr(exc, "args", (None,))[0]
    if not isinstance(code, str) or not code or len(code) > 128 or any(ord(c) < 32 or ord(c) > 126 for c in code):
        code = "admin-admittance-actuator-refused"
    return {"ok": False, "firstMissingSignal": code, "error": code}


def _payload() -> dict[str, Any]:
    raw = sys.stdin.read()
    value = json.loads(raw) if raw else {}
    if not isinstance(value, Mapping):
        raise ValueError("admin-admittance-payload-invalid")
    return dict(value)


def _pin(payload: Mapping[str, Any], *names: str) -> str:
    for name in names:
        value = payload.get(name)
        if isinstance(value, str):
            return value
    raise ValueError("admin-admittance-pin-required")


def _projection(signer: Any) -> dict[str, object]:
    public = getattr(signer, "public_key_hex", None)
    epoch = getattr(signer, "epoch", None)
    if callable(public): public = public()
    if callable(epoch): epoch = epoch()
    if not isinstance(public, str) or not public or not isinstance(epoch, str):
        raise ValueError("admin-admittance-signer-projection-unavailable")
    return {"ok": True, "publicKey": public, "epoch": epoch}


def bind(_: Mapping[str, Any]) -> dict[str, object]:
    with keyman.bind_derived_caduceus() as signer:
        return _projection(signer)


def verify(payload: Mapping[str, Any]) -> dict[str, object]:
    expected_public_key = payload.get("publicKey")
    if not isinstance(expected_public_key, str) or not expected_public_key:
        raise ValueError("admin-admittance-public-key-required")
    try:
        with keyman.verify_and_derive_caduceus(_pin(payload, "pin")) as signer:
            actual_public_key = getattr(signer, "public_key_hex", None)
            if not isinstance(actual_public_key, str) or not actual_public_key:
                raise ValueError("admin-admittance-signer-projection-unavailable")
            verified = hmac.compare_digest(actual_public_key, expected_public_key)
        return {"ok": True, "verified": verified}
    except Exception as exc:
        if getattr(exc, "args", (None,))[0] == "caduceus-pin-refused":
            return {"ok": True, "verified": False}
        raise

def change(payload: Mapping[str, Any]) -> dict[str, object]:
    current = _pin(payload, "currentPin", "oldPin")
    new = _pin(payload, "newPin")
    keyman.change_caduceus_pin(current, new)
    with keyman.bind_derived_caduceus() as signer:
        return _projection(signer)


def reset_default(_: Mapping[str, Any]) -> dict[str, object]:
    sacred_credential.reset_caduceus_pin_to_provisioned_default()
    with keyman.bind_derived_caduceus() as signer:
        return _projection(signer)


def run(operation: Callable[[Mapping[str, Any]], dict[str, object]]) -> int:
    try:
        result = operation(_payload())
    except Exception as exc:
        result = _failure(exc)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1

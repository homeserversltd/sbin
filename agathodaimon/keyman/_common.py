"""Shared Keyman request and redaction helpers."""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "caduceus.staff.v1"
BACKEND = "keyman-rust-crown"
PREFIX = ["/usr/bin/sudo", "-n", "/vault/keyman/keyman"]
MAX_OUTPUT = 1024 * 1024
REDACTED = "[REDACTED]"
_SECRET_NAMES = {
    "key", "keymaterial", "privatekey", "secretkey", "seed", "seedphrase",
    "token", "credential", "passphrase", "pin",
}


@dataclass(frozen=True)
class Request:
    value: dict[str, Any]
    payload: dict[str, Any]
    is_envelope: bool


def _secret_name(name: object) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return (
        "password" in normalized
        or normalized.endswith("pin")
        or normalized in _SECRET_NAMES
        or normalized in {"keybytes", "keydata", "keyfilematerial"}
    )


def _collect_secret_values(value: Any, found: set[str]) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _secret_name(key):
                _collect_string_values(child, found)
            else:
                _collect_secret_values(child, found)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_secret_values(child, found)


def _collect_string_values(value: Any, found: set[str]) -> None:
    if isinstance(value, str) and value:
        found.add(value)
    elif isinstance(value, Mapping):
        for child in value.values():
            _collect_string_values(child, found)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_string_values(child, found)


def _scrub(value: Any, secrets: set[str]) -> Any:
    if isinstance(value, Mapping):
        safe: dict[Any, Any] = {}
        for key, child in value.items():
            safe_key = _scrub(key, secrets) if isinstance(key, str) else key
            if safe_key in safe:
                # Preserve both unknown fields if redaction maps keys together.
                marker = next(
                    (chr(code) for code in range(0xE000, 0xF8FF)
                     if all(chr(code) not in secret for secret in secrets)),
                    "_",
                )
                while safe_key in safe:
                    safe_key = f"{safe_key}{marker}"
            safe[safe_key] = REDACTED if _secret_name(key) else _scrub(child, secrets)
        return safe
    if isinstance(value, list):
        return [_scrub(child, secrets) for child in value]
    if isinstance(value, tuple):
        return [_scrub(child, secrets) for child in value]
    if isinstance(value, str):
        result = value
        for secret in sorted(secrets, key=len, reverse=True):
            result = result.replace(secret, REDACTED)
        return result
    return value


def _emit(receipt: dict[str, Any], request: Request | None, secrets: set[str]) -> int:
    if request is not None and request.is_envelope:
        carried = _scrub(copy.deepcopy(request.value), secrets)
        prior = carried.get("stamps")
        prior = list(prior) if isinstance(prior, list) else []
        stamp = {
            "verb": receipt.get("operation", "unknown"),
            "outcome": "ok" if receipt.get("ok") is True else "failed",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        if "stamps" not in request.value or isinstance(request.value.get("stamps"), list):
            carried["stamps"] = prior + [dict(stamp)]
        receipt.update(
            intent_id=_scrub(request.value.get("intent_id"), secrets),
            raw_envelope=json.dumps(carried, separators=(",", ":"), ensure_ascii=False),
            envelope=carried,
            stamps=prior + [dict(stamp)],
            staff=dict(stamp),
        )
    safe = _scrub(receipt, secrets)
    print(json.dumps(safe, separators=(",", ":"), ensure_ascii=False))
    return 0 if safe.get("ok") is True else 1

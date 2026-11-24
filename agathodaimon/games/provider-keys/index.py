"""Safely report and update runtime game-provider API keys."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

from agathodaimon import _envelope

SUPPORTED_KEYS = ("THEGAMESDB_API_KEY", "SCREENSCRAPER_API_KEY")
DEFAULT_PATH = Path("/etc/arch-game-sync/providers.env")


class _PayloadRequired(ValueError):
    pass


def provider_path() -> Path:
    return DEFAULT_PATH


def _read() -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        lines = provider_path().read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return values
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in SUPPORTED_KEYS:
            continue
        try:
            parsed = shlex.split(value, comments=False, posix=True)
        except ValueError:
            continue
        if parsed:
            values[key] = parsed[0]
    return values


def _status() -> dict[str, Any]:
    values = _read()
    return {
        "ok": True,
        "path": str(provider_path()),
        "configured": {key: bool(values.get(key)) for key in SUPPORTED_KEYS},
        "configured_names": [key for key in SUPPORTED_KEYS if values.get(key)],
        "mode": (oct(stat.S_IMODE(provider_path().stat().st_mode)) if provider_path().exists() else None),
        "mutationPerformed": False,
    }


def _payload(envelope: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("keys", "providers", "metadata"):
        value = envelope.get(key)
        if isinstance(value, Mapping):
            return value
    return envelope


def _read_request() -> _envelope.Request | None:
    try:
        return _envelope.read(quiet_on_tty=True)
    except _envelope.EnvelopeError as error:
        cause = error.__cause__
        if isinstance(cause, json.JSONDecodeError) and not cause.doc.strip():
            return None
        if str(error) == "JSON object required":
            raise ValueError("crossing input must be a JSON object") from None
        if cause is not None:
            raise cause
        raise


def _save(values: Mapping[str, Any]) -> dict[str, Any]:
    unknown = sorted(str(key) for key in values if str(key) not in SUPPORTED_KEYS)
    if unknown:
        raise ValueError("unsupported provider key(s): " + ", ".join(unknown))
    merged = _read()
    for key in SUPPORTED_KEYS:
        if key in values:
            value = values[key]
            if not isinstance(value, str):
                raise ValueError(f"{key} must be a string")
            merged[key] = value
    target = provider_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Runtime-only provider keys. Do not commit real values."]
    lines.extend(f"{key}={shlex.quote(merged[key])}" for key in SUPPORTED_KEYS if merged.get(key))
    content = "\n".join(lines) + "\n"
    old = target.read_text(encoding="utf-8") if target.exists() else None
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent), text=True)
    temp = Path(temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, target)
        dirfd = os.open(target.parent, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        temp.unlink(missing_ok=True)
    return {"ok":True,"path":str(target),"changed":old != content,"preserved_existing":True,"configured_names":[key for key in SUPPORTED_KEYS if merged.get(key)],"mode":"0600","mutationPerformed":True}


def _parse_payload_args(words: list[str]) -> str:
    parser = argparse.ArgumentParser(prog="agathodaimon-games-provider-keys")
    parser.add_argument("operation", choices=("status", "save"), nargs="?", default="status")
    return parser.parse_args(words).operation


def _arguments_invalid() -> int:
    print(json.dumps({"ok": False, "firstMissingSignal": "provider-keys-arguments-invalid"}))
    return 2


def main(argv: Sequence[str] | None = None) -> int:
    try:
        request = _read_request()
        if request is not None and request.envelope:
            payload = request.value.get("payload")
            if not isinstance(payload, dict) or not payload:
                raise _PayloadRequired("provider request payload required")
            # The Caduceus door sends its operation in payload.args as well as
            # verb. Read the vector from the request, not the CLI's argv mirror.
            words = payload.get("args")
        else:
            payload = request.value if request is not None else {}
            words = None
        # An empty pipe still admits the original status spelling; it does not
        # supply fields or let a positional word select a write.
        empty_status = request is None and argv == ["status"]
        if argv and argv != words and not empty_status:
            return _arguments_invalid()
        operation = payload.get("verb")
        if isinstance(words, list) and words:
            if all(isinstance(word, str) for word in words):
                try:
                    operation = _parse_payload_args(words)
                except SystemExit as exc:
                    if exc.code != 2:
                        raise
                    return _arguments_invalid()
            elif operation is None:
                operation = words[0]
        result = _save(_payload(payload)) if operation == "save" else _status()
    except _PayloadRequired as exc:
        print(json.dumps({"ok": False, "error": str(exc),
                          "firstMissingSignal": "agathodaimon-provider-keys-payload-required",
                          "mutationPerformed": False}, sort_keys=True))
        return 2
    except (OSError, TypeError, ValueError) as exc:
        print(json.dumps({"ok":False,"error":str(exc),"mutationPerformed":False}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

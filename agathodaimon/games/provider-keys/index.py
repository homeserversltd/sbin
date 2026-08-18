"""Safely report and update runtime game-provider API keys."""
from __future__ import annotations

import argparse
import json
import os
import shlex
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

SUPPORTED_KEYS = ("STEAMGRIDDB_API_KEY", "THEGAMESDB_API_KEY", "SCREENSCRAPER_API_KEY")
DEFAULT_PATH = Path("/etc/arch-game-sync/providers.env")


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
        "schema": "arch_game_sync.provider_keys.status.v1",
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
    return {"schema":"arch_game_sync.provider_keys.save.v1","ok":True,"path":str(target),"changed":old != content,"preserved_existing":True,"configured_names":[key for key in SUPPORTED_KEYS if merged.get(key)],"mode":"0600","mutationPerformed":True}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-games-provider-keys")
    parser.add_argument("operation", choices=("status", "save"), nargs="?", default="status")
    args = parser.parse_args(argv)
    envelope: Mapping[str, Any] | None = None
    try:
        if argv == []:
            raw = sys.stdin.read()
            if raw.strip():
                loaded = json.loads(raw)
                if not isinstance(loaded, Mapping):
                    raise ValueError("crossing input must be a JSON object")
                envelope = loaded
                if envelope.get("verb") == "save":
                    args.operation = "save"
        if args.operation == "status":
            result = _status()
        else:
            if envelope is None:
                loaded = json.load(sys.stdin)
                if not isinstance(loaded, Mapping):
                    raise ValueError("save input must be a JSON object")
                envelope = loaded
            result = _save(_payload(envelope))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema":"arch_game_sync.provider_keys.v1","ok":False,"error":str(exc),"mutationPerformed":False}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

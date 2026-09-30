"""Owner-scoped Forgejo Git credential-helper actuator."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Sequence

DEFAULT_TOKEN_FILE = "/home/owner/.ssh/forgejo-token"


def token_file() -> Path:
    return Path(os.environ.get("CADUCEUS_FORGEJO_TOKEN_FILE", DEFAULT_TOKEN_FILE))


def get() -> int:
    try:
        values = {}
        for line in token_file().read_text(encoding="utf-8").splitlines():
            if line.startswith("FORGEJO_USERNAME="):
                values["username"] = line.split("=", 1)[1]
            elif line.startswith("FORGEJO_TOKEN="):
                values["password"] = line.split("=", 1)[1]
    except OSError:
        print("forgejo-token-missing-or-incomplete", file=sys.stderr)
        return 1
    if not values.get("username") or not values.get("password"):
        print("forgejo-token-missing-or-incomplete", file=sys.stderr)
        return 1
    print(f"username={values['username']}\npassword={values['password']}")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["get"]:
        return get()
    if args:
        return 1
    if sys.stdin.isatty():
        return get()
    try:
        raw = sys.stdin.read(65537)
        if len(raw) > 65536:
            return 1
        if not raw:
            return get()
        envelope = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return 1
    payload = envelope.get("payload") if isinstance(envelope, dict) and "schema" in envelope else envelope
    if not isinstance(payload, dict) or payload not in ({}, {"op": "get"}, {"operation": "get"}):
        return 1
    return get()


if __name__ == "__main__":
    raise SystemExit(main())

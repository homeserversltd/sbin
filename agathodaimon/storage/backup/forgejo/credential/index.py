"""Owner-scoped Forgejo Git credential-helper actuator."""
from __future__ import annotations

import json
import os
import sys
from io import SEEK_END, StringIO
from pathlib import Path
from typing import Sequence

DEFAULT_TOKEN_FILE = "/home/owner/.ssh/forgejo-token"
MISSING_CREDENTIAL = "forgejo-token-missing-or-incomplete"


def token_file() -> Path:
    return Path(os.environ.get("CADUCEUS_FORGEJO_TOKEN_FILE", DEFAULT_TOKEN_FILE))


def _credentials() -> dict[str, str] | None:
    values = {}
    try:
        for line in token_file().read_text(encoding="utf-8").splitlines():
            if line.startswith("FORGEJO_USERNAME="):
                values["username"] = line.split("=", 1)[1]
            elif line.startswith("FORGEJO_TOKEN="):
                values["password"] = line.split("=", 1)[1]
    except (OSError, UnicodeError):
        return None
    return values if values.get("username") and values.get("password") else None


def get() -> int:
    values = _credentials()
    if values is None:
        print(MISSING_CREDENTIAL, file=sys.stderr)
        return 1
    print(f"username={values['username']}\npassword={values['password']}")
    return 0


def _refuse(signal: str) -> int:
    print(json.dumps({"ok": False, "firstMissingSignal": signal}))
    return 1


def _legacy_hand_without_input() -> bool:
    # cli.py loads a legacy hand stop before it installs the generated
    # envelope. Preserve only the original no-input bit, not request bytes.
    if sys.argv[-2:] != ["forgejo", "credential"]:
        return False
    stream = sys.stdin
    if stream.isatty():
        return True
    if not isinstance(stream, StringIO):
        return False
    position = stream.tell()
    try:
        return stream.seek(0, SEEK_END) == 0
    finally:
        stream.seek(position)


_HAND_WITHOUT_INPUT = _legacy_hand_without_input()


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    # The front door can also pass payload.args to main; that is not Git argv.
    if args == ["get"] and sys.argv[-1:] == ["get"]:
        return get()
    if sys.stdin.isatty():
        return _refuse("forgejo-credential-arguments-invalid") if args else get()
    if not args and _HAND_WITHOUT_INPUT:
        return get()

    from agathodaimon import _envelope

    try:
        request = _envelope.read(max_input_bytes=65536)
    except _envelope.EnvelopeError as exc:
        cause = exc.__cause__
        if not args and isinstance(cause, json.JSONDecodeError) and cause.doc == "":
            return get()
        return _refuse(str(exc))
    except (ValueError, RecursionError):
        return _refuse("invalid JSON")

    # Request.payload is a projection; inspect the actual payload because
    # no member, even one the projection omits, belongs to this request.
    payload = request.value.get("payload") if request.envelope else request.value
    if payload is not None and payload != {}:
        return _refuse("forgejo-credential-payload-not-empty")
    if args:
        return _refuse("forgejo-credential-arguments-invalid")
    values = _credentials()
    if values is None:
        return _refuse(MISSING_CREDENTIAL)
    print(json.dumps({"ok": True, **values}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

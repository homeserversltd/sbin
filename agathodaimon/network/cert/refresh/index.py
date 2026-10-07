"""Root-only fixed certificate-refresh crossing."""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Sequence

_MAX_INPUT_BYTES = 64 * 1024
_BASH = "/bin/bash"
_REFRESH_SCRIPT = "/usr/local/sbin/sslKey.sh"
_EXECUTABLE_SELECTORS = {"bin", "program", "path", "script", "command"}


class Refusal(ValueError):
    def __init__(self, signal: str):
        super().__init__(signal)
        self.signal = signal


def _refuse(signal: str) -> int:
    print(json.dumps({"ok": False, "firstMissingSignal": signal}, separators=(",", ":")))
    return 1


def _request_object() -> dict[str, Any]:
    try:
        stream = getattr(sys.stdin, "buffer", None)
        raw = stream.read(_MAX_INPUT_BYTES + 1) if stream is not None else sys.stdin.read(_MAX_INPUT_BYTES + 1)
    except (OSError, UnicodeError) as error:
        raise Refusal("cert-refresh-request-invalid") from error
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeEncodeError as error:
            raise Refusal("cert-refresh-request-invalid") from error
    if len(raw) > _MAX_INPUT_BYTES:
        raise Refusal("cert-refresh-request-too-large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal("cert-refresh-request-invalid") from error
    if not isinstance(value, dict):
        raise Refusal("cert-refresh-request-invalid")
    payload = value.get("payload") if "payload" in value else value
    if not isinstance(payload, dict):
        raise Refusal("cert-refresh-request-invalid")
    return payload


def _null_stdin() -> None:
    descriptor = os.open(os.devnull, os.O_RDONLY)
    try:
        os.dup2(descriptor, 0)
    finally:
        if descriptor != 0:
            os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        payload = _request_object()
        if _EXECUTABLE_SELECTORS.intersection(payload):
            raise Refusal("cert-refresh-executable-selector-refused")
        if "argv" in payload and payload["argv"] != []:
            raise Refusal("cert-refresh-request-invalid")
        if os.geteuid() != 0:
            raise Refusal("cert-refresh-root-required")
        child_argv = [_BASH, _REFRESH_SCRIPT]
        _null_stdin()
        os.execv(_BASH, child_argv)
    except Refusal as error:
        return _refuse(error.signal)
    except OSError:
        return _refuse("cert-refresh-exec-refused")
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

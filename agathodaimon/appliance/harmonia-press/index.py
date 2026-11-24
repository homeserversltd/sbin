"""Bounded, root-only Harmonia invocation band."""
from __future__ import annotations

import json
import os
import re
from typing import Any, Sequence

from agathodaimon import _envelope
from agathodaimon._nidus.refusal import Refusal

_MAX_INPUT_BYTES = 64 * 1024
_HARMONIA = "/usr/local/bin/harmonia"
_SYSTEMD_RUN = "/usr/bin/systemd-run"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._-]+$")
_INVOCATION_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_PROFILE_INDEX = re.compile(r"^/etc/harmonia/profiles/[a-z0-9-]+/index\.json$")


def _refuse(signal: str) -> int:
    print(json.dumps({"ok": False, "firstMissingSignal": signal}, separators=(",", ":")))
    return 1


def _request_object() -> dict[str, Any]:
    try:
        value = _envelope.read(max_input_bytes=_MAX_INPUT_BYTES).value
    except (_envelope.EnvelopeError, UnicodeError, RecursionError) as error:
        if str(error) == "agathodaimon-envelope-input-too-large":
            raise Refusal("harmonia-press-request-too-large") from error
        raise Refusal("harmonia-press-request-invalid") from error
    # A payload wrapper also takes precedence on the legacy schema-less form.
    payload = value.get("payload", value)
    if not isinstance(payload, dict):
        raise Refusal("harmonia-press-request-invalid")
    return payload


def _allowed_argv(argv: list[str]) -> bool:
    if not argv or argv[0] != _HARMONIA:
        return False
    args = argv[1:]
    if args in (["update"], ["update", "--apply"], ["update", "--check"]):
        return True
    if args == ["interactable", "list", "--json"]:
        return True
    if len(args) == 3 and args[:2] == ["interactable", "run"]:
        return _IDENTIFIER.fullmatch(args[2]) is not None
    if len(args) == 3 and args[:2] in (["interactable", "silence"], ["interactable", "unsilence"]):
        return _IDENTIFIER.fullmatch(args[2]) is not None
    if len(args) in (4, 5) and args[0] == "update-module":
        if (
            _PROFILE_INDEX.fullmatch(args[1]) is None
            or args[2] != "--module"
            or _IDENTIFIER.fullmatch(args[3]) is None
        ):
            return False
        return len(args) == 4 or args[4] == "--apply"
    return False


def _property(invocation_id: str) -> str:
    return (
        "ExecStopPost=/bin/sh -c 'printf \"\\n__CADUCEUS_HARMONIA_EXIT_V1_"
        + invocation_id
        + "__|%s|%s\\n\" \"$$EXIT_CODE\" \"$$EXIT_STATUS\" >&2'"
    )


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
        if "argv" not in payload or "invocation_id" not in payload:
            raise Refusal("harmonia-press-request-invalid")
        command = payload["argv"]
        invocation_id = payload["invocation_id"]
        if not isinstance(command, list) or any(not isinstance(item, str) for item in command):
            raise Refusal("harmonia-press-argv-invalid")
        if not _allowed_argv(command):
            raise Refusal("harmonia-press-argv-invalid")
        if not isinstance(invocation_id, str) or _INVOCATION_ID.fullmatch(invocation_id) is None:
            raise Refusal("harmonia-press-invocation-id-invalid")
        if os.geteuid() != 0:
            raise Refusal("harmonia-press-root-required")

        child_argv = [
            _SYSTEMD_RUN,
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--property",
            _property(invocation_id),
            "--",
            *(item.replace("$", "$$") for item in command),
        ]
        _null_stdin()
        os.execv(_SYSTEMD_RUN, child_argv)
    except Refusal as error:
        return _refuse(error.signal)
    except OSError:
        return _refuse("harmonia-press-exec-refused")
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

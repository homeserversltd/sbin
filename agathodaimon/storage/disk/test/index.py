"""Root-only block-device test band."""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any, Sequence

_MAX_INPUT_BYTES = 64 * 1024
_TEST = "/usr/local/sbin/harddrive_test.sh"
_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]*$")
_TEST_TYPES = {"quick", "full", "ultimate"}


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
        raise Refusal("disk-test-request-invalid") from error
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeEncodeError as error:
            raise Refusal("disk-test-request-invalid") from error
    if len(raw) > _MAX_INPUT_BYTES:
        raise Refusal("disk-test-request-too-large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal("disk-test-request-invalid") from error
    if not isinstance(value, dict):
        raise Refusal("disk-test-request-invalid")
    payload = value.get("payload") if "payload" in value else value
    if not isinstance(payload, dict):
        raise Refusal("disk-test-request-invalid")
    return payload


def _device_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/"):
        raise Refusal("disk-test-device-invalid")
    segments = value[5:].split("/")
    if not segments or any(_SEGMENT.fullmatch(segment) is None for segment in segments):
        raise Refusal("disk-test-device-invalid")
    try:
        resolved = Path(value).resolve(strict=True)
        segments = resolved.relative_to(Path("/dev")).parts
        if not segments or any(_SEGMENT.fullmatch(segment) is None for segment in segments):
            raise Refusal("disk-test-device-invalid")
        if not stat.S_ISBLK(resolved.stat().st_mode):
            raise Refusal("disk-test-device-invalid")
    except Refusal:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise Refusal("disk-test-device-invalid") from error
    return value


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
        if "device" not in payload or "test_type" not in payload:
            raise Refusal("disk-test-request-invalid")
        device = payload["device"]
        test_type = payload["test_type"]
        if not isinstance(device, str):
            raise Refusal("disk-test-device-invalid")
        if not isinstance(test_type, str) or test_type not in _TEST_TYPES:
            raise Refusal("disk-test-test-type-invalid")
        if not device.startswith("/dev/") or any(
            _SEGMENT.fullmatch(segment) is None for segment in device[5:].split("/")
        ):
            raise Refusal("disk-test-device-invalid")
        if os.geteuid() != 0:
            raise Refusal("disk-test-root-required")
        resolved_device = _device_path(device)
        child_argv = [_TEST, resolved_device, test_type]
        _null_stdin()
        os.execv(_TEST, child_argv)
    except Refusal as error:
        return _refuse(error.signal)
    except OSError:
        return _refuse("disk-test-exec-refused")
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

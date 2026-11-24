import json
import os
import subprocess
import sys
from pathlib import Path

from agathodaimon._envelope import EnvelopeError, attach, read


class MalformedInput(ValueError):
    pass


class ExousiaUnprovisioned(RuntimeError):
    pass


_last_request = None
_last_request_pin = None
_REDACTED = "<redacted>"
_SAFE_LAUNCHER_MESSAGE = object()


def _safe_stderr_line(stderr, secrets):
    if not isinstance(stderr, str):
        return _REDACTED
    line = stderr
    for secret in sorted(secrets, key=lambda value: len(value) if isinstance(value, str) else 0, reverse=True):
        if isinstance(secret, str) and secret:
            line = line.replace(secret, _REDACTED)
    line = next((line for line in reversed(line.splitlines()) if line.strip()), "")
    return line[:512]


def _safe_exception_details(exc):
    exception_class = " ".join(type(exc).__name__.splitlines())
    message = str(exc)
    if getattr(exc, "_exousia_safe_message", None) is not _SAFE_LAUNCHER_MESSAGE:
        if isinstance(_last_request_pin, str) and _last_request_pin:
            message = message.replace(_last_request_pin, _REDACTED)
    # Keep the generic diagnostic on one line, followed by run()'s fixed line.
    message = " ".join(message.splitlines())
    return exception_class, message[:512]


def _launcher_error(message):
    error = RuntimeError(message)
    setattr(error, "_exousia_safe_message", _SAFE_LAUNCHER_MESSAGE)
    return error


def text(value, name):
    item = value.get(name)
    if not isinstance(item, str) or not item or len(item) > 512:
        raise MalformedInput(name + " missing or invalid")
    return item


def payload(fields):
    global _last_request, _last_request_pin
    try:
        _last_request = read(known_fields=tuple(fields), declared_flags=tuple(fields))
    except EnvelopeError as exc:
        raise MalformedInput(str(exc)) from exc
    pin = _last_request.payload.get("pin")
    _last_request_pin = pin if isinstance(pin, str) and pin else None
    return _last_request.payload


def invoke_library(verb, value):
    secrets = [
        value.get(name)
        for name in ("pin", "oldPin", "newPin")
        if isinstance(value.get(name), str) and value.get(name)
    ]
    shelf = Path(__file__).resolve().parents[2]
    cli_path = shelf / "agathodaimon" / "cli.py"
    python = os.environ.get("AGATHODAIMON_PYTHON") or "/var/lib/caduceus/venv/bin/python3"
    if not os.access(python, os.X_OK):
        python = "python3"
    env = os.environ.copy()
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(shelf), existing_pythonpath) if part
    )
    command = [python, str(cli_path), "lib", "bind_derived", verb]
    completed = subprocess.run(
        command,
        input=json.dumps(value, separators=(",", ":")),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    child_stderr = (
        _REDACTED
        if "oldPin" in value or "newPin" in value
        else _safe_stderr_line(completed.stderr, secrets)
    )
    response_error = (
        "invalid exousia staff response "
        f"exit={completed.returncode} stderr={child_stderr}"
    )
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise _launcher_error(response_error) from exc
    if not isinstance(result, dict):
        raise _launcher_error(response_error)
    # The real launchers use rc=1 for valid negative JSON outcomes.
    return result


def _unprovisioned(result):
    signal = result.get("firstMissingSignal")
    if result.get("ok") is False and isinstance(signal, str) and signal:
        raise ExousiaUnprovisioned(signal)


def bind():
    payload(set())
    result = invoke_library("bind", {})
    _unprovisioned(result)
    public_key, epoch = result.get("publicKey"), result.get("epoch")
    if result.get("ok") is not True or not isinstance(public_key, str) or not isinstance(epoch, str):
        raise RuntimeError("invalid caduceus bind response")
    return {"ok": True, "publicKey": public_key, "epoch": epoch}


def verify():
    global _last_request
    from agathodaimon.lib.sacred_credential.index import (
        CaduceusAccessRefused,
        verify_caduceus_pin,
    )

    _last_request = read(known_fields=("pin",))
    pin = _last_request.payload.get("pin")
    if not isinstance(pin, str) or not pin or len(pin) > 512:
        return {"ok": False, "verified": False, "firstMissingSignal": "exousia-pin-required"}
    try:
        verified = verify_caduceus_pin(pin)
    except CaduceusAccessRefused as exc:
        signal = str(exc)
        if signal == "exousia-pin-invalid":
            signal = "exousia-pin-required"
        elif signal in {"exousia-pin-absent", "exousia-pin-malformed",
                        "agathodaimon-config-unavailable", "agathodaimon-config-unreadable",
                        "agathodaimon-config-malformed", "agathodaimon-scratch-root-invalid"}:
            signal = "exousia-pin-not-yet-provisioned"
        elif signal != "agathodaimon-staff-root-required":
            raise
        return {"ok": False, "verified": False, "firstMissingSignal": signal}
    return {"ok": True, "verified": verified, "firstMissingSignal": "none"}


def execute(action):
    if action == "bind":
        return bind()
    if action == "verify":
        return verify()
    raise MalformedInput("unknown exousia verb")


def run(action, argv=None):
    global _last_request, _last_request_pin
    _last_request = None
    _last_request_pin = None
    if action == "verify":
        try:
            if argv:
                raise MalformedInput("one exousia verb is required")
            result = verify()
        except Exception as exc:  # noqa: BLE001
            result = {"ok": False, "verified": False,
                      "firstMissingSignal": "agathodaimon-stop-raised",
                      "exceptionType": type(exc).__name__}
        if _last_request is not None:
            try:
                result = attach(result, _last_request)
            except Exception as exc:  # noqa: BLE001
                result = {"ok": False, "verified": False,
                          "firstMissingSignal": "agathodaimon-stop-raised",
                          "exceptionType": type(exc).__name__}
        print(json.dumps(result, separators=(",", ":")))
        return 0
    try:
        if argv:
            raise MalformedInput("one exousia verb is required")
        result = execute(action)
        if _last_request is not None:
            result = attach(result, _last_request)
    except MalformedInput as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except ExousiaUnprovisioned as exc:
        result = {"ok": False, "firstMissingSignal": str(exc)}
        if _last_request is not None:
            result = attach(result, _last_request)
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except Exception as exc:  # noqa: BLE001
        exception_class, message = _safe_exception_details(exc)
        print(
            f"exousia internal failure: {exception_class}: {message}",
            file=sys.stderr,
        )
        print("exousia internal failure", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0

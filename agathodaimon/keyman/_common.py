"""Bounded bridge to the installed Rust Keyman crown verbs."""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import json
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Any, Mapping

SCHEMA = "caduceus.staff.v1"
BACKEND = "keyman-rust-crown"
PREFIX = ["/usr/bin/sudo", "-n", "/vault/keyman/keyman"]
KERNEL_KEYS = ("schema", "intent_id", "transition", "version", "timestamp")
MAX_INPUT = 1024 * 1024
MAX_OUTPUT = 1024 * 1024
REDACTED = "[REDACTED]"
_SECRET_NAMES = {
    "key", "keymaterial", "privatekey", "secretkey", "seed", "seedphrase",
    "token", "credential", "passphrase", "pin",
}


class RequestError(ValueError):
    def __init__(self, signal: str):
        super().__init__(signal)
        self.signal = signal


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


def _read_request() -> Request:
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
    except (OSError, UnicodeError):
        raise RequestError("keyman-request-unreadable") from None
    if len(raw.encode("utf-8", "replace")) > MAX_INPUT:
        raise RequestError("keyman-request-too-large")
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError, RecursionError):
        raise RequestError("keyman-request-json-invalid") from None
    if not isinstance(value, dict):
        raise RequestError("keyman-request-object-required")
    has_schema = "schema" in value
    if has_schema:
        if value.get("schema") != SCHEMA:
            raise RequestError("keyman-envelope-schema-foreign")
        missing = [key for key in KERNEL_KEYS if key not in value]
        if missing:
            raise RequestError("keyman-envelope-kernel-missing")
        source = value.get("payload")
        payload = dict(source) if isinstance(source, Mapping) else {}
        return Request(value, payload, True)
    nested = value.get("payload")
    payload = dict(nested) if isinstance(nested, Mapping) else dict(value)
    return Request(value, payload, False)


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


def _failure(operation: str, signal: str, *, planned: bool = False,
             attempt: Any = None, details: Any = None,
             changed: bool | None = False,
             attempted_operation: str | None = None) -> dict[str, Any]:
    receipt = {
        "schema": SCHEMA,
        "ok": False,
        "firstMissingSignal": signal,
        "mutationPerformed": changed,
        "backend": BACKEND,
        "operation": operation,
        "planned": planned,
        "changed": changed,
        "details": details,
        "observed": None,
        "could-change": [operation],
        "attempt": attempt,
        "final": ({"ok": False, "signal": signal} if attempted_operation is None
                  else {"ok": False, "state": "unknown", "signal": signal}),
    }
    if attempted_operation is not None:
        receipt["attempted-operation"] = attempted_operation
    return receipt


def _nonempty_string(payload: Mapping[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise RequestError("keyman-field-invalid")
    return value


def _planned(payload: Mapping[str, Any]) -> bool:
    value = payload.get("planned")
    if value is None:
        return False
    if not isinstance(value, bool):
        raise RequestError("keyman-field-invalid")
    return value


def _plan(verb: str, payload: Mapping[str, Any]) -> tuple[list[str], dict[str, Any], bool, list[str]]:
    planned = _planned(payload)
    if verb == "key-status":
        return PREFIX + [verb], {"planned": planned}, planned, []
    if verb == "create-key":
        target = _nonempty_string(payload, "target")
        strategy = _nonempty_string(payload, "strategy")
        password = _nonempty_string(payload, "password")
        if target not in {"vault", "external", "both"}:
            raise RequestError("keyman-field-invalid")
        if strategy not in {"safe_rotation", "replace_primary", "flexible_addition"}:
            raise RequestError("keyman-field-invalid")
        return (
            PREFIX + [verb, "--target", target, "--strategy", strategy],
            {"password": password, "planned": planned}, planned, [password],
        )
    if verb == "update-key":
        device = _nonempty_string(payload, "device")
        token_device = re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}", device) is not None
        path_parts = device.split("/")
        path_device = (
            device.startswith("/dev/")
            and len(path_parts) >= 3
            and path_parts[0] == ""
            and path_parts[1] == "dev"
            and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,254}", part)
                    for part in path_parts[2:])
        )
        if not (token_device or path_device):
            raise RequestError("keyman-field-invalid")
        strategy = _nonempty_string(payload, "strategy")
        current_password = _nonempty_string(payload, "current_password")
        if strategy not in {"safe_rotation", "replace_primary", "flexible_addition"}:
            raise RequestError("keyman-field-invalid")
        return (
            PREFIX + [verb, "--device", device, "--strategy", strategy],
            {"current_password": current_password, "planned": planned}, planned,
            [current_password],
        )
    if verb == "admin-password":
        old_password = _nonempty_string(payload, "old_password")
        new_password = _nonempty_string(payload, "new_password")
        return (
            PREFIX + [verb],
            {"old_password": old_password, "new_password": new_password, "planned": planned},
            planned, [old_password, new_password],
        )
    raise RequestError("keyman-verb-unknown")


def _stop_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.communicate(timeout=1)
        except (OSError, subprocess.SubprocessError):
            pass
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def _run(argv: list[str], *, stdin: str | None, timeout: float
         ) -> tuple[subprocess.CompletedProcess[str] | None, bool]:
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", close_fds=True,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None, False
    try:
        stdout, stderr = process.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        _stop_process_group(process)
        return None, True
    except (OSError, subprocess.SubprocessError):
        _stop_process_group(process)
        return None, True
    return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr), True


def _supports_verb() -> tuple[bool, str | None]:
    result, _dispatched = _run(PREFIX + ["--help"], stdin=None, timeout=10)
    if result is None:
        return False, "keyman-crown-unavailable"
    if result.returncode != 0:
        return False, "keyman-crown-help-failed"
    usage = result.stdout + "\n" + result.stderr
    return True, usage


def _usage_has_verb(usage: str, verb: str) -> bool:
    for line in usage.splitlines():
        if re.match(rf"^\s*(?:[-*•]\s*)?{re.escape(verb)}(?:\s|$)", line):
            return True
        if re.match(rf"^\s*keyman\s+{re.escape(verb)}(?:\s|$)", line):
            return True
        usage_line = re.match(r"^\s*Usage:\s*(.*)$", line, re.IGNORECASE)
        if not usage_line:
            continue
        command_position = re.compile(
            r"(?:^|\|)\s*(?:keyman|[^\s|]*/keyman)\s+(<[^<>]*>|[A-Za-z][A-Za-z0-9-]*)"
        )
        for match in command_position.finditer(usage_line.group(1)):
            command = match.group(1)
            candidates = command[1:-1].split("|") if command.startswith("<") else [command]
            if any(candidate.strip() == verb for candidate in candidates):
                return True
    return False


def _reported_changed(backend: Any) -> bool | None:
    changed = backend.get("changed") if isinstance(backend, dict) else None
    return changed if isinstance(changed, bool) else None


def _dispatched_failure(operation: str, signal_name: str, *, planned: bool,
                        attempt: Any, changed: bool | None = None) -> dict[str, Any]:
    return _failure(operation, signal_name, planned=planned, attempt=attempt,
                    changed=changed, attempted_operation=operation)


def _signal(value: Any, fallback: str) -> str:
    if isinstance(value, str) and re.fullmatch(r"[a-z0-9][a-z0-9_.:-]{0,127}", value):
        return value
    return fallback


def main_for(verb: str, argv: list[str] | None = None) -> int:
    request: Request | None = None
    secrets: set[str] = set()
    planned = False
    try:
        request = _read_request()
        _collect_secret_values(request.value, secrets)
        _collect_secret_values(request.payload, secrets)
        if argv:
            raise RequestError("keyman-argv-not-supported")
        command, stdin_payload, planned, explicit_secrets = _plan(verb, request.payload)
        secrets.update(explicit_secrets)
    except RequestError as error:
        receipt = _failure(verb, error.signal, planned=planned)
        return _emit(receipt, request, secrets)
    except Exception:
        return _emit(_failure(verb, "keyman-staff-request-failed", planned=planned), request, secrets)

    available, usage = _supports_verb()
    if not available:
        signal_name = usage if isinstance(usage, str) else "keyman-crown-unavailable"
        return _emit(_failure(verb, signal_name, planned=planned,
                              attempt={"help": "failed"}), request, secrets)
    if not _usage_has_verb(usage or "", verb):
        return _emit(_failure(verb, "keyman-crown-verb-unavailable", planned=planned,
                              attempt={"help": "available", "requestedVerbPresent": False}), request, secrets)

    result, dispatched = _run(command, stdin=json.dumps(stdin_payload, separators=(",", ":")), timeout=30)
    if result is None:
        if dispatched:
            receipt = _dispatched_failure(verb, "keyman-crown-timeout-or-unavailable",
                                          planned=planned, attempt={"command": "timed-out"})
        else:
            receipt = _failure(verb, "keyman-crown-timeout-or-unavailable", planned=planned,
                              attempt={"command": "not-started"})
        return _emit(receipt, request, secrets)
    if len(result.stdout.encode("utf-8", "replace")) > MAX_OUTPUT:
        return _emit(_dispatched_failure(
            verb, "keyman-crown-output-too-large", planned=planned,
            attempt={"returnCode": result.returncode},
        ), request, secrets)
    try:
        backend = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError, RecursionError):
        backend = None
    if not isinstance(backend, dict):
        return _emit(_dispatched_failure(
            verb, "keyman-crown-receipt-invalid", planned=planned,
            attempt={"returnCode": result.returncode},
        ), request, secrets)

    _collect_secret_values(backend, secrets)
    if (
        not isinstance(backend.get("ok"), bool)
        or not isinstance(backend.get("changed"), bool)
        or backend.get("operation") != verb
        or backend.get("planned") is not planned
        or not isinstance(backend.get("firstMissingSignal"), str)
    ):
        return _emit(_dispatched_failure(
            verb, "keyman-crown-receipt-invalid", planned=planned,
            attempt={"returnCode": result.returncode}, changed=_reported_changed(backend),
        ), request, secrets)
    changed = backend["changed"]
    signal_name = _signal(backend.get("firstMissingSignal"), "keyman-crown-command-failed")
    ok = result.returncode == 0 and backend["ok"] is True and signal_name == "none"
    if not backend["ok"] and signal_name == "none":
        signal_name = "keyman-crown-command-refused"
    if result.returncode != 0 and signal_name == "none":
        signal_name = "keyman-crown-command-failed"
    if planned and changed:
        ok = False
        signal_name = "keyman-planned-mutation-reported"
    if ok:
        signal_name = "none"
    receipt = {
        "schema": SCHEMA,
        "ok": ok,
        "firstMissingSignal": signal_name,
        "mutationPerformed": changed,
        "backend": BACKEND,
        "operation": verb,
        "planned": planned,
        "changed": changed,
        "details": backend.get("details"),
        "observed": backend.get("observed"),
        "could-change": backend.get("could-change", [verb]),
        "attempt": backend.get("attempt", {"returnCode": result.returncode}),
        "final": backend.get("final", {"ok": ok, "changed": changed}),
        "attempted-operation": verb,
    }
    if not ok and receipt["firstMissingSignal"] == "none":
        receipt["firstMissingSignal"] = "keyman-crown-command-failed"
    return _emit(receipt, request, secrets)

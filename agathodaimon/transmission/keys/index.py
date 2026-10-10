from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import stat
from collections.abc import Mapping
from typing import Any

from agathodaimon.transmission import runtime as rt

SCHEMA = "caduceus.transmission.keys.v1"
_KEY_DIRECTORY = "/vault/.keys"
_ACTIONS = frozenset(("status", "replace", "rotate"))
_ACTION_FIELDS = ("action", "op", "operation", "verb")
_KNOWN_FIELDS = (
    "action", "op", "operation", "verb", "service", "username", "password", "args",
)
_ROTATION_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def _action_value(value: Any) -> str | None:
    return value if isinstance(value, str) and value in _ACTIONS else None


def select_action(request: Any = None, argv: Any = None, *, envelope: Any = None) -> str | None:
    # The front-door PIN gate and dispatch call this same selector.
    if argv is not None:
        try:
            arguments = list(argv)
        except TypeError:
            return None
        if arguments:
            if len(arguments) != 1:
                return None
            return _action_value(arguments[0])

    raw = envelope
    if raw is None:
        raw = request if isinstance(request, Mapping) else getattr(request, "value", None)
    if not isinstance(raw, Mapping):
        return "status"
    payload = raw.get("payload")
    if isinstance(payload, Mapping) and "args" in payload:
        arguments = payload.get("args")
        if not isinstance(arguments, list):
            return None
        if arguments:
            if len(arguments) != 1:
                return None
            return _action_value(arguments[0])

    containers = []
    if isinstance(payload, Mapping):
        containers.append(payload)
    containers.append(raw)
    metadata = [container.get("metadata") for container in containers]
    containers.extend(item for item in metadata if isinstance(item, Mapping))
    for container in containers:
        for field in _ACTION_FIELDS:
            if field in container:
                return _action_value(container[field])
    if "transition" in raw:
        transition = raw.get("transition")
        if not isinstance(transition, str) or not transition:
            return None
        parts = [part for part in re.split(r"[./:]", transition) if part]
        return _action_value(parts[-1]) if parts else None
    return "status"


def _receipt(action: str | None, service: str | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": False,
        "action": action,
        "service": service,
        "services": None,
        "keys": None,
        "keyChanged": None,
        "lengths": None,
        "restart": {
            "unit": rt.NATIVE_UNIT,
            "stateBefore": None,
            "attempted": False,
            "outcome": "not-requested",
        },
        "onness": None,
        "firstMissingSignal": "transmission-keys-incomplete",
        "steps": [],
    }


def _step(receipt: dict[str, Any], name: str, observed: Any, could_change: Any,
          attempt: Any, final_state: Any) -> dict[str, Any]:
    value = {
        "step": name,
        "observed": observed,
        "could-change": could_change,
        "attempt": attempt,
        "finalState": final_state,
    }
    receipt["steps"].append(value)
    return value


def _fail(receipt: dict[str, Any], signal: str) -> dict[str, Any]:
    receipt["ok"] = False
    receipt["firstMissingSignal"] = signal
    return receipt


def _signal(failure: BaseException, fallback: str) -> str:
    candidate = getattr(failure, "signal_name", None)
    if (isinstance(candidate, str) and candidate.startswith("transmission-")
            and candidate.replace("-", "").isalnum()):
        return candidate
    return fallback


def _raw_request(request: Any) -> Mapping[str, Any] | None:
    value = getattr(request, "value", request)
    return value if isinstance(value, Mapping) else None


def _field(request: Any, name: str) -> tuple[bool, Any]:
    raw = _raw_request(request)
    if raw is None:
        return False, None
    payload = raw.get("payload")
    for container in (payload, raw):
        if isinstance(container, Mapping) and name in container:
            return True, container[name]
    return False, None


def _sanitize_request(request: Any) -> Any:
    if request is None:
        return None
    raw = _raw_request(request)
    if raw is None:
        return None
    clean = dict(raw)
    for field in ("username", "password", "service"):
        clean.pop(field, None)
    payload = clean.get("payload")
    if isinstance(payload, Mapping):
        clean_payload = dict(payload)
        for field in ("username", "password", "service"):
            clean_payload.pop(field, None)
        clean["payload"] = clean_payload
    selected = getattr(request, "payload", {})
    clean_selected = dict(selected) if isinstance(selected, Mapping) else {}
    for field in ("username", "password", "service"):
        clean_selected.pop(field, None)
    raw_envelope = json.dumps(clean, separators=(",", ":"), ensure_ascii=True)
    if dataclasses.is_dataclass(request):
        return dataclasses.replace(
            request, value=clean, payload=clean_selected, raw_envelope=raw_envelope,
        )
    return None


def _service_names() -> tuple[list[str], list[str]]:
    providers, _default = rt._provider_metadata()
    names = list(providers) + ["transmission"]
    return list(providers), names


def _key_directory_fd() -> int:
    try:
        return rt._open_absolute_dir(_KEY_DIRECTORY)
    except FileNotFoundError:
        raise
    except PermissionError:
        if os.geteuid() != 0 and rt._scratch_root() is None:
            raise rt.TransmissionError("transmission-root-required", "key-presence") from None
        raise rt.TransmissionError("transmission-key-presence-unobservable", "key-presence") from None
    except OSError:
        raise rt.TransmissionError("transmission-key-path-unsafe", "key-presence") from None


def _observe_key_map(receipt: dict[str, Any], names: list[str]) -> dict[str, str]:
    if os.geteuid() != 0 and rt._scratch_root() is None:
        raise rt.TransmissionError("transmission-root-required", "key-presence")
    try:
        directory_fd = _key_directory_fd()
    except FileNotFoundError:
        result = {name: "absent" for name in names}
        receipt["keys"] = result
        return result
    result: dict[str, str] = {}
    try:
        for name in names:
            filename = name + ".key"
            try:
                info = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                result[name] = "absent"
                receipt["keys"] = result
                continue
            except PermissionError:
                receipt["keys"] = result or None
                if os.geteuid() != 0 and rt._scratch_root() is None:
                    raise rt.TransmissionError("transmission-root-required", "key-presence") from None
                raise rt.TransmissionError("transmission-key-presence-unobservable", "key-presence") from None
            except OSError:
                receipt["keys"] = result or None
                raise rt.TransmissionError("transmission-key-presence-unobservable", "key-presence") from None
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                receipt["keys"] = result or None
                raise rt.TransmissionError("transmission-key-file-unsafe", "key-presence")
            result[name] = "present"
            receipt["keys"] = result
        return result
    finally:
        os.close(directory_fd)

def _status() -> dict[str, Any]:
    receipt = _receipt("status")
    try:
        _providers, names = _service_names()
        receipt["services"] = names
        step = _step(
            receipt, "key-presence-readback", {"services": names}, False,
            "no-follow-stat-key-files", {"keys": None, "complete": False},
        )
        try:
            keys = _observe_key_map(receipt, names)
        except rt.TransmissionError as failure:
            step["finalState"] = {"keys": receipt["keys"], "complete": False}
            return _fail(receipt, _signal(failure, "transmission-key-presence-unobservable"))
        step["observed"] = {"keys": keys}
        step["finalState"] = {"keys": keys, "complete": True}
        receipt["ok"] = True
        receipt["firstMissingSignal"] = "none"
        return receipt
    except rt.TransmissionError as failure:
        return _fail(receipt, _signal(failure, "transmission-provider-metadata-unreadable"))
    except Exception:
        return _fail(receipt, "transmission-keys-status-failed")


def _credential_lengths(service: str) -> tuple[int, int]:
    username = None
    password = None
    try:
        with rt.exported_credentials(service) as credentials:
            username, password = credentials
            return len(username.encode("utf-8")), len(password.encode("utf-8"))
    finally:
        username = None
        password = None


def _stat_one_key(service: str) -> str:
    if os.geteuid() != 0 and rt._scratch_root() is None:
        raise rt.TransmissionError("transmission-root-required", "key-presence")
    try:
        directory_fd = _key_directory_fd()
    except FileNotFoundError:
        return "absent"
    try:
        try:
            info = os.stat(service + ".key", dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return "absent"
        except PermissionError:
            if os.geteuid() != 0 and rt._scratch_root() is None:
                raise rt.TransmissionError("transmission-root-required", "key-presence") from None
            raise rt.TransmissionError("transmission-key-presence-unobservable", "key-presence") from None
        except OSError:
            raise rt.TransmissionError("transmission-key-presence-unobservable", "key-presence") from None
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise rt.TransmissionError("transmission-key-file-unsafe", "key-presence")
        return "present"
    finally:
        os.close(directory_fd)


def _create_and_readback(receipt: dict[str, Any], service: str,
                         username_buffer: bytearray, password_buffer: bytearray) -> bool:
    expected_username_length = len(username_buffer)
    expected_password_length = len(password_buffer)
    payload = bytearray()
    process_result = None
    command_step = _step(
        receipt, "key-create", {"service": service}, ["key:" + service],
        "native-keyman-crypto-create-stdin", {"outcome": "not-attempted"},
    )
    command_signal = None
    command_succeeded = False
    try:
        payload.extend(b"service=")
        payload.extend(service.encode("ascii"))
        payload.extend(b"\nusername=")
        payload.extend(username_buffer)
        payload.extend(b"\npassword=")
        payload.extend(password_buffer)
        payload.extend(b"\n")
        command_step["finalState"] = {"outcome": "attempted"}
        try:
            process_result = rt.run(
                [rt.KEYMAN, "crypto", "create", "/dev/stdin"],
                input_data=payload, step="key-create",
            )
            return_code = process_result.returncode
            command_succeeded = return_code == 0
            command_step["finalState"] = {
                "outcome": "completed", "returnCode": return_code,
                "commandSucceeded": command_succeeded,
            }
            if not command_succeeded:
                command_signal = "transmission-key-create-failed"
        except rt.TransmissionError as failure:
            command_signal = _signal(failure, "transmission-key-create-failed")
            command_step["finalState"] = {"outcome": "unobserved"}
        except Exception:
            command_signal = "transmission-key-create-failed"
            command_step["finalState"] = {"outcome": "unobserved"}
        finally:
            if process_result is not None:
                process_result.stdout = b""
                process_result.stderr = b""
                process_result = None

        presence_step = _step(
            receipt, "key-presence-readback", {"service": service}, False,
            "no-follow-stat-key-file", {"presence": None},
        )
        try:
            presence = _stat_one_key(service)
            receipt["keys"] = {service: presence}
            presence_step["observed"] = {"presence": presence}
            presence_step["finalState"] = {"presence": presence}
        except rt.TransmissionError as failure:
            receipt["keys"] = None
            presence_step["finalState"] = {"presence": None}
            if command_signal is None:
                command_signal = _signal(failure, "transmission-key-presence-unobservable")
            presence = None
        except Exception:
            receipt["keys"] = None
            presence_step["finalState"] = {"presence": None}
            if command_signal is None:
                command_signal = "transmission-key-presence-unobservable"
            presence = None

        lengths_match = False
        if presence == "present":
            length_step = _step(
                receipt, "credential-length-readback", {"service": service}, False,
                "export-credential-lengths-only", {"credentialLengths": None, "match": False},
            )
            try:
                username_length, password_length = _credential_lengths(service)
                lengths = {"username": username_length, "password": password_length}
                receipt["lengths"] = lengths
                lengths_match = (
                    username_length == expected_username_length
                    and password_length == expected_password_length
                )
                length_step["observed"] = {"credentialLengths": lengths}
                length_step["finalState"] = {
                    "credentialLengths": lengths, "match": lengths_match,
                }
                if not lengths_match and command_signal is None:
                    command_signal = "transmission-key-readback-length-mismatch"
            except rt.TransmissionError as failure:
                length_step["finalState"] = {"credentialLengths": None, "match": False}
                if command_signal is None:
                    command_signal = _signal(failure, "transmission-key-readback-failed")
            except Exception:
                length_step["finalState"] = {"credentialLengths": None, "match": False}
                if command_signal is None:
                    command_signal = "transmission-key-readback-failed"

        if command_succeeded and presence == "present" and lengths_match:
            receipt["keyChanged"] = True
        if command_signal is not None:
            _fail(receipt, command_signal)
            return False
        if presence != "present":
            _fail(receipt, "transmission-key-readback-absent")
            return False
        if not lengths_match:
            _fail(receipt, "transmission-key-readback-length-mismatch")
            return False
        return True
    finally:
        if process_result is not None:
            process_result.stdout = b""
            process_result.stderr = b""
            process_result = None
        for buffer in (username_buffer, password_buffer, payload):
            buffer[:] = b"\x00" * len(buffer)


def _replace(service_value: Any, username_value: Any, password_value: Any,
             service_present: bool, username_present: bool,
             password_present: bool) -> dict[str, Any]:
    receipt = _receipt("replace")
    username_buffer = bytearray()
    password_buffer = bytearray()
    username_value_ref = username_value
    password_value_ref = password_value
    try:
        providers, names = _service_names()
        receipt["services"] = names
        if (not service_present or not isinstance(service_value, str)
                or service_value == "transmission" or service_value not in providers):
            return _fail(receipt, "transmission-key-service-invalid")
        service = service_value
        receipt["service"] = service
        validation = _step(
            receipt, "credential-input-validation",
            {"usernamePresent": username_present, "passwordPresent": password_present},
            False, "validate-stdin-credentials", {"valid": False},
        )
        if (not username_present or not password_present
                or not isinstance(username_value_ref, str)
                or not isinstance(password_value_ref, str)
                or not username_value_ref or not password_value_ref
                or any(character in username_value_ref for character in "\r\n\x00")
                or any(character in password_value_ref for character in "\r\n\x00")):
            return _fail(receipt, "transmission-key-credentials-invalid")
        try:
            username_buffer.extend(username_value_ref.encode("utf-8"))
            password_buffer.extend(password_value_ref.encode("utf-8"))
        except UnicodeError:
            return _fail(receipt, "transmission-key-credentials-invalid")
        validation["observed"] = {
            "usernameLength": len(username_buffer), "passwordLength": len(password_buffer),
        }
        validation["finalState"] = {"valid": True}
        if not username_buffer or not password_buffer:
            return _fail(receipt, "transmission-key-credentials-invalid")
        if not _create_and_readback(receipt, service, username_buffer, password_buffer):
            return receipt
        receipt["ok"] = True
        receipt["firstMissingSignal"] = "none"
        return receipt
    except rt.TransmissionError as failure:
        return _fail(receipt, _signal(failure, "transmission-keys-replace-failed"))
    except Exception:
        return _fail(receipt, "transmission-keys-replace-failed")
    finally:
        for buffer in (username_buffer, password_buffer):
            buffer[:] = b"\x00" * len(buffer)
        username_value_ref = None
        password_value_ref = None
        service_value = None
        username_value = None
        password_value = None


def _rotate(service_value: Any, service_present: bool) -> dict[str, Any]:
    receipt = _receipt("rotate")
    username_buffer = bytearray()
    password_buffer = bytearray()
    username_value = None
    credentials = None
    try:
        _providers, names = _service_names()
        receipt["services"] = names
        if not service_present or not isinstance(service_value, str) or service_value != "transmission":
            return _fail(receipt, "transmission-key-service-invalid")
        service = "transmission"
        receipt["service"] = service
        export_step = _step(
            receipt, "existing-credential-readback", {"service": service}, False,
            "export-existing-username", {"usernameObserved": False},
        )
        try:
            with rt.exported_credentials(service) as credentials:
                username_value = credentials[0]
                if (not isinstance(username_value, str) or not username_value
                        or any(character in username_value for character in "\r\n\x00")):
                    return _fail(receipt, "transmission-key-export-invalid")
                username_buffer.extend(username_value.encode("utf-8"))
                export_step["observed"] = {"usernameLength": len(username_buffer)}
                export_step["finalState"] = {"usernameObserved": True}
        except rt.TransmissionError as failure:
            return _fail(receipt, _signal(failure, "transmission-key-export-failed"))
        except Exception:
            return _fail(receipt, "transmission-key-export-failed")
        credentials = None
        username_value = None
        if not username_buffer:
            return _fail(receipt, "transmission-key-export-invalid")

        unit_step = _step(
            receipt, "native-unit-state-readback", {"unit": rt.NATIVE_UNIT}, False,
            "read-native-unit-state", {"state": None},
        )
        try:
            unit_state = rt.unit_state(rt.NATIVE_UNIT, step="rotate-unit-state-readback")
        except rt.TransmissionError as failure:
            unit_step["finalState"] = {"state": None}
            return _fail(receipt, _signal(failure, "transmission-unit-state-unreadable"))
        except Exception:
            unit_step["finalState"] = {"state": None}
            return _fail(receipt, "transmission-unit-state-unreadable")
        receipt["restart"]["stateBefore"] = unit_state
        unit_step["observed"] = {"state": unit_state}
        unit_step["finalState"] = {"state": unit_state}

        password_buffer.extend(secrets.choice(_ROTATION_ALPHABET) for _ in range(32))
        if not _create_and_readback(receipt, service, username_buffer, password_buffer):
            return receipt

        if unit_state not in {"active", "reloading"}:
            receipt["restart"]["outcome"] = "not-active"
            receipt["ok"] = True
            receipt["firstMissingSignal"] = "none"
            return receipt

        receipt["restart"]["attempted"] = True
        restart_step = _step(
            receipt, "native-unit-restart", {"stateBefore": unit_state},
            [rt.NATIVE_UNIT + " process"], "systemctl-restart-native-unit",
            {"outcome": "attempted"},
        )
        process_result = None
        try:
            process_result = rt.run(
                [rt.SYSTEMCTL, "restart", rt.NATIVE_UNIT],
                timeout=180, step="rotate-native-unit-restart",
            )
            return_code = process_result.returncode
            process_result.stdout = b""
            process_result.stderr = b""
            process_result = None
            if return_code != 0:
                receipt["restart"]["outcome"] = "failed"
                restart_step["finalState"] = {
                    "outcome": "failed", "returnCode": return_code,
                }
                return _fail(receipt, "transmission-native-unit-restart-failed")
            receipt["restart"]["outcome"] = "succeeded"
            restart_step["finalState"] = {"outcome": "succeeded", "returnCode": return_code}
        except rt.TransmissionError as failure:
            if process_result is not None:
                process_result.stdout = b""
                process_result.stderr = b""
            receipt["restart"]["outcome"] = "unobserved"
            restart_step["finalState"] = {"outcome": "unobserved"}
            return _fail(receipt, _signal(failure, "transmission-native-unit-restart-failed"))
        except Exception:
            if process_result is not None:
                process_result.stdout = b""
                process_result.stderr = b""
            receipt["restart"]["outcome"] = "unobserved"
            restart_step["finalState"] = {"outcome": "unobserved"}
            return _fail(receipt, "transmission-native-unit-restart-failed")
        finally:
            if process_result is not None:
                process_result.stdout = b""
                process_result.stderr = b""
                process_result = None

        onness_step = _step(
            receipt, "native-unit-onness-readback", {"unit": rt.NATIVE_UNIT}, False,
            "provider-bound-status-readback", {"on": None, "firstMissingSignal": None},
        )
        try:
            provider = rt.provider_bound_to_unit(rt.NATIVE_UNIT)
            provider_names, _default = rt._provider_metadata()
            status = rt.status_read(provider, provider_names)
            onness = {
                "provider": provider,
                "ok": status.get("ok") is True,
                "on": status.get("on") is True,
                "firstMissingSignal": status.get("firstMissingSignal"),
                "conditions": status.get("conditions"),
            }
            receipt["onness"] = onness
            onness_step["observed"] = {
                "on": onness["on"], "firstMissingSignal": onness["firstMissingSignal"],
            }
            onness_step["finalState"] = {
                "on": onness["on"], "firstMissingSignal": onness["firstMissingSignal"],
            }
            if onness["ok"] and onness["on"]:
                receipt["ok"] = True
                receipt["firstMissingSignal"] = "none"
                return receipt
            signal = onness["firstMissingSignal"]
            if not isinstance(signal, str) or not signal or signal == "none":
                signal = "transmission-onness-not-established"
            return _fail(receipt, signal)
        except rt.TransmissionError as failure:
            onness_step["finalState"] = {"on": None, "firstMissingSignal": _signal(failure, "transmission-onness-readback-failed")}
            return _fail(receipt, _signal(failure, "transmission-onness-readback-failed"))
        except Exception:
            onness_step["finalState"] = {"on": None, "firstMissingSignal": "transmission-onness-readback-failed"}
            return _fail(receipt, "transmission-onness-readback-failed")
    except rt.TransmissionError as failure:
        return _fail(receipt, _signal(failure, "transmission-keys-rotate-failed"))
    except Exception:
        return _fail(receipt, "transmission-keys-rotate-failed")
    finally:
        for buffer in (username_buffer, password_buffer):
            buffer[:] = b"\x00" * len(buffer)
        credentials = None
        username_value = None
        service_value = None


def main(argv: Any = None) -> int:
    arguments = [] if argv is None else argv
    request = None
    request_sanitized = False
    action = None
    service_present = username_present = password_present = False
    service_value = username_value = password_value = None
    successful_read = False
    try:
        request = rt.read_request(known_fields=_KNOWN_FIELDS, declared_flags=())
        action = select_action(request=request, argv=arguments)
        service_present, service_value = _field(request, "service")
        username_present, username_value = _field(request, "username")
        password_present, password_value = _field(request, "password")
        request = _sanitize_request(request)
        request_sanitized = True
        if action is None:
            receipt = _fail(_receipt(None), "transmission-keys-action-invalid")
        elif action == "status":
            receipt = _status()
            successful_read = receipt.get("ok") is True
        elif action == "replace":
            receipt = _replace(
                service_value, username_value, password_value,
                service_present, username_present, password_present,
            )
        else:
            receipt = _rotate(service_value, service_present)
    except rt.TransmissionError as failure:
        if request is not None and not request_sanitized:
            try:
                request = _sanitize_request(request)
                request_sanitized = True
            except Exception:
                request = None
        receipt = _fail(_receipt(action), _signal(failure, "transmission-keys-request-failed"))
    except Exception:
        if request is not None and not request_sanitized:
            try:
                request = _sanitize_request(request)
                request_sanitized = True
            except Exception:
                request = None
        receipt = _fail(_receipt(action), "transmission-keys-request-failed")
    finally:
        service_value = None
        username_value = None
        password_value = None
    return rt.print_receipt(rt.finish(receipt, request, successful_read=successful_read))


if __name__ == "__main__":
    raise SystemExit(main())

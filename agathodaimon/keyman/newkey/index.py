"""Create a Keyman service credential through the Rust crown."""
from __future__ import annotations

import getpass
import json
import os
import signal
import subprocess
import sys
import threading
import warnings
from typing import Any

from agathodaimon.keyman._common import (
    BACKEND,
    MAX_OUTPUT,
    PREFIX,
    SCHEMA,
    _collect_secret_values,
    _emit,
    _scrub,
)
from agathodaimon.lib.keyman_export.index import KeymanExportError, exchange_session

_MAX_SERVICE_NAME = 238
_MAX_FIELD_VALUE = 511
_READ_CHUNK = 4096
_TIMEOUT_SECONDS = 30


class RequestError(ValueError):
    def __init__(self, signal_name: str):
        super().__init__(signal_name)
        self.signal = signal_name


def _receipt(
    signal_name: str,
    *,
    mutation: bool | None,
    secrets: set[str],
    dispatched: bool = False,
    service: str | None = None,
    username: str | None = None,
    replace: bool | None = None,
    backend_receipt: Any = None,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "schema": SCHEMA,
        "ok": signal_name == "none",
        "firstMissingSignal": signal_name,
        "mutationPerformed": mutation,
        "backend": BACKEND,
        "operation": "newkey",
        "service": _scrub(service, secrets),
        "username": _scrub(username, secrets),
        "replace": replace,
        "observed": None,
        "could-change": ["newkey"],
        "attempt": {"dispatched": dispatched},
        "final": (
            {"ok": False, "state": "unknown", "signal": signal_name}
            if dispatched and signal_name != "none"
            else {"ok": signal_name == "none", "signal": signal_name}
        ),
    }
    if dispatched:
        receipt["attempted-operation"] = "newkey"
    if backend_receipt is not None:
        receipt["backendReceipt"] = _scrub(backend_receipt, secrets)
    return receipt


def _preflight_password_argv(args: list[str], secrets: set[str]) -> None:
    for index, argument in enumerate(args):
        if not isinstance(argument, str):
            continue
        if argument.startswith("--pword="):
            value = argument.partition("=")[2]
            if value:
                secrets.add(value)
            raise RequestError("keyman-newkey-password-on-argv-refused")
        if argument == "--pword" and index + 1 < len(args):
            value = args[index + 1]
            if value != "-":
                if isinstance(value, str) and value:
                    secrets.add(value)
                raise RequestError("keyman-newkey-password-on-argv-refused")


def _parse_args(args: list[str], secrets: set[str]) -> tuple[str, str, bool, bool]:
    if not args:
        raise RequestError("keyman-newkey-argv-required")
    _preflight_password_argv(args, secrets)
    if not all(isinstance(argument, str) for argument in args):
        raise RequestError("keyman-newkey-arguments-invalid")

    service = args[0]
    username: str | None = None
    password_stdin = False
    replace = False
    seen_username = False
    seen_password = False
    seen_replace = False
    index = 1
    while index < len(args):
        argument = args[index]
        if argument == "--username":
            if seen_username or index + 1 >= len(args):
                raise RequestError("keyman-newkey-arguments-invalid")
            username = args[index + 1]
            seen_username = True
            index += 2
            continue
        if argument == "--pword":
            if seen_password or index + 1 >= len(args) or args[index + 1] != "-":
                raise RequestError("keyman-newkey-arguments-invalid")
            password_stdin = True
            seen_password = True
            index += 2
            continue
        if argument == "--replace":
            if seen_replace:
                raise RequestError("keyman-newkey-arguments-invalid")
            replace = True
            seen_replace = True
            index += 1
            continue
        raise RequestError("keyman-newkey-arguments-invalid")

    if not seen_username or username is None:
        raise RequestError("keyman-newkey-arguments-invalid")
    return service, username, password_stdin, replace


def _validate_service(service: object) -> None:
    if not isinstance(service, str) or not service or len(service) > _MAX_SERVICE_NAME:
        raise RequestError("keyman-newkey-service-invalid")
    if not service.isascii() or not all(
        "A" <= char <= "Z"
        or "a" <= char <= "z"
        or "0" <= char <= "9"
        or char == "_"
        for char in service
    ) or service == "service_suite":
        raise RequestError("keyman-newkey-service-invalid")


def _field_bytes(value: object, signal_name: str) -> bytearray:
    if not isinstance(value, str) or not value or len(value) > _MAX_FIELD_VALUE:
        raise RequestError(signal_name)
    try:
        encoded = bytearray(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise RequestError(signal_name) from None
    if (
        not encoded
        or len(encoded) > _MAX_FIELD_VALUE
        or any(byte in encoded for byte in (0, 10, 13, 34))
    ):
        encoded[:] = b"\0" * len(encoded)
        raise RequestError(signal_name)
    return encoded


def _read_piped_password(secrets: set[str]) -> str:
    raw = bytearray()
    overflow = False
    unreadable = False
    invalid_text = False
    stream = getattr(sys.stdin, "buffer", sys.stdin)
    try:
        while True:
            try:
                chunk = stream.read(_READ_CHUNK)
            except (OSError, UnicodeError, ValueError):
                unreadable = True
                break
            if not chunk:
                break
            if isinstance(chunk, str):
                try:
                    chunk = chunk.encode("utf-8")
                except UnicodeEncodeError:
                    invalid_text = True
                    continue
            elif not isinstance(chunk, (bytes, bytearray)):
                invalid_text = True
                continue
            if not overflow:
                if len(raw) + len(chunk) <= _MAX_FIELD_VALUE + 1:
                    raw.extend(chunk)
                else:
                    overflow = True
        if unreadable:
            raise RequestError("keyman-newkey-password-source-unreadable")
        if overflow or invalid_text:
            raise RequestError("keyman-newkey-password-invalid")
        if raw.endswith(b"\n"):
            del raw[-1:]
        try:
            password = raw.decode("utf-8")
        except UnicodeDecodeError:
            candidate = raw.decode("utf-8", "replace")
            if candidate:
                secrets.add(candidate)
            raise RequestError("keyman-newkey-password-invalid") from None
        if password:
            secrets.add(password)
        return password
    finally:
        raw[:] = b"\0" * len(raw)


def _prompt_password(service: str, secrets: set[str]) -> str:
    try:
        if not sys.stdin.isatty():
            raise RequestError("keyman-newkey-password-source-missing")
    except (AttributeError, OSError, ValueError):
        raise RequestError("keyman-newkey-password-source-missing") from None

    first: str | None = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            first = getpass.getpass(f"password for {service}:")
            if isinstance(first, str) and first:
                secrets.add(first)
            second = getpass.getpass(f"password for {service}:")
            if isinstance(second, str) and second:
                secrets.add(second)
    except (EOFError, OSError, getpass.GetPassWarning):
        raise RequestError("keyman-newkey-password-source-missing") from None

    if not isinstance(first, str) or not isinstance(second, str):
        raise RequestError("keyman-newkey-password-invalid")
    if first != second:
        raise RequestError("keyman-newkey-password-mismatch")
    return first


def _zero(buffer: bytearray | None) -> None:
    if buffer is not None:
        buffer[:] = b"\0" * len(buffer)


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=1)
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass


def _drain_stream(stream, buffer: bytearray, state: dict[str, bool]) -> None:
    try:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            remaining = MAX_OUTPUT - len(buffer)
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            if len(chunk) > remaining:
                state["overflow"] = True
    except (OSError, ValueError):
        state["read_failed"] = True


def _write_stdin(stream, body: bytearray, state: dict[str, bool]) -> None:
    try:
        stream.write(body)
        stream.flush()
    except (BrokenPipeError, OSError, ValueError):
        state["write_failed"] = True
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _relay_input(source, target, state: dict[str, bool]) -> None:
    reusable = bytearray(_READ_CHUNK)
    try:
        reader = getattr(source, "readinto", None)
        if callable(reader):
            while True:
                try:
                    count = reader(reusable)
                except (OSError, UnicodeError, ValueError):
                    state["read_failed"] = True
                    break
                if not isinstance(count, int):
                    state["read_failed"] = True
                    break
                if count <= 0:
                    break
                try:
                    view = memoryview(reusable)[:count]
                    offset = 0
                    while offset < count:
                        written = target.write(view[offset:])
                        if written is None or written <= 0:
                            state["write_failed"] = True
                            return
                        offset += written
                    target.flush()
                except (BrokenPipeError, OSError, ValueError):
                    state["write_failed"] = True
                    break
                finally:
                    reusable[:count] = b"\0" * count
            return

        while True:
            try:
                chunk = source.read(_READ_CHUNK)
            except (OSError, UnicodeError, ValueError):
                state["read_failed"] = True
                break
            if not chunk:
                break
            try:
                if isinstance(chunk, str):
                    relay = bytearray(chunk.encode("utf-8", "surrogateescape"))
                elif isinstance(chunk, (bytes, bytearray)):
                    relay = bytearray(chunk)
                else:
                    state["read_failed"] = True
                    break
            except UnicodeEncodeError:
                state["read_failed"] = True
                break
            finally:
                chunk = None
            try:
                view = memoryview(relay)
                offset = 0
                while offset < len(relay):
                    written = target.write(view[offset:])
                    if written is None or written <= 0:
                        state["write_failed"] = True
                        break
                    offset += written
                target.flush()
            except (BrokenPipeError, OSError, ValueError):
                state["write_failed"] = True
                break
            finally:
                _zero(relay)
    finally:
        _zero(reusable)
        try:
            target.close()
        except (OSError, ValueError):
            pass


def _receipt_output(output: bytearray) -> bool:
    try:
        value = json.loads(output)
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError):
        return False
    return (
        isinstance(value, dict)
        and isinstance(value.get("schema"), str)
        and isinstance(value.get("ok"), bool)
        and isinstance(value.get("firstMissingSignal"), str)
        and (
            value.get("operation") == "newkey"
            or value.get("schema") == "agathodaimon.front-door.v1"
        )
    )


def _root_reexec(args: list[str]) -> tuple[bytearray, int] | None:
    try:
        interactive = bool(sys.stdin.isatty())
    except (AttributeError, OSError, ValueError):
        interactive = False
    argv = [
        "/usr/bin/sudo",
        "-n",
        "/usr/local/sbin/agathodaimon/cli.py",
        "keyman",
        "newkey",
        *args,
    ]
    try:
        process = subprocess.Popen(
            argv,
            stdin=None if interactive else subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    output = bytearray()
    output_state = {"overflow": False, "read_failed": False}
    input_state = {"read_failed": False, "write_failed": False}
    if process.stdout is None or (not interactive and process.stdin is None):
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait()
        except (OSError, subprocess.SubprocessError):
            pass
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        return None

    output_thread = threading.Thread(
        target=_drain_stream, args=(process.stdout, output, output_state), daemon=True
    )
    input_thread = None
    if not interactive:
        try:
            source = getattr(sys.stdin, "buffer", sys.stdin)
        except (AttributeError, OSError, UnicodeError, ValueError):
            source = sys.stdin
        input_thread = threading.Thread(
            target=_relay_input, args=(source, process.stdin, input_state), daemon=True
        )
    started = []
    try:
        output_thread.start()
        started.append(output_thread)
        if input_thread is not None:
            input_thread.start()
            started.append(input_thread)
    except RuntimeError:
        try:
            process.kill()
        except OSError:
            pass

    returncode = None
    try:
        returncode = process.wait()
    except (OSError, subprocess.SubprocessError):
        try:
            process.kill()
        except OSError:
            pass
        try:
            returncode = process.wait()
        except (OSError, subprocess.SubprocessError):
            pass
    for thread in started:
        thread.join()
    for stream in (process.stdin, process.stdout):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    if (
        returncode is None
        or output_state["overflow"]
        or output_state["read_failed"]
        or (input_thread is not None and (input_state["read_failed"] or input_state["write_failed"]))
        or not _receipt_output(output)
    ):
        _zero(output)
        return None
    return output, int(returncode)


def _write_passthrough(output: bytearray) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is not None:
        view = memoryview(output)
        offset = 0
        while offset < len(view):
            written = stream.write(view[offset:])
            if written is None or written <= 0:
                raise OSError("stdout-write-failed")
            offset += written
        stream.flush()
        return
    sys.stdout.write(output.decode("utf-8", "surrogateescape"))
    sys.stdout.flush()


def _run_child(argv: list[str], body: bytearray) -> dict[str, Any] | None:
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    stdout = bytearray()
    stderr = bytearray()
    stdout_state = {"overflow": False, "read_failed": False}
    stderr_state = {"overflow": False, "read_failed": False}
    stdin_state = {"write_failed": False}
    stdin_stream = process.stdin
    stdout_stream = process.stdout
    stderr_stream = process.stderr
    streams = (stdin_stream, stdout_stream, stderr_stream)
    if stdin_stream is None or stdout_stream is None or stderr_stream is None:
        _kill_process_group(process)
        for stream in streams:
            if stream is not None:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        return {
            "returncode": None,
            "stdout": stdout,
            "stderr": stderr,
            "timed_out": False,
            "thread_failed": True,
            "stdout_state": stdout_state,
            "stderr_state": stderr_state,
            "stdin_state": stdin_state,
        }

    threads = [
        threading.Thread(target=_write_stdin, args=(stdin_stream, body, stdin_state), daemon=True),
        threading.Thread(target=_drain_stream, args=(stdout_stream, stdout, stdout_state), daemon=True),
        threading.Thread(target=_drain_stream, args=(stderr_stream, stderr, stderr_state), daemon=True),
    ]
    started_threads = []
    thread_failed = False
    try:
        for thread in threads:
            thread.start()
            started_threads.append(thread)
    except RuntimeError:
        thread_failed = True
        _kill_process_group(process)
        for stream in (stdin_stream, stdout_stream, stderr_stream):
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    timed_out = False
    returncode: int | None = None
    try:
        returncode = process.wait(timeout=_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
    except (OSError, subprocess.SubprocessError):
        thread_failed = True
        _kill_process_group(process)

    for thread in started_threads:
        thread.join(timeout=1)
    if any(thread.is_alive() for thread in started_threads):
        _kill_process_group(process)
        for stream in (stdin_stream, stdout_stream, stderr_stream):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        for thread in started_threads:
            thread.join(timeout=1)
        if any(thread.is_alive() for thread in started_threads):
            thread_failed = True

    for stream in streams:
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "timed_out": timed_out,
        "thread_failed": thread_failed,
        "stdout_state": stdout_state,
        "stderr_state": stderr_state,
        "stdin_state": stdin_state,
    }


def _backend_outcome(
    result: dict[str, Any] | None,
    *,
    dispatched: bool,
    service: str,
    username: str,
    replace: bool,
    secrets: set[str],
) -> dict[str, Any]:
    if result is None:
        return _receipt(
            "keyman-newkey-backend-unavailable",
            mutation=False,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )

    stdout: bytearray = result["stdout"]
    stderr: bytearray = result["stderr"]
    if result["timed_out"]:
        return _receipt(
            "keyman-newkey-backend-timeout",
            mutation=None,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )
    if (
        result["thread_failed"]
        or result["stdin_state"]["write_failed"]
        or result["stdout_state"]["read_failed"]
        or result["stderr_state"]["read_failed"]
    ):
        return _receipt(
            "keyman-newkey-backend-failed",
            mutation=None,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )
    if result["stdout_state"]["overflow"] or result["stderr_state"]["overflow"]:
        return _receipt(
            "keyman-newkey-backend-output-too-large",
            mutation=None,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )

    returncode = result["returncode"]
    if (
        returncode == 2
        and not stdout
        and bytes(stderr).rstrip(b"\n") == b"ERROR: key file already exists"
    ):
        return _receipt(
            "keyman-newkey-key-already-exists",
            mutation=False,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )
    if returncode != 0:
        return _receipt(
            "keyman-newkey-backend-failed",
            mutation=None,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )

    try:
        backend = json.loads(stdout)
    except (UnicodeError, json.JSONDecodeError, RecursionError, TypeError):
        backend = None
    if isinstance(backend, dict):
        _collect_secret_values(backend, secrets)
    if (
        not isinstance(backend, dict)
        or backend.get("ok") is not True
        or backend.get("operation") != "newkey"
        or backend.get("service") != service
        or backend.get("secret_free") is not True
    ):
        backend = None
        return _receipt(
            "keyman-newkey-backend-receipt-invalid",
            mutation=None,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
        )

    receipt = _receipt(
        "none",
        mutation=True,
        secrets=secrets,
        dispatched=dispatched,
        service=service,
        username=username,
        replace=replace,
        backend_receipt=backend,
    )
    backend = None
    return receipt


def main(argv=None):
    secrets: set[str] = set()
    service: str | None = None
    username: str | None = None
    replace: bool | None = None
    body: bytearray | None = None
    username_bytes: bytearray | None = None
    password_bytes: bytearray | None = None
    child_result: dict[str, Any] | None = None
    root_result: tuple[bytearray, int] | None = None
    dispatch_begun = False
    receipt: dict[str, Any] | None = None
    try:
        if argv is None:
            args: list[str] = []
        elif isinstance(argv, (list, tuple)):
            args = list(argv)
        else:
            raise RequestError("keyman-newkey-arguments-invalid")

        service, username, password_stdin, replace = _parse_args(args, secrets)
        _validate_service(service)
        username_bytes = _field_bytes(username, "keyman-newkey-username-invalid")

        if os.geteuid() != 0:
            root_result = _root_reexec(args)
            if root_result is None:
                receipt = _receipt(
                    "keyman-newkey-root-required",
                    mutation=False,
                    secrets=secrets,
                    service=service,
                    username=username,
                    replace=replace,
                )
        else:
            password = (
                _read_piped_password(secrets)
                if password_stdin
                else _prompt_password(service, secrets)
            )
            if password:
                secrets.add(password)
            password_bytes = _field_bytes(password, "keyman-newkey-password-invalid")

            body = bytearray(b'username="')
            body.extend(username_bytes)
            body.extend(b'"\npassword="')
            body.extend(password_bytes)
            body.extend(b'"\n')
            scratch_root = os.environ.get("KEYMAN_ROOT")
            with exchange_session(
                scratch_root=scratch_root,
                exporter=PREFIX[-1] if scratch_root is not None else None,
                native=True,
            ):
                child_argv = [PREFIX[-1], "newkey", "--stdin", service]
                if replace:
                    child_argv.append("--replace")
                dispatch_begun = True
                child_result = _run_child(child_argv, body)
                receipt = _backend_outcome(
                    child_result,
                    dispatched=child_result is not None,
                    service=service,
                    username=username,
                    replace=replace,
                    secrets=secrets,
                )
    except KeymanExportError as error:
        dispatched = child_result is not None
        backend_receipt = receipt.get("backendReceipt") if receipt is not None else None
        mutation = (
            True
            if receipt is not None and receipt.get("mutationPerformed") is True
            else None if dispatched else False
        )
        receipt = _receipt(
            "keyman-newkey-" + error.signal,
            mutation=mutation,
            secrets=secrets,
            dispatched=dispatched,
            service=service,
            username=username,
            replace=replace,
            backend_receipt=backend_receipt,
        )
    except RequestError as error:
        receipt = _receipt(
            error.signal,
            mutation=False,
            secrets=secrets,
            service=service,
            username=username,
            replace=replace,
        )
    except Exception:
        receipt = _receipt(
            "keyman-newkey-staff-failed",
            mutation=(None if dispatch_begun else False),
            secrets=secrets,
            dispatched=dispatch_begun,
            service=service,
            username=username,
            replace=replace,
        )
    finally:
        _zero(body)
        _zero(username_bytes)
        _zero(password_bytes)
        if child_result is not None:
            _zero(child_result.get("stdout"))
            _zero(child_result.get("stderr"))

    if root_result is not None:
        output, returncode = root_result
        try:
            _write_passthrough(output)
        except OSError:
            pass
        finally:
            _zero(output)
        return returncode
    assert receipt is not None
    return _emit(receipt, None, secrets)

"""Sway session and IPC helpers shared by settings."""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from agathodaimon.settings.display import policy

if TYPE_CHECKING:
    from agathodaimon.settings import _shared


def _owner_uid():
    return backends._owner_uid()


def _owner_processes(name):
    return backends._owner_processes(name)


def _sway_socket_for(pid, uid):
    return backends._sway_socket_for(pid, uid)


def _parse_json_list(result):
    return backends._parse_json_list(result)


def _merge_kms_modes(connectors, kms):
    return backends._merge_kms_modes(connectors, kms)


def select_backend() -> dict[str, Any] | None:
    """Sway requires one owner-owned live IPC socket."""
    sway_pids = _owner_processes("sway")
    if sway_pids is None or not sway_pids:
        return None
    try:
        uid = _owner_uid()
    except KeyError:
        return None
    valid = [(pid, _sway_socket_for(pid, uid)) for pid in sway_pids]
    valid = [(pid, socket_path) for pid, socket_path in valid if socket_path]
    if len(valid) != 1:
        return None
    pid, socket_path = valid[0]
    return {"kind": "sway", "pid": pid, "socket": socket_path, "owner_process_count": len(sway_pids)}

def _bounded_command(argv: Sequence[str], *, runtime: str | None = None,
                     socket_path: str | None = None) -> dict[str, Any]:
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    if runtime is not None:
        env["XDG_RUNTIME_DIR"] = runtime
    if socket_path is not None:
        env["SWAYSOCK"] = socket_path
    process: subprocess.Popen[bytes] | None = None
    selector = selectors.DefaultSelector()
    streams: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                                   close_fds=True)
        assert process.stdout is not None and process.stderr is not None
        os.set_blocking(process.stdout.fileno(), False)
        os.set_blocking(process.stderr.fileno(), False)
        pipe_by_label = {"stdout": process.stdout, "stderr": process.stderr}
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        deadline = time.monotonic() + COMMAND_TIMEOUT
        timed_out = False
        too_large = False
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                process.kill()
                break
            events = selector.select(min(remaining, 0.1))
            if not events and process.poll() is not None:
                # A final read drains pipe EOF without waiting for another process event.
                events = [(key, None) for key in list(selector.get_map().values())]
            for key, _mask in events:
                label = key.data
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    pipe_by_label[label].close()
                    continue
                if len(streams[label]) + len(chunk) > MAX_COMMAND_BYTES:
                    too_large = True
                    process.kill()
                    selector.unregister(key.fileobj)
                    pipe_by_label[label].close()
                    break
                streams[label].extend(chunk)
            if too_large:
                break
        if timed_out or too_large:
            for key in list(selector.get_map().values()):
                try:
                    selector.unregister(key.fileobj)
                    pipe_by_label[key.data].close()
                except (KeyError, OSError):
                    pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            signal = "command-timeout" if timed_out else "command-output-limit"
            return {"ok": False, "signal": signal, "returncode": process.returncode,
                    "stdout": "", "stderr": signal}
        returncode = process.wait(timeout=0.2)
        stdout = bytes(streams["stdout"]).decode("utf-8", "replace")
        stderr = bytes(streams["stderr"]).decode("utf-8", "replace")
        return {"ok": returncode == 0, "signal": None if returncode == 0 else "command-failed",
                "returncode": returncode, "stdout": stdout, "stderr": stderr}
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        return {"ok": False, "signal": f"command-unavailable:{type(exc).__name__}",
                "returncode": None, "stdout": "", "stderr": ""}
    finally:
        selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

def _sway_argv(socket_path: str, command: Sequence[str]) -> tuple[list[str], str, int]:
    uid = _owner_uid()
    runtime = f"/run/user/{uid}"
    if os.geteuid() == 0:
        argv = ["runuser", "-u", OWNER, "--", "env", f"XDG_RUNTIME_DIR={runtime}",
                f"SWAYSOCK={socket_path}", "swaymsg", "-s", socket_path, *command]
    else:
        argv = ["swaymsg", "-s", socket_path, *command]
    return argv, runtime, uid

def observe_sway(socket_path: str, kms: Mapping[str, Any] | None = None) -> dict[str, Any]:
    argv, runtime, _uid = _sway_argv(socket_path, ["-t", "get_outputs"])
    result = _bounded_command(argv, runtime=runtime, socket_path=socket_path)
    outputs, error = _parse_json_list(result)
    if error or outputs is None:
        return {"ok": False, "connectors": [], "signal": error or "sway-output-array-invalid"}
    normalized = policy.normalize_sway_outputs(outputs)
    return {"ok": True, "connectors": _merge_kms_modes(normalized, kms), "signal": None,
            "source": "sway-ipc", "preferred_exposed_by_sway": False}

def _escape_sway_name(name: str) -> str:
    if not name or len(name) > 256 or any(ord(character) < 0x20 for character in name):
        raise ValueError("invalid Sway output name")
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _sway_reload(receipt: _shared.Receipt) -> None:
    selected = backends.select_backend()
    if not selected:
        raise ValueError("sway-session-unavailable")
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, ["reload"])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    receipt.commands.append({"argv": argv, "returncode": result.get("returncode")})
    try:
        responses = json.loads(result.get("stdout", ""))
    except (TypeError, json.JSONDecodeError):
        responses = []
    if not result.get("ok") or not isinstance(responses, list) or not responses or any(not isinstance(x, dict) or x.get("success") is not True for x in responses):
        raise ValueError("sway-reload-failed")


from agathodaimon.settings.display import backends

OWNER = backends.OWNER
COMMAND_TIMEOUT = backends.COMMAND_TIMEOUT
MAX_COMMAND_BYTES = backends.MAX_COMMAND_BYTES

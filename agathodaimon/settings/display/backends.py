"""Owner-process backend selection and bounded Sway IPC operations."""
from __future__ import annotations

import json
import os
import pwd
import selectors
import stat
import subprocess
import time
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
from pathlib import Path
from typing import Any, Collection, Mapping, Sequence

from agathodaimon.settings.display import policy

OWNER = "owner"
MAX_PROC_SCAN = 16384
MAX_ENV_BYTES = 64 * 1024
MAX_RUNTIME_ENTRIES = 128
MAX_COMMAND_BYTES = 256 * 1024
COMMAND_TIMEOUT = 3.0


def _owner_uid() -> int:
    return pwd.getpwnam(OWNER).pw_uid


def _owner_processes(name: str | Collection[str]) -> list[int] | None:
    names = {name} if isinstance(name, str) else set(name)
    try:
        uid = _owner_uid()
        found: list[int] = []
        with os.scandir("/proc") as proc:
            for index, entry in enumerate(proc):
                if index >= MAX_PROC_SCAN:
                    return None
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                try:
                    if os.stat(entry.path).st_uid != uid:
                        continue
                    with open(f"/proc/{pid}/comm", "rb") as stream:
                        command = stream.read(128).decode("utf-8", "replace").strip()
                except (OSError, ValueError):
                    continue
                if command in names:
                    found.append(pid)
        return sorted(found)
    except (OSError, KeyError):
        return None


def _process_coordinates(pid: int) -> dict[str, str] | None:
    """Read only Sway's IPC/runtime coordinates; never retain or return its environment."""
    wanted = {b"SWAYSOCK", b"XDG_RUNTIME_DIR"}
    try:
        with open(f"/proc/{pid}/environ", "rb") as stream:
            raw = stream.read(MAX_ENV_BYTES + 1)
        if len(raw) > MAX_ENV_BYTES:
            return None
        coordinates: dict[str, str] = {}
        for item in raw.split(b"\0"):
            key, separator, value = item.partition(b"=")
            if separator and key in wanted:
                coordinates[key.decode("ascii")] = value.decode("utf-8")
        return coordinates
    except (OSError, UnicodeDecodeError):
        return None


def _socket_is_owned(socket_path: Path, runtime: Path, uid: int, pid: int) -> bool:
    try:
        if not socket_path.is_absolute() or socket_path.parent != runtime:
            return False
        if any(part in {".", ".."} for part in socket_path.parts):
            return False
        if str(pid) not in socket_path.name.split(".") or str(uid) not in socket_path.name.split("."):
            return False
        metadata = socket_path.lstat()
        return stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == uid
    except OSError:
        return False


def _sway_socket_for(pid: int, uid: int) -> str | None:
    runtime = Path(f"/run/user/{uid}")
    try:
        runtime_info = runtime.lstat()
        if not stat.S_ISDIR(runtime_info.st_mode) or runtime_info.st_uid != uid:
            return None
    except OSError:
        return None
    coordinates = _process_coordinates(pid) or {}
    if coordinates.get("XDG_RUNTIME_DIR") not in {None, str(runtime)}:
        return None
    advertised = coordinates.get("SWAYSOCK")
    if advertised:
        candidate = Path(advertised)
        if _socket_is_owned(candidate, runtime, uid, pid):
            return str(candidate)
    matches: list[Path] = []
    try:
        with os.scandir(runtime) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_RUNTIME_ENTRIES:
                    break
                if "sway-ipc" not in entry.name or str(pid) not in entry.name.split("."):
                    continue
                candidate = Path(entry.path)
                if _socket_is_owned(candidate, runtime, uid, pid):
                    matches.append(candidate)
    except OSError:
        return None
    return str(matches[0]) if len(matches) == 1 else None


def select_backend() -> dict[str, Any] | None:
    """Gamescope owner process wins; Sway requires one owner-owned live IPC socket."""
    # gamescope names its Wayland thread "gamescope-wl" at wlserver_run:
    # https://github.com/ValveSoftware/gamescope/blob/6867f509874f9bc52e12d6f4c4596cdf0d5be6b4/src/wlserver.cpp#L2397-L2400
    gamescope = _owner_processes(("gamescope-wl", "gamescope"))
    if gamescope is None:
        return None
    if gamescope:
        return {"kind": "gamescope", "pid": gamescope[0], "owner_process_count": len(gamescope)}
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


def _parse_json_list(result: Mapping[str, Any]) -> tuple[list[Any] | None, str | None]:
    if result.get("ok") is not True:
        return None, str(result.get("signal") or "sway-command-failed")
    try:
        value = json.loads(str(result.get("stdout", "")))
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None, "sway-json-invalid"
    if not isinstance(value, list) or len(value) > policy.MAX_CONNECTORS:
        return None, "sway-output-array-invalid"
    return value, None


def _mode_match(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if left.get("width") != right.get("width") or left.get("height") != right.get("height"):
        return False
    left_rate = policy._rate_fraction(left)
    right_rate = policy._rate_fraction(right)
    if left_rate is None or right_rate is None:
        return False
    return abs(left_rate - right_rate) <= Fraction(1, 2000)


def _merge_kms_modes(sway_connectors: list[dict[str, Any]], kms: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(kms, Mapping) or kms.get("ok") is not True:
        return sway_connectors
    kms_connectors = kms.get("connectors")
    if not isinstance(kms_connectors, list):
        return sway_connectors
    by_name = {
        str(connector.get("connector_name")): connector
        for connector in kms_connectors if isinstance(connector, dict)
    }
    for connector in sway_connectors:
        kms_connector = by_name.get(str(connector.get("connector_name")))
        if not isinstance(kms_connector, dict):
            continue
        connector["device"] = kms_connector.get("device")
        connector["connector_id"] = kms_connector.get("connector_id")
        connector["kms_current_mode"] = kms_connector.get("current_mode")
        kms_modes_value = kms_connector.get("modes")
        kms_modes = kms_modes_value if isinstance(kms_modes_value, list) else []
        sway_modes_value = connector.get("modes")
        sway_modes = sway_modes_value if isinstance(sway_modes_value, list) else []
        for mode in sway_modes:
            if not isinstance(mode, dict):
                continue
            match = next((candidate for candidate in kms_modes
                          if isinstance(candidate, dict) and _mode_match(mode, candidate)), None)
            if match is not None:
                mode["interlaced"] = match.get("interlaced")
                mode["preferred"] = match.get("preferred")
                mode["kms_current"] = match.get("current")
    return sway_connectors


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


def _refresh_hz_text(rate: Fraction) -> str:
    value = (Decimal(rate.numerator) / Decimal(rate.denominator)).quantize(
        Decimal("0.001"), rounding=ROUND_HALF_UP)
    return format(value, "f").rstrip("0").rstrip(".")


def _expected_millihz(mode: Mapping[str, Any]) -> int | None:
    raw = mode.get("refresh_millihz")
    if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0:
        return raw
    rate = policy._rate_fraction(mode)
    if rate is None:
        return None
    scaled = rate * 1000
    return int(scaled + Fraction(1, 2))


def _find_live_output(connectors: Sequence[Mapping[str, Any]], name: str) -> Mapping[str, Any] | None:
    return next((connector for connector in connectors
                 if connector.get("connector_name") == name and connector.get("connected") is True), None)


def apply_sway_mode(socket_path: str, connector: Mapping[str, Any], mode: Mapping[str, Any],
                    kms: Mapping[str, Any] | None = None) -> dict[str, Any]:
    name = connector.get("connector_name") or connector.get("name")
    width, height = mode.get("width"), mode.get("height")
    rate = policy._rate_fraction(mode)
    if (not isinstance(name, str) or not isinstance(width, int) or isinstance(width, bool)
            or not isinstance(height, int) or isinstance(height, bool) or rate is None):
        return {"ok": False, "mutation_performed": False, "signal": "resolved-sway-mode-invalid"}
    command = f"output {_escape_sway_name(name)} mode {width}x{height}@{_refresh_hz_text(rate)}Hz"
    argv, runtime, _uid = _sway_argv(socket_path, [command])
    applied = _bounded_command(argv, runtime=runtime, socket_path=socket_path)
    command_responses: Any = None
    if applied.get("ok") is True:
        try:
            command_responses = json.loads(str(applied.get("stdout", "")))
        except (json.JSONDecodeError, TypeError, ValueError):
            command_responses = None
    command_ok = (
        applied.get("ok") is True and isinstance(command_responses, list)
        and bool(command_responses)
        and all(isinstance(item, dict) and item.get("success") is True for item in command_responses)
    )
    command_receipt: dict[str, Any] = {
        "argv": argv, "ok": command_ok,
        "returncode": applied.get("returncode"),
        "signal": applied.get("signal") if not command_ok else None,
    }
    if not command_ok:
        return {"ok": False, "mutation_performed": applied.get("returncode") is not None,
                "signal": str(applied.get("signal") or "sway-command-refused"),
                "command": command_receipt, "current_mode": None,
                "physical_mode_verified": False}
    after = observe_sway(socket_path, kms)
    if after.get("ok") is not True:
        return {"ok": False, "mutation_performed": True,
                "signal": str(after.get("signal") or "sway-readback-failed"),
                "command": command_receipt, "current_mode": None,
                "physical_mode_verified": False}
    live = _find_live_output(after.get("connectors", []), str(name))
    current = live.get("current_mode") if isinstance(live, Mapping) else None
    expected_millihz = _expected_millihz(mode)
    same = (
        isinstance(current, dict)
        and current.get("width") == width and current.get("height") == height
        and isinstance(current.get("refresh"), int) and not isinstance(current.get("refresh"), bool)
        and expected_millihz is not None
        and abs(int(current["refresh"]) - expected_millihz) <= 1
    )
    return {
        "ok": bool(same), "mutation_performed": True,
        "signal": None if same else "sway-mode-readback-mismatch",
        "command": command_receipt,
        "current_mode": dict(current) if isinstance(current, dict) else None,
        "expected_millihz": expected_millihz,
        "physical_mode_verified": bool(same),
        "connectors": after.get("connectors", []),
    }


def restart_gamescope_seat() -> dict[str, Any]:
    """Use the existing seat restart actuator; do not duplicate its service logic."""
    try:
        from agathodaimon.console.restart.index import restart
        reply = restart("seat")
        return reply if isinstance(reply, dict) else {
            "ok": False, "first_missing_signal": "console-restart-invalid-reply",
            "mutation_performed": False,
        }
    except Exception as exc:
        return {"ok": False, "first_missing_signal": f"console-restart-unavailable:{type(exc).__name__}",
                "mutation_performed": False}

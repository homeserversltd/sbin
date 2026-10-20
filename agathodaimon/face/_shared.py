from __future__ import annotations

import fcntl
import json
import os
import pwd
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from agathodaimon import _load_trace
from agathodaimon._envelope import EnvelopeError, Request, attach, read
from agathodaimon.lib.receipts.index import emit

OWNER_USER = "owner"
DEFAULT_OWNER_HOME = "/home/owner"
DEFAULT_CACHE_STATE = "Different"
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|access[_-]?key|credential|pin)\b"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_VALUE = re.compile(r"(?i)\b(Basic\s+)[A-Za-z0-9+/=]+")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/@]+@")


class FaceError(ValueError):
    def __init__(self, signal: str, **fields: Any):
        super().__init__(signal)
        self.signal = signal
        self.fields = fields


_BENCHMARK_SCHEMA = "caduceus.benchmark.v1"
_SWAY_IPC_MAGIC = b"i3-ipc"
_SWAY_IPC_HEADER_SIZE = 14
_SWAY_IPC_MAX_REPLY_BYTES = 16 * 1024 * 1024
_SWAY_IPC_TIMEOUT_SECONDS = 8.0
# Compatibility adapters: the sole clocks and ContextVar live in _load_trace.
_BENCHMARK_CONTEXT = _load_trace.BENCHMARK_CONTEXT
_benchmark_enabled = _load_trace.benchmark_enabled
_process_boot_elapsed_ms = _load_trace.process_boot_elapsed_ms
_benchmark_call = _load_trace.benchmark_call
_benchmark_boot_entry = _load_trace.benchmark_boot_entry


def read_payload() -> Request:
    """Read the public envelope and select the fields used by FaceDoor verbs."""
    return read(known_fields=("payload", "direction", "action", "desktop_id", "menu", "id", "kind", "step", "carry", "ring", "mode"))


def invoke(verb: str, operation: Callable[[dict[str, Any]], Mapping[str, Any]]) -> int:
    """Emit one transient receipt through the shared trace/timing scope."""
    request: Request | None = None
    trace: _load_trace.InvocationHandle | None = None
    benchmark_report: dict[str, Any] | None = None
    try:
        request = read_payload()
        with _load_trace.invocation(
            request.load_context,
            trace_present=request.load_context_present,
            benchmark=_benchmark_enabled(request),
            operation="agathodaimon.face.operation",
        ) as trace:
            try:
                if request.envelope:
                    payload = request.payload
                else:
                    primitive_payload = request.value.get("payload")
                    payload = dict(primitive_payload) if isinstance(primitive_payload, Mapping) else {}
                fields = dict(operation(payload))
                fields.setdefault("ok", True)
                fields.setdefault("firstMissingSignal", "none")
                receipt = {"verb": verb, **fields}
            except EnvelopeError as error:
                receipt = {"verb": verb, "ok": False, "firstMissingSignal": str(error)}
            except FaceError as error:
                receipt = {
                    "verb": verb,
                    "ok": False,
                    "firstMissingSignal": error.signal,
                    **error.fields,
                }
            except Exception:
                receipt = {"verb": verb, "ok": False, "firstMissingSignal": f"face-{verb}-operation-failed"}
            if trace is not None:
                trace.set_outcome("failed" if receipt.get("ok") is False else "ok")
                benchmark_report = trace.benchmark_report()
        if request is not None and trace is not None:
            request.returned_load_context = trace.response_context()
    except EnvelopeError as error:
        receipt = {"verb": verb, "ok": False, "firstMissingSignal": str(error)}
    if request is not None:
        receipt = attach(receipt, request)
    if benchmark_report is not None:
        receipt["benchmark"] = benchmark_report
    return emit(receipt)


def _owner() -> pwd.struct_passwd:
    try:
        account = pwd.getpwnam(OWNER_USER)
    except KeyError:
        raise FaceError("owner-account-missing")
    if os.geteuid() not in (0, account.pw_uid):
        raise FaceError("owner-session-identity-refused")
    return account


def _absolute_home(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or "\x00" in value or any(part in {".", ".."} for part in value.split("/")):
        raise FaceError("launcher-home-invalid")
    return path.resolve(strict=False)


def owner_home() -> Path:
    return _absolute_home(os.environ.get("CADUCEUS_LAUNCHER_HOME", DEFAULT_OWNER_HOME))


def launcher_cache_directory(home: Path | None = None) -> Path:
    override = os.environ.get("CADUCEUS_LAUNCHER_CACHE_DIR")
    if override is not None:
        return _absolute_home(override)
    return (home or owner_home()) / ".cache"


def _runtime_dir(account: pwd.struct_passwd) -> Path:
    return Path(f"/run/user/{account.pw_uid}")


def _is_live_owned_socket(path: Path, account: pwd.struct_passwd, runtime: Path) -> bool:
    try:
        relative = path.relative_to(runtime)
        if not relative.parts or any(part in {".", ".."} for part in relative.parts):
            return False
        current = runtime
        runtime_stat = os.lstat(current)
        if not stat.S_ISDIR(runtime_stat.st_mode) or stat.S_ISLNK(runtime_stat.st_mode) or runtime_stat.st_uid != account.pw_uid:
            return False
        for part in relative.parts[:-1]:
            current = current / part
            metadata = os.lstat(current)
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != account.pw_uid:
                return False
        metadata = os.lstat(path)
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != account.pw_uid:
            return False
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.25)
        try:
            probe.connect(str(path))
        finally:
            probe.close()
        return True
    except (OSError, ValueError):
        return False


def _socket_path(value: str, runtime: Path) -> Path | None:
    if not value or "\x00" in value:
        return None
    candidate = Path(value)
    if not candidate.is_absolute():
        if len(candidate.parts) != 1 or candidate.name in {".", ".."}:
            return None
        candidate = runtime / candidate
    try:
        candidate.relative_to(runtime)
    except ValueError:
        return None
    return candidate


def _runtime_socket_candidates(key: str, account: pwd.struct_passwd, runtime: Path) -> list[Path]:
    pattern = f"sway-ipc.{account.pw_uid}.*.sock" if key == "SWAYSOCK" else "wayland-*"
    try:
        candidates = sorted(runtime.glob(pattern))
    except OSError:
        return []
    return [candidate for candidate in candidates if _is_live_owned_socket(candidate, account, runtime)]


def _proc_sway_environments_observed(uid: int) -> tuple[list[tuple[str, dict[str, str]]], bool]:
    found: list[tuple[str, dict[str, str]]] = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return found, False
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != uid:
                continue
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
            command = (entry / "cmdline").read_bytes().split(b"\x00", 1)[0].decode("utf-8", "replace")
            if comm != "sway" and Path(command).name != "sway":
                continue
            raw = (entry / "environ").read_bytes()
        except OSError:
            continue
        values: dict[str, str] = {}
        for item in raw.split(b"\x00"):
            if b"=" not in item:
                continue
            key, value = item.split(b"=", 1)
            try:
                values[key.decode("ascii")] = value.decode("utf-8")
            except UnicodeError:
                continue
        found.append((entry.name, values))
    return found, True


def _proc_sway_environments(uid: int) -> list[tuple[str, dict[str, str]]]:
    return _proc_sway_environments_observed(uid)[0]


def _runuser_command(command: Sequence[str], environment: Mapping[str, str]) -> tuple[list[str], dict[str, str]]:
    account = _owner()
    if os.geteuid() == account.pw_uid:
        return list(command), dict(environment)
    runuser = shutil.which("runuser") or "/usr/sbin/runuser"
    if not Path(runuser).is_file():
        raise FaceError("owner-runuser-unavailable")
    env_program = "/usr/bin/env"
    assignments = [f"{key}={value}" for key, value in sorted(environment.items())]
    return [runuser, "-u", OWNER_USER, "--", env_program, *assignments, *command], {"PATH": os.environ.get("PATH", os.defpath)}


def _systemctl_environment_observed(
    account: pwd.struct_passwd, home: Path, runtime: Path,
) -> tuple[dict[str, str], bool]:
    utility = shutil.which("systemctl")
    if utility is None:
        return {}, False
    environment = {
        "HOME": str(home), "USER": OWNER_USER, "LOGNAME": OWNER_USER,
        "PATH": os.environ.get("PATH", os.defpath), "XDG_RUNTIME_DIR": str(runtime),
        "XDG_CONFIG_HOME": str(home / ".config"), "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_STATE_HOME": str(home / ".local/state"),
    }
    bus = runtime / "bus"
    if _is_live_owned_socket(bus, account, runtime):
        environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    try:
        command, outer = _runuser_command([utility, "--user", "show-environment"], environment)
        result = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False, env=outer)
    except (OSError, subprocess.SubprocessError, FaceError):
        return {}, False
    if result.returncode != 0:
        return {}, False
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"SWAYSOCK", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "PULSE_SERVER"}:
            values[key] = value
    return values, True


def _systemctl_environment(account: pwd.struct_passwd, home: Path, runtime: Path) -> dict[str, str]:
    return _systemctl_environment_observed(account, home, runtime)[0]


def _owner_session_environment(
    *, home: Path | None = None, discover: bool = True,
    require_sway: bool = False, require_wayland: bool = False,
    enter_owner: bool = False, prefer_direct_keys: Sequence[str] = (),
) -> tuple[dict[str, str], str]:
    account = _owner()
    selected_home = home or Path(account.pw_dir)
    runtime = _runtime_dir(account)
    env = {
        "HOME": str(selected_home), "USER": OWNER_USER, "LOGNAME": OWNER_USER,
        "PATH": os.environ.get("PATH", os.defpath), "XDG_RUNTIME_DIR": str(runtime),
        "XDG_CONFIG_HOME": str(selected_home / ".config"),
        "XDG_CACHE_HOME": str(selected_home / ".cache"),
        "XDG_STATE_HOME": str(selected_home / ".local/state"),
    }
    if not discover and not (require_sway or require_wayland) and not enter_owner:
        return env, "not-required"

    proc_observation = _benchmark_call(
        "staff.session-env.proc",
        lambda: _proc_sway_environments_observed(account.pw_uid),
        success=lambda result: isinstance(result, tuple) and len(result) == 2 and result[1] is True,
    )
    proc_sources = proc_observation[0]
    if enter_owner:
        _benchmark_call("staff.owner-switch", _volume_owner_switch)

    direct_mode = bool(prefer_direct_keys) and not enter_owner
    runtime_values: dict[str, list[tuple[str, str]]] = {"SWAYSOCK": [], "WAYLAND_DISPLAY": []}
    if direct_mode:
        for key in runtime_values:
            for candidate in _runtime_socket_candidates(key, account, runtime):
                value = str(candidate) if key == "SWAYSOCK" else candidate.name
                runtime_values[key].append(("runtime-discovered", value))
        direct_ready = True
        for key in prefer_direct_keys:
            candidates: list[Path] = []
            for _pid, values in proc_sources:
                value = values.get(key)
                path = _socket_path(value, runtime) if value else None
                if path is not None and _is_live_owned_socket(path, account, runtime):
                    candidates.append(path)
            for _source, value in runtime_values.get(key, []):
                path = _socket_path(value, runtime)
                if path is not None:
                    candidates.append(path)
            if len(set(candidates)) != 1:
                direct_ready = False
                break
    else:
        direct_ready = False

    if not direct_ready:
        system_observation = _benchmark_call(
            "staff.session-env.systemctl",
            lambda: _systemctl_environment_observed(account, selected_home, runtime),
            success=lambda result: isinstance(result, tuple) and len(result) == 2 and result[1] is True,
        )
        system_values = system_observation[0]
    else:
        system_values = {}
    values_by_key: dict[str, list[tuple[str, str]]] = {key: [] for key in ("SWAYSOCK", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "PULSE_SERVER")}
    for pid, values in proc_sources:
        for key in values_by_key:
            if values.get(key):
                values_by_key[key].append((f"proc:{pid}", values[key]))
    if direct_mode and direct_ready:
        for key, values in runtime_values.items():
            values_by_key[key].extend(values)
    for key, value in system_values.items():
        if value:
            values_by_key[key].append(("systemctl-user", value))

    sources: dict[str, str] = {}
    for key in ("SWAYSOCK", "WAYLAND_DISPLAY"):
        valid: list[tuple[str, str]] = []
        for source, value in values_by_key[key]:
            path = _socket_path(value, runtime)
            if path is not None and _is_live_owned_socket(path, account, runtime):
                valid.append((source, value))
        unique = {(source, value) for source, value in valid}
        paths = (
            {_socket_path(value, runtime) for _source, value in unique}
            if direct_mode else {value for _source, value in unique}
        )
        if len(paths) == 1:
            source, value = next(iter(unique))
            env[key] = value
            sources[key] = source
        elif len(paths) > 1:
            required_key = (key == "SWAYSOCK" and require_sway) or (key == "WAYLAND_DISPLAY" and require_wayland)
            if required_key or not direct_mode:
                raise FaceError("owner-session-socket-ambiguous", socket=key)
        else:
            live = _runtime_socket_candidates(key, account, runtime)
            if len(live) == 1:
                env[key] = str(live[0]) if key == "SWAYSOCK" else live[0].name
                sources[key] = "runtime-unique"
            elif len(live) > 1:
                required_key = (key == "SWAYSOCK" and require_sway) or (key == "WAYLAND_DISPLAY" and require_wayland)
                if required_key or (not direct_mode and (require_sway or require_wayland)):
                    raise FaceError("owner-session-socket-ambiguous", socket=key)

    dbus_candidates = values_by_key["DBUS_SESSION_BUS_ADDRESS"]
    for source, value in dbus_candidates:
        match = re.fullmatch(r"unix:path=(.+)", value)
        if not match:
            continue
        path = _socket_path(match.group(1), runtime)
        if path is not None and _is_live_owned_socket(path, account, runtime):
            env["DBUS_SESSION_BUS_ADDRESS"] = value
            sources["DBUS_SESSION_BUS_ADDRESS"] = source
            break
    if "DBUS_SESSION_BUS_ADDRESS" not in env:
        bus = runtime / "bus"
        if _is_live_owned_socket(bus, account, runtime):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
            sources["DBUS_SESSION_BUS_ADDRESS"] = "runtime-owner-bus"

    for source, value in values_by_key["PULSE_SERVER"]:
        if value.startswith("unix:"):
            candidate_value = value[5:]
            path = _socket_path(candidate_value, runtime)
            if path is not None and _is_live_owned_socket(path, account, runtime):
                env["PULSE_SERVER"] = value
                sources["PULSE_SERVER"] = source
                break

    if require_sway and "SWAYSOCK" not in env:
        raise FaceError("owner-sway-socket-unavailable")
    if require_wayland and "WAYLAND_DISPLAY" not in env:
        raise FaceError("owner-wayland-socket-unavailable")
    source_text = ";".join(f"{key.lower()}:{sources.get(key, 'unavailable')}" for key in ("SWAYSOCK", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "PULSE_SERVER"))
    return env, source_text


def owner_session_environment(
    *, home: Path | None = None, discover: bool = True,
    require_sway: bool = False, require_wayland: bool = False,
    enter_owner: bool = False, prefer_direct_keys: Sequence[str] = (),
) -> tuple[dict[str, str], str]:
    return _benchmark_call(
        "staff.session-env",
        lambda: _owner_session_environment(
            home=home, discover=discover,
            require_sway=require_sway, require_wayland=require_wayland,
            enter_owner=enter_owner, prefer_direct_keys=prefer_direct_keys,
        ),
    )


def owner_session_command(argv: Sequence[str], environment: Mapping[str, str]) -> tuple[list[str], dict[str, str]]:
    if not argv or not all(isinstance(item, str) and "\x00" not in item for item in argv):
        raise FaceError("owner-command-argv-invalid")
    return _runuser_command(argv, environment)


def _owner_run(
    argv: Sequence[str], environment: Mapping[str, str], *, timeout: float = 8,
) -> subprocess.CompletedProcess[str]:
    command, outer = owner_session_command(argv, environment)
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False, env=outer)
    except (OSError, subprocess.TimeoutExpired) as error:
        return subprocess.CompletedProcess(command, 127, "", type(error).__name__)


def owner_run(
    argv: Sequence[str], environment: Mapping[str, str], *, timeout: float = 8,
) -> subprocess.CompletedProcess[str]:
    return _benchmark_call(
        "staff.act",
        lambda: _owner_run(argv, environment, timeout=timeout),
        success=lambda result: isinstance(result, subprocess.CompletedProcess) and result.returncode == 0,
    )


def _root_process_run(
    argv: Sequence[str], environment: Mapping[str, str], *, action: str, timeout: float = 5,
) -> subprocess.CompletedProcess[str]:
    def run() -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(list(argv), capture_output=True, text=True, timeout=timeout, check=False, env=environment)
        except (OSError, subprocess.SubprocessError) as error:
            return subprocess.CompletedProcess(list(argv), 127, "", type(error).__name__)

    accepted = (0, 1) if action == "pgrep" else (0,)
    return _benchmark_call(
        f"staff.act root {action}", run,
        success=lambda result: isinstance(result, subprocess.CompletedProcess) and result.returncode in accepted,
    )


def owner_spawn(argv: Sequence[str], environment: Mapping[str, str]) -> tuple[subprocess.Popen, int | None]:
    command, outer = owner_session_command(argv, environment)
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, start_new_session=True, env=outer,
        )
    except OSError:
        raise FaceError("owner-launch-exec-failed")
    time.sleep(0.05)
    exit_code = process.poll()
    if exit_code not in (None, 0):
        raise FaceError("owner-launch-exec-failed", exit=exit_code)
    return process, exit_code


def _require_string(payload: Mapping[str, Any], key: str, signal: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise FaceError(signal)
    return value


def _owner_utility(name: str) -> str | None:
    return shutil.which(name, path=os.environ.get("PATH", os.defpath))


def _sway_ipc_read_exact(connection: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = connection.recv(length - len(data))
        if not chunk:
            raise FaceError("swaymsg-query-failed")
        data.extend(chunk)
    return bytes(data)


def _sway_ipc_exchange(query_type: int, body: bytes, environment: Mapping[str, str]) -> bytes:
    socket_path = environment.get("SWAYSOCK")
    if not socket_path or "\x00" in socket_path or len(body) > _SWAY_IPC_MAX_REPLY_BYTES:
        raise FaceError("swaymsg-query-failed")
    try:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.settimeout(_SWAY_IPC_TIMEOUT_SECONDS)
            connection.connect(socket_path)
            header = _SWAY_IPC_MAGIC + struct.pack("=II", len(body), query_type)
            connection.sendall(header + body)
            reply_header = _sway_ipc_read_exact(connection, _SWAY_IPC_HEADER_SIZE)
            if reply_header[:6] != _SWAY_IPC_MAGIC:
                raise FaceError("swaymsg-query-failed")
            reply_length, reply_type = struct.unpack("=II", reply_header[6:])
            if reply_type != query_type or reply_length > _SWAY_IPC_MAX_REPLY_BYTES:
                raise FaceError("swaymsg-query-failed")
            return _sway_ipc_read_exact(connection, reply_length)
        finally:
            connection.close()
    except FaceError:
        raise
    except (OSError, struct.error, ValueError):
        raise FaceError("swaymsg-query-failed")


def _sway_json(query: str, environment: Mapping[str, str]) -> Any:
    query_types = {"get_workspaces": 1, "get_outputs": 3, "get_tree": 4}
    query_type = query_types.get(query)
    if query_type is None:
        raise FaceError("swaymsg-query-failed")

    def exchange_and_parse() -> Any:
        response = _sway_ipc_exchange(query_type, b"", environment)
        try:
            return json.loads(response)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            raise FaceError("swaymsg-json-invalid")

    return _benchmark_call(f"staff.act ipc {query}", exchange_and_parse)


def _sway_command(
    command: str, environment: Mapping[str, str], *, raw: bool = False,
) -> subprocess.CompletedProcess[str]:
    argv = ["swaymsg", *(["-r"] if raw else []), command]

    def exchange() -> tuple[subprocess.CompletedProcess[str], bool]:
        try:
            response = _sway_ipc_exchange(0, command.encode("utf-8"), environment)
        except FaceError as error:
            return subprocess.CompletedProcess(argv, 127, "", str(error)), False
        output = response.decode("utf-8", errors="replace")
        returncode = 0
        parsed = True
        try:
            replies = json.loads(response)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            replies = None
            parsed = False
            returncode = 1
        if isinstance(replies, list) and any(
            isinstance(row, dict) and row.get("success") is False for row in replies
        ):
            returncode = 2
        completed = subprocess.CompletedProcess(argv, returncode, output, "")
        return completed, parsed and returncode == 0

    result = _benchmark_call(
        "staff.act ipc command", exchange,
        success=lambda value: isinstance(value, tuple) and len(value) == 2 and value[1] is True,
    )
    return result[0]


def focus(payload: dict[str, Any]) -> Mapping[str, Any]:
    direction = _require_string(payload, "direction", "face-focus-direction-required")
    if direction not in {"next", "prev"}:
        raise FaceError("face-focus-direction-invalid")
    environment, socket_source = owner_session_environment(
        discover=True, require_sway=True, prefer_direct_keys=("SWAYSOCK",),
    )
    tree = _sway_json("get_tree", environment)
    workspaces = _sway_json("get_workspaces", environment)
    outputs = _sway_json("get_outputs", environment)
    if not isinstance(workspaces, list) or not isinstance(outputs, list) or not isinstance(tree, dict):
        raise FaceError("swaymsg-response-shape-invalid")
    workspace_by_name = {row.get("name"): row for row in workspaces if isinstance(row, dict) and isinstance(row.get("name"), str)}
    active_outputs = {row.get("name") for row in outputs if isinstance(row, dict) and row.get("active") is True and isinstance(row.get("name"), str)}
    windows: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], workspace: str | None = None, output: str | None = None) -> None:
        kind = node.get("type")
        if kind == "output":
            output = node.get("name") if isinstance(node.get("name"), str) else None
        elif kind == "workspace":
            workspace = node.get("name") if isinstance(node.get("name"), str) else None
        children = list(node.get("nodes") or []) + list(node.get("floating_nodes") or [])
        if kind == "con" and not children:
            props = node.get("window_properties") or {}
            app_id = node.get("app_id") or ""
            window_class = props.get("class") or ""
            row = workspace_by_name.get(workspace)
            scratch = node.get("scratchpad_state") not in (None, "", "none")
            is_client = bool(app_id or window_class or node.get("window") is not None)
            hidden_here = bool(row and row.get("visible") is True and node.get("visible") is False)
            con_id = node.get("id")
            if row and output in active_outputs and is_client and not scratch and not hidden_here and type(con_id) is int:
                number = row.get("num", -1)
                if type(number) is not int or number < 0:
                    number = 2**31 - 1
                rect = node.get("rect") or {}
                y, x = rect.get("y", 0), rect.get("x", 0)
                windows.append({
                    "id": con_id, "workspace": workspace, "workspace_num": number,
                    "output": output, "y": y if type(y) is int else 0,
                    "x": x if type(x) is int else 0, "focused": node.get("focused") is True,
                })
        for child in children:
            if isinstance(child, dict):
                walk(child, workspace, output)

    walk(tree)
    windows.sort(key=lambda row: (row["workspace_num"], row["workspace"], row["output"], row["y"], row["x"], row["id"]))
    if not windows:
        return {
            "ok": True, "firstMissingSignal": "none", "changed": False,
            "target": None, "socket_source": socket_source,
        }
    active_index = next((i for i, row in enumerate(windows) if row["focused"]), -1)
    if direction == "next":
        index = (active_index + 1) % len(windows)
    else:
        index = (active_index - 1) % len(windows) if active_index >= 0 else len(windows) - 1
    target = windows[index]
    actions = (
        f"focus output {json.dumps(target['output'])}",
        f"workspace {json.dumps(target['workspace'])}",
        f'[con_id="{target["id"]}"] focus',
    )
    for action in actions:
        result = _sway_command(action, environment)
        if result.returncode != 0:
            raise FaceError(
                "swaymsg-focus-failed", target=target,
                socket_source=socket_source,
            )
    return {
        "ok": True, "firstMissingSignal": "none", "changed": True,
        "target": target, "socket_source": socket_source,
    }


def workspace(payload: dict[str, Any]) -> Mapping[str, Any]:
    direction = _require_string(payload, "direction", "face-workspace-direction-required")
    if direction not in {"prev", "next"}:
        raise FaceError("face-workspace-direction-invalid")
    carry = payload.get("carry")
    if carry is None:
        carry = False
    elif type(carry) is not bool:
        raise FaceError("face-workspace-carry-invalid")
    ring = payload.get("ring")
    if ring is None:
        ring = []
    elif not isinstance(ring, list) or any(type(number) is not int for number in ring):
        raise FaceError("face-workspace-ring-invalid")
    ring = sorted(set(ring))
    environment, socket_source = owner_session_environment(
        discover=True, require_sway=True, prefer_direct_keys=("SWAYSOCK",),
    )
    workspaces = _sway_json("get_workspaces", environment)
    if not isinstance(workspaces, list):
        raise FaceError("face-workspace-workspaces-shape-invalid")
    focused = next((row for row in workspaces if isinstance(row, dict) and row.get("focused") is True), None)
    if focused is None:
        raise FaceError("face-workspace-focused-missing")
    previous = focused.get("num")
    if type(previous) is not int:
        raise FaceError("face-workspace-focused-num-invalid")
    ring = sorted(set(ring).union(
        row["num"] for row in workspaces
        if isinstance(row, dict) and type(row.get("num")) is int and row["num"] > 0
    ))
    if not ring:
        raise FaceError(
            "face-workspace-ring-empty", previous=previous, ring=ring,
            carry=carry, socket_source=socket_source,
        )
    try:
        index = ring.index(previous) if previous != -1 else 0
    except ValueError:
        index = 0
    offset = 1 if direction == "next" else -1
    target = ring[(index + offset) % len(ring)]
    commands = (
        [f"move container to workspace number {target}, workspace number {target}"]
        if carry else [f"workspace number {target}"]
    )
    refusal_context = {
        "target": target, "previous": previous, "ring": ring,
        "carry": carry, "socket_source": socket_source,
    }
    for command in commands:
        result = _sway_command(command, environment, raw=True)
        if result.returncode != 0:
            signal = "swaymsg-workspace-move-failed" if carry else "swaymsg-workspace-focus-failed"
            raise FaceError(signal, **refusal_context)
        try:
            response = json.loads(result.stdout)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
            raise FaceError("swaymsg-workspace-response-invalid", **refusal_context)
        if not isinstance(response, list) or not response or any(not isinstance(row, dict) for row in response):
            raise FaceError("swaymsg-workspace-response-invalid", **refusal_context)
        if any(row.get("success") is False or row.get("parse_error") is True for row in response):
            raise FaceError("swaymsg-workspace-command-refused", **refusal_context)
        if any(row.get("success") is not True for row in response):
            raise FaceError("swaymsg-workspace-response-invalid", **refusal_context)
    return {
        "ok": True, "firstMissingSignal": "none", "target": target,
        "previous": previous, "ring": ring, "carry": carry,
        "socket_source": socket_source,
    }


def fetch(payload: dict[str, Any]) -> Mapping[str, Any]:
    environment, socket_source = owner_session_environment(
        discover=True, require_sway=True, prefer_direct_keys=("SWAYSOCK",),
    )
    workspaces = _sway_json("get_workspaces", environment)
    if not isinstance(workspaces, list):
        raise FaceError("swaymsg-workspaces-shape-invalid")
    current = next((row for row in workspaces if isinstance(row, dict) and row.get("focused") is True), None)
    if current is None or not isinstance(current.get("name"), str):
        raise FaceError("sway-focused-workspace-missing")
    current_name = current["name"]
    workspace_names = {row.get("name") for row in workspaces if isinstance(row, dict) and isinstance(row.get("name"), str)}
    tree = _sway_json("get_tree", environment)
    if not isinstance(tree, dict):
        raise FaceError("swaymsg-tree-shape-invalid")
    windows: list[int] = []

    def walk(node: dict[str, Any], workspace: str | None = None) -> None:
        if node.get("type") == "workspace":
            workspace = node.get("name") if isinstance(node.get("name"), str) else None
        children = list(node.get("nodes") or []) + list(node.get("floating_nodes") or [])
        if node.get("type") == "con" and not children:
            props = node.get("window_properties") or {}
            app_id = node.get("app_id") or ""
            window_class = props.get("class") or ""
            scratch = node.get("scratchpad_state") not in (None, "", "none")
            is_client = bool(app_id or window_class or node.get("window") is not None)
            con_id = node.get("id")
            if workspace in workspace_names and workspace != current_name and is_client and not scratch and type(con_id) is int:
                windows.append(con_id)
        for child in children:
            if isinstance(child, dict):
                walk(child, workspace)

    walk(tree)
    moved: list[int] = []
    failure: str | None = None
    try:
        for con_id in windows:
            selector = f'[con_id="{con_id}"] move container to workspace {json.dumps(current_name)}'
            result = _sway_command(selector, environment)
            if result.returncode != 0:
                failure = "swaymsg-move-failed"
                break
            moved.append(con_id)
    finally:
        refocus = _sway_command(f"workspace {json.dumps(current_name)}", environment)
    if failure:
        raise FaceError(
            failure, moved_count=len(moved), requested_count=len(windows),
            refocus_ok=refocus.returncode == 0, socket_source=socket_source,
        )
    if refocus.returncode != 0:
        raise FaceError(
            "swaymsg-refocus-failed", moved_count=len(moved),
            requested_count=len(windows), socket_source=socket_source,
        )
    return {
        "ok": True, "firstMissingSignal": "none", "moved_count": len(moved),
        "requested_count": len(windows), "current_workspace": current_name,
        "socket_source": socket_source,
    }


def launch(payload: dict[str, Any]) -> Mapping[str, Any]:
    desktop_id = payload.get("desktop_id")
    menu = payload.get("menu")
    if desktop_id is not None:
        if menu is not None or not isinstance(desktop_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.desktop", desktop_id):
            raise FaceError("face-launch-desktop-id-invalid")
        home = Path(DEFAULT_OWNER_HOME)
        environment, socket_source = owner_session_environment(
            home=home, discover=True, require_wayland=True,
            prefer_direct_keys=("WAYLAND_DISPLAY",),
        )
        gtk_launch = _owner_utility("gtk-launch")
        if gtk_launch:
            argv = [gtk_launch, desktop_id[:-8] if desktop_id.endswith(".desktop") else desktop_id]
            launcher = "gtk-launch"
        else:
            gio = _owner_utility("gio")
            if not gio:
                raise FaceError("face-launch-utility-missing")
            candidates = [
                home / ".local/share/applications",
                Path("/usr/local/share/applications"),
                Path("/usr/share/applications"),
            ]
            app_path = None
            for directory in candidates:
                try:
                    candidate = directory / desktop_id
                    if candidate.is_file() and not candidate.is_symlink():
                        app_path = candidate
                        break
                except OSError:
                    continue
            if app_path is None:
                raise FaceError("face-launch-desktop-id-not-found")
            argv = [gio, "launch", str(app_path)]
            launcher = "gio"
    else:
        if menu not in (None, True):
            raise FaceError("face-launch-menu-invalid")
        home = Path(DEFAULT_OWNER_HOME)
        environment, socket_source = owner_session_environment(
            home=home, discover=True, require_wayland=True,
            prefer_direct_keys=("WAYLAND_DISPLAY",),
        )
        argv = [
            "wofi", "--show", "drun", "--conf", str(home / ".config/wofi/config"),
            "--style", str(home / ".config/wofi/style.css"),
            "--cache-file", str(home / ".local/state/hometv-launcher/wofi-drun-cache"),
            "--sort-order", "default", "--allow-images", "--parse-search", "--no-custom-entry",
        ]
        launcher = "wofi"
    process, exit_code = owner_spawn(argv, environment)
    return {
        "ok": True, "firstMissingSignal": "none", "launched": True,
        "detached": True, "launcher": launcher, "pid": process.pid,
        "early_exit": exit_code, "socket_source": socket_source,
    }


_SCREENSHOT_CAPTURE_NAME = "agathodaimon-face-screenshot.png"
_SCREENSHOT_CREATE_CAPTURE = """
import os, stat, sys
path = sys.argv[1]
fd = os.open(path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
        raise SystemExit(74)
    os.fchmod(fd, 0o600)
finally:
    os.close(fd)
"""
_SCREENSHOT_TRUNCATE_CAPTURE = """
import os, stat, sys
path = sys.argv[1]
fd = os.open(path, os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_nlink != 1:
        raise SystemExit(74)
    os.fchmod(fd, 0o600)
    os.ftruncate(fd, 0)
finally:
    os.close(fd)
"""
_SCREENSHOT_SATTY_WAITER = r'''
import os, stat, subprocess, sys
satty, capture, uid, lock_fd = sys.argv[1:]
uid = int(uid)
lock_fd = int(lock_fd)
metadata = os.fstat(lock_fd)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
    raise SystemExit(70)
result = subprocess.run(
    [satty, "-f", capture], stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    close_fds=True, check=False,
)
raise SystemExit(result.returncode)
'''
_SCREENSHOT_SWAPPY_WAITER = r'''
import os, pathlib, stat, subprocess, sys
capture, swappy, pictures_home, wl_paste, notify_send, uid, lock_fd = sys.argv[1:]
uid = int(uid)
lock_fd = int(lock_fd)
metadata = os.fstat(lock_fd)
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid:
    raise SystemExit(70)
original = sys.stdin.buffer.read()
home = pathlib.Path(pictures_home)
screenshots = home / "Pictures" / "Screenshots"

def files_now():
    for directory in (home, home / "Pictures", screenshots):
        try:
            item = os.lstat(directory)
        except FileNotFoundError:
            return {}
        except OSError:
            return None
        if stat.S_ISLNK(item.st_mode) or not stat.S_ISDIR(item.st_mode) or item.st_uid != uid:
            return None
    result = {}
    try:
        with os.scandir(screenshots) as entries:
            for entry in entries:
                try:
                    item = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISREG(item.st_mode) and item.st_uid == uid:
                    result[entry.name] = item.st_mtime_ns
    except OSError:
        return None
    return result

before = files_now()
try:
    editor = subprocess.Popen(
        [swappy, "-f", capture], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
except OSError:
    raise SystemExit(71)
editor.wait()
after = files_now()
saved = None
if before is not None and after is not None:
    added = [name for name in after if name not in before]
    if added:
        saved = max(added, key=lambda name: after[name])

def clipboard_changed():
    if not wl_paste:
        return False
    try:
        reader = subprocess.Popen(
            [wl_paste, "--type", "image/png"], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        )
    except OSError:
        return False
    offset = 0
    changed = False
    try:
        while True:
            chunk = reader.stdout.read(65536)
            if not chunk:
                break
            if offset + len(chunk) > len(original) or original[offset:offset + len(chunk)] != chunk:
                changed = True
            offset += len(chunk)
        return reader.wait(timeout=8) == 0 and (changed or offset != len(original))
    except (OSError, subprocess.SubprocessError):
        try:
            reader.kill()
        except OSError:
            pass
        return False

def notify(message):
    if not notify_send or not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        return
    try:
        subprocess.run(
            [notify_send, message],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=3, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass

if saved is not None:
    safe_name = "".join(character for character in saved if character.isprintable())[:180]
    notify("Saved " + safe_name)
elif clipboard_changed():
    notify("Copied to clipboard")
'''


def _screenshot_process_environments(account: pwd.struct_passwd) -> list[tuple[str, str, dict[str, str]]]:
    found: list[tuple[str, str, dict[str, str]]] = []
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return found
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != account.pw_uid:
                continue
            comm = (entry / "comm").read_text(encoding="utf-8").strip().lower()
            command = (entry / "cmdline").read_bytes().split(b"\x00", 1)[0].decode("utf-8", "replace")
            name = Path(command).name.lower()
            compositor = "sway" if comm == "sway" or name == "sway" else (
                "hyprland" if comm == "hyprland" or name == "hyprland" else None
            )
            if compositor is None:
                continue
            raw = (entry / "environ").read_bytes()
        except OSError:
            continue
        values: dict[str, str] = {}
        for item in raw.split(b"\x00"):
            key, separator, value = item.partition(b"=")
            if not separator:
                continue
            try:
                values[key.decode("ascii")] = value.decode("utf-8")
            except UnicodeError:
                continue
        found.append((entry.name, compositor, values))
    return found


def _screenshot_systemd_environment(
    account: pwd.struct_passwd, runtime: Path,
) -> dict[str, str]:
    systemctl = shutil.which("systemctl", path=os.environ.get("PATH", os.defpath))
    if systemctl is None:
        return {}
    environment = {
        "HOME": account.pw_dir, "USER": OWNER_USER, "LOGNAME": OWNER_USER,
        "PATH": os.environ.get("PATH", os.defpath), "XDG_RUNTIME_DIR": str(runtime),
    }
    bus = runtime / "bus"
    if _is_live_owned_socket(bus, account, runtime):
        environment["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    result = owner_run([systemctl, "--user", "show-environment"], environment, timeout=3)
    if result.returncode != 0:
        return {}
    values: dict[str, str] = {}
    allowed = {
        "PATH", "SWAYSOCK", "WAYLAND_DISPLAY", "HYPRLAND_INSTANCE_SIGNATURE",
        "DBUS_SESSION_BUS_ADDRESS",
    }
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key in allowed:
            values[key] = value
    return values


def _screenshot_safe_runtime(account: pwd.struct_passwd) -> Path:
    runtime = _runtime_dir(account)
    try:
        metadata = os.lstat(runtime)
    except OSError:
        raise FaceError("face-screenshot-runtime-directory-unavailable")
    if (
        stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != account.pw_uid or metadata.st_mode & 0o077
    ):
        raise FaceError("face-screenshot-runtime-directory-unsafe")
    return runtime


def _screenshot_unique_value(
    observations: Sequence[tuple[str, str]], key: str, *, source: str,
) -> tuple[str, str] | None:
    unique: dict[str, str] = {}
    for origin, value in observations:
        if value and "\x00" not in value:
            unique.setdefault(value, origin)
    if len(unique) > 1:
        raise FaceError(f"face-screenshot-{key.lower().replace('_', '-')}-ambiguous")
    if not unique:
        return None
    value, origin = next(iter(unique.items()))
    return value, origin if origin else source


def _screenshot_runtime_socket(
    value: str, key: str, account: pwd.struct_passwd, runtime: Path,
) -> Path | None:
    path = _socket_path(value, runtime)
    if path is None or not _is_live_owned_socket(path, account, runtime):
        return None
    return path


def _screenshot_external_socket(path: str, account: pwd.struct_passwd, runtime: Path) -> bool:
    candidate = Path(path)
    if not candidate.is_absolute() or "\x00" in path or any(part in {".", ".."} for part in candidate.parts):
        return False
    try:
        parts = candidate.parts
        current = Path(parts[0])
        for part in parts[1:-1]:
            current = current / part
            metadata = os.lstat(current)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return False
            if current == runtime or runtime in current.parents:
                if metadata.st_uid != account.pw_uid:
                    return False
            if metadata.st_mode & 0o002 and not metadata.st_mode & stat.S_ISVTX:
                return False
        metadata = os.lstat(candidate)
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != account.pw_uid:
            return False
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        probe.settimeout(0.25)
        try:
            probe.connect(str(candidate))
        finally:
            probe.close()
        return True
    except (OSError, ValueError):
        return False


def _screenshot_bus_path(value: str) -> str | None:
    first = value.split(";", 1)[0].split(",", 1)[0]
    if not first.startswith("unix:path="):
        return None
    path = first[len("unix:path="):]
    return path if path and Path(path).is_absolute() else None


def _screenshot_owner_environment(
    *, window: bool,
) -> tuple[dict[str, str], str, pwd.struct_passwd, Path]:
    account = _owner()
    runtime = _screenshot_safe_runtime(account)
    process_environments = _screenshot_process_environments(account)
    systemd_environment = _screenshot_systemd_environment(account, runtime)

    wayland_observations = [
        (f"proc:{pid}", values["WAYLAND_DISPLAY"])
        for pid, _compositor, values in process_environments
        if values.get("WAYLAND_DISPLAY")
        and _screenshot_runtime_socket(values["WAYLAND_DISPLAY"], "WAYLAND_DISPLAY", account, runtime)
    ]
    wayland = _screenshot_unique_value(wayland_observations, "WAYLAND_DISPLAY", source="proc")
    if wayland is None:
        value = systemd_environment.get("WAYLAND_DISPLAY", "")
        if value and _screenshot_runtime_socket(value, "WAYLAND_DISPLAY", account, runtime):
            wayland = (value, "systemd-user")
    if wayland is None:
        candidates = _runtime_socket_candidates("WAYLAND_DISPLAY", account, runtime)
        if len(candidates) > 1:
            raise FaceError("face-screenshot-wayland-display-ambiguous")
        if candidates:
            wayland = (candidates[0].name, "runtime-unique")
    if wayland is None:
        raise FaceError("face-screenshot-wayland-display-unavailable")

    session_records = [
        record for record in process_environments
        if record[2].get("WAYLAND_DISPLAY") == wayland[0]
    ]
    path_observations = [
        (f"proc:{pid}", values["PATH"])
        for pid, _compositor, values in session_records if values.get("PATH")
    ]
    owner_path_value = None
    if any(record[1] == "sway" for record in session_records):
        owner_path_value = _screenshot_unique_value(path_observations, "OWNER_PATH", source="proc")
    if owner_path_value is None and systemd_environment.get("PATH"):
        owner_path_value = (systemd_environment["PATH"], "systemd-user")
    if owner_path_value is None:
        owner_path_value = _screenshot_unique_value(path_observations, "OWNER_PATH", source="proc")
    if owner_path_value is None:
        raise FaceError("face-screenshot-owner-path-unavailable")
    owner_path, path_source = owner_path_value
    path_entries = owner_path.split(os.pathsep)
    if not owner_path or any(not entry or not Path(entry).is_absolute() for entry in path_entries):
        raise FaceError("face-screenshot-owner-path-invalid")

    environment = {
        "HOME": account.pw_dir, "USER": OWNER_USER, "LOGNAME": OWNER_USER,
        "PATH": owner_path, "XDG_RUNTIME_DIR": str(runtime),
        "XDG_CONFIG_HOME": str(Path(account.pw_dir) / ".config"),
        "XDG_CACHE_HOME": str(Path(account.pw_dir) / ".cache"),
        "XDG_STATE_HOME": str(Path(account.pw_dir) / ".local/state"),
        "WAYLAND_DISPLAY": wayland[0],
    }
    source_parts = [f"wayland:{wayland[1]}", f"path:{path_source}"]

    compositor_records = [record for record in session_records if record[1] in {"sway", "hyprland"}]
    bus_observations: list[tuple[str, str]] = []
    for pid, _compositor, values in compositor_records:
        address = values.get("DBUS_SESSION_BUS_ADDRESS", "")
        path = _screenshot_bus_path(address) if address else None
        if path and _screenshot_external_socket(path, account, runtime):
            bus_observations.append((f"proc:{pid}", address))
    bus = _screenshot_unique_value(bus_observations, "DBUS_SESSION_BUS_ADDRESS", source="proc")
    if bus is None:
        address = systemd_environment.get("DBUS_SESSION_BUS_ADDRESS", "")
        path = _screenshot_bus_path(address) if address else None
        if path and _screenshot_external_socket(path, account, runtime):
            bus = (address, "systemd-user")
    if bus is not None:
        environment["DBUS_SESSION_BUS_ADDRESS"] = bus[0]
        source_parts.append(f"dbus:{bus[1]}")

    if window:
        sway_observations = [
            (f"proc:{pid}", values["SWAYSOCK"])
            for pid, compositor, values in process_environments
            if compositor == "sway" and values.get("SWAYSOCK")
            and _screenshot_runtime_socket(values["SWAYSOCK"], "SWAYSOCK", account, runtime)
        ]
        sway = _screenshot_unique_value(sway_observations, "SWAYSOCK", source="proc")
        if sway is None:
            value = systemd_environment.get("SWAYSOCK", "")
            if value and _screenshot_runtime_socket(value, "SWAYSOCK", account, runtime):
                sway = (value, "systemd-user")
        if sway is None:
            candidates = _runtime_socket_candidates("SWAYSOCK", account, runtime)
            if len(candidates) > 1:
                raise FaceError("face-screenshot-sway-socket-ambiguous")
            if candidates:
                sway = (str(candidates[0]), "runtime-unique")
        if sway is not None:
            path = _screenshot_runtime_socket(sway[0], "SWAYSOCK", account, runtime)
            environment["SWAYSOCK"] = str(path) if path is not None else sway[0]
            source_parts.append(f"sway:{sway[1]}")

        hypr_processes = [record for record in process_environments if record[1] == "hyprland"]
        hypr_observations = [
            (f"proc:{pid}", values["HYPRLAND_INSTANCE_SIGNATURE"])
            for pid, _compositor, values in hypr_processes
            if values.get("HYPRLAND_INSTANCE_SIGNATURE")
        ]
        hypr = _screenshot_unique_value(hypr_observations, "HYPRLAND_INSTANCE_SIGNATURE", source="proc")
        manager_signature = systemd_environment.get("HYPRLAND_INSTANCE_SIGNATURE")
        if hypr is not None and manager_signature and manager_signature != hypr[0]:
            raise FaceError("face-screenshot-hyprland-instance-signature-ambiguous")
        if hypr is None and systemd_environment.get("HYPRLAND_INSTANCE_SIGNATURE"):
            hypr = (systemd_environment["HYPRLAND_INSTANCE_SIGNATURE"], "systemd-user")
        if hypr is not None:
            signature, signature_source = hypr
            if (
                len(signature) > 256 or signature in {".", ".."}
                or "/" in signature or "\\" in signature or "\x00" in signature
            ):
                raise FaceError("face-screenshot-hyprland-signature-invalid")
            hypr_root = runtime / "hypr"
            hypr_directory = hypr_root / signature
            try:
                root_metadata = os.lstat(hypr_root)
                directory_metadata = os.lstat(hypr_directory)
            except OSError:
                raise FaceError("face-screenshot-hyprland-signature-unavailable")
            if (
                stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode)
                or root_metadata.st_uid != account.pw_uid
                or stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode)
                or directory_metadata.st_uid != account.pw_uid
            ):
                raise FaceError("face-screenshot-hyprland-signature-unsafe")
            control_socket = hypr_directory / ".socket.sock"
            if not _is_live_owned_socket(control_socket, account, runtime):
                raise FaceError("face-screenshot-hyprland-signature-unavailable")
            environment["HYPRLAND_INSTANCE_SIGNATURE"] = signature
            source_parts.append(f"hyprland:{signature_source}")
        elif hypr_processes:
            raise FaceError("face-screenshot-hyprland-signature-unavailable")
        if sway is None and hypr is None:
            raise FaceError("face-screenshot-window-compositor-unavailable")
        if sway is not None and hypr is not None:
            raise FaceError("face-screenshot-window-compositor-ambiguous")

    return environment, ";".join(source_parts), account, runtime


def _screenshot_utility(name: str, owner_path: str) -> str | None:
    utility = shutil.which(name, path=owner_path)
    if utility is None:
        return None
    try:
        metadata = os.stat(utility)
    except OSError:
        return None
    return utility if stat.S_ISREG(metadata.st_mode) and os.access(utility, os.X_OK) else None


def _screenshot_prepare_capture(
    path: Path, environment: Mapping[str, str], python: str,
) -> int:
    prepared = owner_run([python, "-c", _SCREENSHOT_CREATE_CAPTURE, str(path)], environment)
    if prepared.returncode != 0:
        raise FaceError("face-screenshot-capture-file-create-failed")
    try:
        fd = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise FaceError("face-screenshot-capture-file-open-failed")
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != _owner().pw_uid
            or metadata.st_nlink != 1 or metadata.st_mode & 0o077
        ):
            raise FaceError("face-screenshot-capture-file-unsafe")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise FaceError("face-screenshot-capture-busy")
        reset = owner_run([python, "-c", _SCREENSHOT_TRUNCATE_CAPTURE, str(path)], environment)
        if reset.returncode != 0:
            raise FaceError("face-screenshot-capture-reset-failed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _screenshot_capture_bytes(path: Path, fd: int, account: pwd.struct_passwd) -> bytes:
    try:
        path_metadata = os.lstat(path)
        metadata = os.fstat(fd)
        if (
            stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISREG(path_metadata.st_mode)
            or path_metadata.st_uid != account.pw_uid or metadata.st_ino != path_metadata.st_ino
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != account.pw_uid
            or metadata.st_nlink != 1 or metadata.st_mode & 0o077 or metadata.st_size <= 0
        ):
            raise FaceError("face-screenshot-capture-file-unsafe")
        os.lseek(fd, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                raise FaceError("face-screenshot-capture-read-failed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    except FaceError:
        raise
    except OSError:
        raise FaceError("face-screenshot-capture-read-failed")


def _screenshot_owner_run_bytes(
    argv: Sequence[str], environment: Mapping[str, str], payload: bytes,
) -> subprocess.CompletedProcess[bytes]:
    command, outer = owner_session_command(argv, environment)
    try:
        return subprocess.run(
            command, input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=12, check=False, env=outer,
        )
    except (OSError, subprocess.SubprocessError) as error:
        return subprocess.CompletedProcess(command, 127, b"", type(error).__name__.encode())


def _screenshot_spawn_with_fd(
    argv: Sequence[str], environment: Mapping[str, str], capture_fd: int,
    *, input_bytes: bytes | None = None,
) -> tuple[subprocess.Popen, int | None]:
    command, outer = owner_session_command(argv, environment)
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, env=outer, pass_fds=(capture_fd,),
        )
    except OSError:
        raise FaceError("face-screenshot-editor-launch-failed")
    if input_bytes is not None:
        try:
            assert process.stdin is not None
            process.stdin.write(input_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            try:
                process.terminate()
                process.wait(timeout=1)
            except (OSError, subprocess.SubprocessError):
                pass
            raise FaceError("face-screenshot-waiter-input-failed")
    time.sleep(0.05)
    exit_code = process.poll()
    if exit_code not in (None, 0):
        raise FaceError("face-screenshot-editor-launch-failed", exit=exit_code)
    return process, exit_code


def _screenshot_geometry_from_rect(rect: Any, signal: str) -> str:
    if not isinstance(rect, Mapping):
        raise FaceError(signal)
    x, y, width, height = (rect.get(key) for key in ("x", "y", "width", "height"))
    if (
        type(x) is not int or type(y) is not int or type(width) is not int or type(height) is not int
        or width <= 0 or height <= 0
    ):
        raise FaceError(signal)
    return f"{x},{y} {width}x{height}"


def _screenshot_sway_geometry(environment: Mapping[str, str]) -> str:
    tree = _sway_json("get_tree", environment)
    if not isinstance(tree, Mapping):
        raise FaceError("face-screenshot-sway-tree-invalid")
    focused: list[Mapping[str, Any]] = []

    def visit(node: Mapping[str, Any]) -> None:
        children = list(node.get("nodes") or []) + list(node.get("floating_nodes") or [])
        if node.get("focused") is True and node.get("type") == "con" and not children:
            focused.append(node)
        for child in children:
            if isinstance(child, Mapping):
                visit(child)

    visit(tree)
    if len(focused) != 1:
        raise FaceError("face-screenshot-sway-focused-window-ambiguous")
    return _screenshot_geometry_from_rect(focused[0].get("rect"), "face-screenshot-sway-focused-rect-invalid")


def _screenshot_hypr_geometry(environment: Mapping[str, str], hyprctl: str) -> str:
    result = owner_run([hyprctl, "activewindow", "-j"], environment)
    if result.returncode != 0:
        raise FaceError("face-screenshot-hyprland-activewindow-failed")
    try:
        active = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError, RecursionError):
        raise FaceError("face-screenshot-hyprland-activewindow-invalid")
    if not isinstance(active, Mapping):
        raise FaceError("face-screenshot-hyprland-activewindow-invalid")
    at, size = active.get("at"), active.get("size")
    if (
        not isinstance(at, list) or len(at) != 2 or not isinstance(size, list) or len(size) != 2
        or any(type(value) is not int for value in (*at, *size)) or size[0] <= 0 or size[1] <= 0
    ):
        raise FaceError("face-screenshot-hyprland-activewindow-rect-invalid")
    return f"{at[0]},{at[1]} {size[0]}x{size[1]}"


def _screenshot_stop_process_group(process: subprocess.Popen[str]) -> None:
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except OSError:
        pass

    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            break
        except OSError:
            break
        remaining = deadline - time.monotonic()
        try:
            process.communicate(timeout=min(0.05, remaining))
        except subprocess.TimeoutExpired:
            pass
        except (OSError, subprocess.SubprocessError):
            break
        time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))

    try:
        os.killpg(process_group, 0)
    except ProcessLookupError:
        group_exists = False
    except OSError:
        group_exists = True
    else:
        group_exists = True
    if group_exists:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except OSError:
            pass

    try:
        process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except OSError:
            pass
        try:
            process.communicate(timeout=1)
        except subprocess.TimeoutExpired:
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    except (OSError, subprocess.SubprocessError):
        pass


def _screenshot_area_geometry(slurp: str, environment: Mapping[str, str]) -> str | None:
    command, outer = owner_session_command([slurp], environment)
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, start_new_session=True, env=outer,
        )
    except (OSError, subprocess.SubprocessError):
        raise FaceError("face-screenshot-slurp-failed", exit=127)
    try:
        stdout, stderr = process.communicate(timeout=100)
    except subprocess.TimeoutExpired:
        _screenshot_stop_process_group(process)
        raise FaceError("face-screenshot-slurp-timeout", timeout=100)
    except (OSError, subprocess.SubprocessError):
        _screenshot_stop_process_group(process)
        raise FaceError("face-screenshot-slurp-failed", exit=127)
    if process.returncode == 1 and stderr.strip() in ("", "selection cancelled"):
        return None
    if process.returncode != 0:
        raise FaceError("face-screenshot-slurp-failed", exit=process.returncode)
    match = re.fullmatch(r"\s*(-?\d+),(-?\d+)\s+(\d+)x(\d+)\s*", stdout)
    if match is None or int(match.group(3)) <= 0 or int(match.group(4)) <= 0:
        raise FaceError("face-screenshot-slurp-geometry-invalid")
    return f"{match.group(1)},{match.group(2)} {match.group(3)}x{match.group(4)}"


def screenshot(payload: dict[str, Any]) -> Mapping[str, Any]:
    raw_mode = payload["mode"] if "mode" in payload else "area"
    if not isinstance(raw_mode, str) or raw_mode not in {"area", "full", "window"}:
        raise FaceError(
            "face-screenshot-mode-invalid", mode=raw_mode if isinstance(raw_mode, str) else None,
            editor=None, captured=False,
        )
    mode = raw_mode
    editor_name: str | None = None
    captured = False
    try:
        environment, socket_source, account, runtime = _screenshot_owner_environment(window=mode == "window")
        owner_path = environment["PATH"]
        grim = _screenshot_utility("grim", owner_path)
        wl_copy = _screenshot_utility("wl-copy", owner_path)
        python = _screenshot_utility("python3", owner_path)
        if grim is None:
            raise FaceError("face-screenshot-grim-unavailable")
        if wl_copy is None:
            raise FaceError("face-screenshot-wl-copy-unavailable")
        if python is None:
            raise FaceError("face-screenshot-owner-python-unavailable")

        geometry: str | None = None
        if mode == "area":
            slurp = _screenshot_utility("slurp", owner_path)
            if slurp is None:
                raise FaceError("face-screenshot-slurp-unavailable")
            geometry = _screenshot_area_geometry(slurp, environment)
            if geometry is None:
                return {
                    "ok": True, "firstMissingSignal": "none", "mode": mode,
                    "editor": None, "captured": False, "cancelled": True,
                    "detached": False, "socket_source": socket_source,
                }
        elif mode == "window":
            if environment.get("SWAYSOCK"):
                geometry = _screenshot_sway_geometry(environment)
            else:
                hyprctl = _screenshot_utility("hyprctl", owner_path)
                if hyprctl is None:
                    raise FaceError("face-screenshot-hyprctl-unavailable")
                geometry = _screenshot_hypr_geometry(environment, hyprctl)

        satty = _screenshot_utility("satty", owner_path)
        swappy = _screenshot_utility("swappy", owner_path) if satty is None else None
        if satty is None and swappy is None:
            raise FaceError("face-screenshot-editor-unavailable")
        wl_paste = _screenshot_utility("wl-paste", owner_path) if swappy is not None else None
        notify_send = _screenshot_utility("notify-send", owner_path) if swappy is not None and environment.get("DBUS_SESSION_BUS_ADDRESS") else None
        if swappy is not None and wl_paste is None:
            raise FaceError("face-screenshot-wl-paste-unavailable")
        if swappy is not None and notify_send is None:
            raise FaceError("face-screenshot-notification-unavailable")

        capture_path = runtime / _SCREENSHOT_CAPTURE_NAME
        capture_fd = _screenshot_prepare_capture(capture_path, environment, python)
        try:
            if geometry is None:
                capture_argv = [grim, str(capture_path)]
            else:
                capture_argv = [grim, "-g", geometry, str(capture_path)]
            captured_result = owner_run(capture_argv, environment, timeout=15)
            if captured_result.returncode != 0:
                raise FaceError("face-screenshot-grim-failed", exit=captured_result.returncode)
            raw_capture = _screenshot_capture_bytes(capture_path, capture_fd, account)
            captured = True
            copied = _screenshot_owner_run_bytes([wl_copy, "--type", "image/png"], environment, raw_capture)
            if copied.returncode != 0:
                raise FaceError("face-screenshot-wl-copy-failed", captured=True, mode=mode)
            if satty is not None:
                editor_name = "satty"
                process, _exit_code = _screenshot_spawn_with_fd(
                    [
                        python, "-c", _SCREENSHOT_SATTY_WAITER,
                        satty, str(capture_path), str(account.pw_uid), str(capture_fd),
                    ], environment, capture_fd,
                )
                return {
                    "ok": True, "firstMissingSignal": "none", "mode": mode,
                    "editor": editor_name, "captured": True, "detached": True,
                    "pid": process.pid, "socket_source": socket_source,
                }
            if swappy is not None:
                editor_name = "swappy"
                waiter_argv = [
                    python, "-c", _SCREENSHOT_SWAPPY_WAITER,
                    str(capture_path), swappy, str(Path(account.pw_dir)),
                    wl_paste or "", notify_send or "", str(account.pw_uid), str(capture_fd),
                ]
                process, _exit_code = _screenshot_spawn_with_fd(
                    waiter_argv, environment, capture_fd, input_bytes=raw_capture,
                )
                return {
                    "ok": True, "firstMissingSignal": "none", "mode": mode,
                    "editor": editor_name, "captured": True, "detached": True,
                    "pid": process.pid, "socket_source": socket_source,
                }
            raise FaceError("face-screenshot-editor-unavailable", captured=True, mode=mode)
        except FaceError as error:
            error.fields.setdefault("mode", mode)
            error.fields.setdefault("editor", editor_name)
            error.fields.setdefault("captured", captured)
            raise
        finally:
            os.close(capture_fd)
    except FaceError as error:
        error.fields.setdefault("mode", mode)
        error.fields.setdefault("editor", editor_name)
        error.fields.setdefault("captured", captured)
        raise


def _pgrep(program: str, account: pwd.struct_passwd, environment: Mapping[str, str]) -> int:
    utility = _owner_utility("pgrep")
    if utility is None:
        raise FaceError("face-app-pgrep-unavailable")
    result = _root_process_run(
        [utility, "--exact", "--uid", str(account.pw_uid), "--", program],
        environment, action="pgrep",
    )
    if result.returncode not in (0, 1):
        raise FaceError("face-app-pgrep-failed")
    return result.returncode


@contextmanager
def _runtime_lock(name: str):
    account = _owner()
    runtime = _runtime_dir(account)
    try:
        directory_fd = os.open(runtime, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise FaceError("owner-runtime-directory-unavailable")
    metadata = os.fstat(directory_fd)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != account.pw_uid:
        os.close(directory_fd)
        raise FaceError("owner-runtime-directory-unsafe")
    created = False
    try:
        try:
            fd = os.open(name, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
            created = True
        except OSError:
            raise FaceError("face-runtime-lock-open-failed")
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(fd)
            raise FaceError("face-runtime-lock-unsafe")
        if created and os.geteuid() == 0:
            try:
                os.fchown(fd, account.pw_uid, account.pw_gid)
                os.fchmod(fd, 0o600)
            except OSError:
                os.close(fd)
                try:
                    os.unlink(name, dir_fd=directory_fd)
                except OSError:
                    pass
                raise FaceError("face-runtime-lock-custody-failed")
        elif metadata.st_uid != account.pw_uid:
            os.close(fd)
            raise FaceError("face-runtime-lock-owner-invalid")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
        except OSError:
            os.close(fd)
            raise FaceError("face-runtime-lock-acquire-failed")
        yield fd, runtime / name
    finally:
        try:
            if 'fd' in locals():
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
        finally:
            os.close(directory_fd)


def _lock_state(fd: int) -> bool:
    value = os.pread(fd, 16, 0)
    if value in (b"", b"0", b"0\n"):
        return False
    if value in (b"1", b"1\n"):
        return True
    raise FaceError("face-runtime-lock-state-invalid")


def _write_lock_state(fd: int, state: bool) -> None:
    try:
        os.ftruncate(fd, 0)
        os.pwrite(fd, b"1" if state else b"0", 0)
        os.fsync(fd)
    except OSError:
        raise FaceError("face-runtime-lock-write-failed")


def bar(payload: dict[str, Any]) -> Mapping[str, Any]:
    action = _require_string(payload, "action", "face-bar-action-required")
    if action != "toggle":
        raise FaceError("face-bar-action-invalid")
    account = _owner()
    environment, socket_source = owner_session_environment(discover=False)
    with _runtime_lock("agathodaimon-face-waybar-toggle.lock") as (fd, lock_path):
        prior = _lock_state(fd)
        utility = _owner_utility("pkill")
        if utility is None:
            raise FaceError("face-bar-pkill-unavailable", lock_path=str(lock_path))
        result = _root_process_run(
            [utility, "--signal", "USR1", "--exact", "--uid", str(account.pw_uid), "--", "waybar"],
            environment, action="pkill",
        )
        if result.returncode != 0:
            raise FaceError(
                "face-bar-signal-failed", lock_path=str(lock_path),
                socket_source=socket_source,
            )
        _write_lock_state(fd, not prior)
    return {
        "ok": True, "firstMissingSignal": "none", "changed": True,
        "lock_path": str(lock_path), "hidden": not prior,
        "socket_source": socket_source,
    }


def app(payload: dict[str, Any]) -> Mapping[str, Any]:
    program = _require_string(payload, "id", "face-app-id-required")
    action = _require_string(payload, "action", "face-app-action-required")
    if len(program) > 128 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", program):
        raise FaceError("face-app-id-invalid")
    if action != "toggle":
        raise FaceError("face-app-action-invalid")
    account = _owner()
    environment, socket_source = owner_session_environment(discover=False)
    lock_name = f"agathodaimon-face-app-{program}.lock"
    with _runtime_lock(lock_name) as (fd, lock_path):
        marked = _lock_state(fd)
        running = _pgrep(program, account, environment) == 0 if marked else False
        if marked and running:
            utility = _owner_utility("pkill")
            if utility is None:
                raise FaceError("face-app-pkill-unavailable", lock_path=str(lock_path))
            result = _root_process_run(
                [utility, "--exact", "--uid", str(account.pw_uid), "--", program],
                environment, action="pkill",
            )
            stopped = False
            for attempt in range(10):
                if _pgrep(program, account, environment) == 1:
                    stopped = True
                    break
                if attempt < 9:
                    time.sleep(0.1)
            if not stopped:
                raise FaceError(
                    "face-app-stop-failed", lock_path=str(lock_path),
                    socket_source=socket_source, signal_exit=result.returncode,
                    running=True,
                )
            _write_lock_state(fd, False)
            return {
                "ok": True, "firstMissingSignal": "none", "changed": True,
                "program": program, "running": False, "lock_path": str(lock_path),
                "socket_source": socket_source,
            }
        if marked:
            # Recover a stale marker before restarting so failures stay inactive.
            _write_lock_state(fd, False)
        environment, socket_source = owner_session_environment(
            discover=True,
            prefer_direct_keys=("WAYLAND_DISPLAY",),
        )
        process, exit_code = owner_spawn([program], environment)
        post_launch = _pgrep(program, account, environment)
        if post_launch != 0:
            _write_lock_state(fd, False)
            raise FaceError(
                "face-app-process-not-observed", program=program, launched=True,
                running=False, pid=process.pid, early_exit=exit_code,
                lock_path=str(lock_path), socket_source=socket_source,
            )
        _write_lock_state(fd, True)
        return {
            "ok": True, "firstMissingSignal": "none", "changed": True,
            "program": program, "running": True, "pid": process.pid,
            "lock_path": str(lock_path), "socket_source": socket_source,
        }


def _volume_owner_switch() -> None:
    account = _owner()
    if account.pw_uid == 0:
        raise FaceError("owner-session-identity-refused")
    if os.geteuid() == account.pw_uid:
        return
    try:
        os.initgroups(OWNER_USER, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
        if hasattr(os, "getresuid") and hasattr(os, "getresgid"):
            uids = os.getresuid()
            gids = os.getresgid()
        else:
            uids = (os.getuid(), os.geteuid())
            gids = (os.getgid(), os.getegid())
    except Exception:
        raise FaceError("owner-session-identity-refused") from None
    if any(uid != account.pw_uid for uid in uids) or any(gid != account.pw_gid for gid in gids):
        raise FaceError("owner-session-identity-refused")


def volume(payload: dict[str, Any]) -> Mapping[str, Any]:
    step = _require_string(payload, "step", "face-volume-step-required")
    if step not in {"+5", "-5", "mute"}:
        raise FaceError("face-volume-step-invalid")
    environment, socket_source = owner_session_environment(discover=True, enter_owner=True)
    pactl = _owner_utility("pactl")
    if pactl is None:
        raise FaceError("face-volume-pactl-unavailable", socket_source=socket_source)
    default = owner_run([pactl, "get-default-sink"], environment)
    sink = default.stdout.strip() if default.returncode == 0 else ""
    if not sink:
        listed = owner_run([pactl, "list", "short", "sinks"], environment)
        if listed.returncode == 0:
            for line in listed.stdout.splitlines():
                columns = line.split()
                if len(columns) > 1 and "hdmi" in line:
                    sink = columns[1]
                    break
    if not sink:
        raise FaceError("face-volume-sink-unavailable", socket_source=socket_source)
    commands = []
    if step == "+5":
        commands = [[pactl, "set-sink-mute", sink, "0"], [pactl, "set-sink-volume", sink, "+5%"]]
    elif step == "-5":
        commands = [[pactl, "set-sink-volume", sink, "-5%"]]
    else:
        commands = [[pactl, "set-sink-mute", sink, "toggle"]]
    for command in commands:
        result = owner_run(command, environment)
        if result.returncode != 0:
            raise FaceError("face-volume-change-failed", sink=sink, socket_source=socket_source)
    observed = owner_run([pactl, "list", "sinks"], environment)
    if observed.returncode != 0:
        raise FaceError("face-volume-readback-failed", sink=sink, socket_source=socket_source)
    in_sink = False
    mute: bool | None = None
    level: int | None = None
    for line in observed.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("Name:"):
            in_sink = stripped.split(":", 1)[1].strip() == sink
            continue
        if not in_sink:
            continue
        if stripped.startswith("Mute:") and mute is None:
            mute_value = stripped.split(":", 1)[1].strip().lower()
            if mute_value not in {"yes", "no"}:
                raise FaceError("face-volume-mute-readback-invalid", sink=sink, socket_source=socket_source)
            mute = mute_value == "yes"
        if stripped.startswith("Volume:") and level is None:
            match = re.search(r"(\d+)%", stripped)
            if match:
                level = int(match.group(1))
        if stripped.startswith("Formats:"):
            break
    if mute is None or level is None:
        raise FaceError("face-volume-readback-invalid", sink=sink, socket_source=socket_source)
    notify = {"available": False, "ok": None}
    dunstify = _owner_utility("dunstify")
    if dunstify is not None:
        notify_value = 0 if mute else level
        notify_text = "Muted" if mute else f"{level}%"
        notified = _benchmark_call(
            "staff.notify",
            lambda: owner_run([
                dunstify, "--app-name=volume", "--replace-id=91190", "--stack-tag=volume",
                "--urgency=low", "--expire-time=1200", f"--hint=int:value:{notify_value}",
                "Volume", notify_text,
            ], environment, timeout=5),
            success=lambda result: isinstance(result, subprocess.CompletedProcess) and result.returncode == 0,
        )
        notify = {"available": True, "ok": notified.returncode == 0}
    return {"ok": True, "firstMissingSignal": "none", "sink": sink, "level": level, "mute": mute, "notification": notify, "socket_source": socket_source}


def _bars(pct: int) -> str:
    filled = max(0, min(4, (int(pct) + 24) // 25))
    return "▰" * filled + "▱" * (4 - filled)


def _class_for(pct: int) -> str:
    if pct >= 85:
        return "high"
    if pct >= 60:
        return "medium"
    return "low"


def _cpu_percent() -> int:
    def sample() -> tuple[int, int]:
        try:
            fields = Path("/proc/stat").read_text(encoding="ascii").splitlines()[0].split()
            values = [int(item) for item in fields[1:9]]
        except (OSError, IndexError, ValueError):
            raise FaceError("face-meter-cpu-observation-failed")
        if len(values) != 8:
            raise FaceError("face-meter-cpu-observation-invalid")
        user, nice, system, idle, iowait, irq, softirq, steal = values
        return sum(values), idle + iowait
    total1, idle1 = sample()
    time.sleep(0.25)
    total2, idle2 = sample()
    delta_total = total2 - total1
    delta_idle = idle2 - idle1
    return (100 * (delta_total - delta_idle) // delta_total) if delta_total > 0 else 0


def _run_text(argv: Sequence[str], signal: str) -> str:
    try:
        result = subprocess.run(list(argv), capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        raise FaceError(signal)
    if result.returncode != 0:
        raise FaceError(signal)
    return result.stdout


def _memory_values() -> tuple[int, int]:
    text = _run_text(["free", "-m"], "face-meter-ram-command-failed")
    row = next((line.split() for line in text.splitlines() if line.strip().startswith("Mem:")), None)
    if row is None or len(row) < 3:
        raise FaceError("face-meter-ram-observation-invalid")
    try:
        return int(row[1]), int(row[2])
    except ValueError:
        raise FaceError("face-meter-ram-observation-invalid")


def _disk_values() -> tuple[int, int, int]:
    text = _run_text(["df", "-Pm", "/"], "face-meter-disk-command-failed")
    rows = [line.split() for line in text.splitlines() if line.strip()]
    if len(rows) < 2 or len(rows[1]) < 6:
        raise FaceError("face-meter-disk-observation-invalid")
    try:
        used, total = int(rows[1][2]), int(rows[1][1])
        percent = int(rows[1][4].rstrip("%"))
    except ValueError:
        raise FaceError("face-meter-disk-observation-invalid")
    return used, total, percent


def _temp_c() -> int | None:
    for hwmon in sorted(Path("/sys/class/hwmon").glob("hwmon*")):
        try:
            if (hwmon / "name").read_text(encoding="utf-8").strip() != "coretemp":
                continue
        except OSError:
            continue
        for label in sorted(hwmon.glob("temp*_label")):
            try:
                if label.read_text(encoding="utf-8").strip() == "Package id 0":
                    input_path = Path(str(label)[:-6] + "_input")
                    return (int(input_path.read_text(encoding="ascii").strip()) + 500) // 1000
            except (OSError, ValueError):
                continue
        try:
            return (int((hwmon / "temp1_input").read_text(encoding="ascii").strip()) + 500) // 1000
        except (OSError, ValueError):
            continue
    for zone in sorted(Path("/sys/class/thermal").glob("thermal_zone*")):
        try:
            zone_type = (zone / "type").read_text(encoding="utf-8").strip()
            if zone_type not in {"x86_pkg_temp", "acpitz"}:
                continue
            raw = int((zone / "temp").read_text(encoding="ascii").strip())
            return (raw + 500) // 1000
        except (OSError, ValueError):
            continue
    return None


def meter(payload: dict[str, Any]) -> Mapping[str, Any]:
    kind = _require_string(payload, "kind", "face-meter-kind-required")
    if kind not in {"cpu", "ram", "temp", "disk"}:
        raise FaceError("face-meter-kind-invalid")
    if kind == "cpu":
        pct = _cpu_percent()
        text = f"CPU {_bars(pct)}"
        class_name = _class_for(pct)
        tooltip = f"CPU: {pct}%"
        return {"ok": True, "firstMissingSignal": "none", "text": text, "tooltip": tooltip, "class": class_name, "value": pct}
    if kind == "ram":
        total, used = _memory_values()
        if total <= 0:
            raise FaceError("face-meter-ram-total-invalid")
        pct = used * 100 // total
        return {"ok": True, "firstMissingSignal": "none", "text": f"RAM {_bars(pct)}", "tooltip": f"RAM: {pct}% ({used}/{total} MiB)", "class": _class_for(pct), "value": pct}
    if kind == "disk":
        used, total, pct = _disk_values()
        if total <= 0:
            raise FaceError("face-meter-disk-total-invalid")
        return {"ok": True, "firstMissingSignal": "none", "text": f"DSK {_bars(pct)}", "tooltip": f"Disk /: {pct}% ({used}/{total} MiB)", "class": _class_for(pct), "value": pct}
    celsius = _temp_c()
    if celsius is None:
        return {"ok": True, "firstMissingSignal": "none", "text": "TMP ????", "tooltip": "No temperature sensor found", "class": "high", "value": None}
    pct = max(0, min(100, (celsius - 30) * 100 // 70))
    class_name = "high" if celsius >= 90 else "medium" if celsius >= 75 else "low"
    return {"ok": True, "firstMissingSignal": "none", "text": f"TMP {_bars(pct)}", "tooltip": f"CPU package temperature: {celsius}°C", "class": class_name, "value": celsius}


def _load_optional_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        return None


def _item_name(value: Any, fallback: str) -> str:
    if not isinstance(value, dict):
        return fallback
    return str(value.get("description") or value.get("name") or value.get("hotfix_id") or value.get("id") or fallback)


def badge(payload: dict[str, Any]) -> Mapping[str, Any]:
    feed_path = Path(os.environ.get("HARMONIA_FEED_PATH", "/var/lib/harmonia/interactables.json"))
    receipt_dir = Path(os.environ.get("HARMONIA_RECEIPT_DIR", "/var/lib/harmonia/receipts/tv-update-latest"))
    subscription_path = Path(os.environ.get("HARMONIA_SUBSCRIPTION_PATH", "/var/lib/harmonia/subscription.json"))
    try:
        feed = json.loads(feed_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
        raise FaceError("harmonia-feed-observation-failed")
    if not isinstance(feed, dict):
        raise FaceError("harmonia-feed-object-required")
    rows = feed.get("interactables", [])
    pending = [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []
    pending_names = [_item_name(row, "unnamed update") for row in pending]
    subscription = _load_optional_json(subscription_path)
    hotfix_ledger = subscription.get("hotfix_ledger", {}) if isinstance(subscription, dict) else {}
    if not isinstance(hotfix_ledger, dict):
        hotfix_ledger = {}
    hotfixes: list[str] = []
    hotfix_dir = receipt_dir / "hotfixes"
    try:
        receipt_paths = sorted(hotfix_dir.glob("*.json")) if hotfix_dir.is_dir() else []
    except OSError:
        receipt_paths = []
    for path in receipt_paths:
        item = _load_optional_json(path)
        if not isinstance(item, dict):
            continue
        hotfix_id = str(item.get("hotfix_id") or path.stem)
        unresolved = item.get("lifecycle") == "blocked" or (
            item.get("eligibility_comparison") == "nonempty" and hotfix_id not in hotfix_ledger
        )
        if unresolved:
            hotfixes.append(_item_name(item, hotfix_id))
    ledger_path = receipt_dir.parent / "tv-ledger.jsonl"
    entries: list[dict[str, Any]] = []
    try:
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            try:
                value = json.loads(line)
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and isinstance(value.get("run_id"), str):
                entries.append(value)
    except (OSError, UnicodeError):
        pass
    latest_run_id = entries[-1]["run_id"] if entries else None
    failed_modules = [
        str(entry.get("module_id") or "unnamed module")
        for entry in entries
        if entry.get("run_id") == latest_run_id and entry.get("ok") is False
    ]
    if hotfixes:
        state = "bad"
        tooltip = "Harmonia hotfix needs attention:\n" + "\n".join(f"• {name}" for name in hotfixes)
    elif failed_modules:
        state = "bad"
        tooltip = "Harmonia module failed:\n" + "\n".join(f"• {name}" for name in failed_modules)
    elif pending_names:
        state = "medium"
        tooltip = "Harmonia pending updates:\n" + "\n".join(f"• {name}" for name in pending_names)
    else:
        state = "good"
        tooltip = "Harmonia: no pending updates"
    return {
        "ok": True, "firstMissingSignal": "none", "text": "󰚰", "class": state,
        "tooltip": tooltip, "pending_count": len(pending_names),
        "hotfix_count": len(hotfixes), "failed_module_count": len(failed_modules),
    }


def _cache_input_observation(home: Path, cache_directory: Path) -> dict[str, Any]:
    errors: list[str] = []
    cache_mtimes: list[int] = []
    try:
        with os.scandir(cache_directory) as items:
            for item in items:
                if not item.name.startswith("ksycoca6_"):
                    continue
                try:
                    metadata = item.stat(follow_symlinks=False)
                    if stat.S_ISREG(metadata.st_mode):
                        cache_mtimes.append(metadata.st_mtime_ns)
                except OSError:
                    errors.append("launcher-cache-cache-stat-failed")
    except FileNotFoundError:
        pass
    except OSError:
        errors.append("launcher-cache-cache-directory-observation-failed")
    newest_input = 0
    input_count = 0
    for directory in (home / ".local/share/applications", Path("/usr/local/share/applications"), Path("/usr/share/applications")):
        if not directory.exists():
            continue
        def onerror(_error: OSError) -> None:
            errors.append("launcher-cache-desktop-input-observation-failed")
        try:
            for current, _dirs, files in os.walk(directory, onerror=onerror, followlinks=False):
                for filename in files:
                    if not filename.endswith(".desktop"):
                        continue
                    path = Path(current) / filename
                    try:
                        metadata = path.stat()
                        if stat.S_ISREG(metadata.st_mode):
                            newest_input = max(newest_input, metadata.st_mtime_ns)
                            input_count += 1
                    except OSError:
                        errors.append("launcher-cache-desktop-input-stat-failed")
        except OSError:
            errors.append("launcher-cache-desktop-input-observation-failed")
    cache_mtime = max(cache_mtimes) if cache_mtimes else None
    state = "Empty" if cache_mtime is not None and cache_mtime >= newest_input else "Different"
    return {
        "state": state, "cache_mtime_ns": cache_mtime,
        "newest_desktop_input_mtime_ns": newest_input,
        "cache_count": len(cache_mtimes), "desktop_input_count": input_count,
        "errors": errors,
    }


def _safe_native_target(path: Path, home: Path) -> bool:
    try:
        relative = path.relative_to(home)
        current = home
        for part in relative.parts[:-1]:
            current = current / part
            try:
                metadata = os.lstat(current)
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                return False
        return True
    except ValueError:
        return False


def bounded_stderr_tail(stderr: str | bytes | None) -> str | None:
    if not stderr:
        return None
    text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
    text = "\n".join(text.splitlines()[-20:])
    text = _SECRET_ASSIGNMENT.sub(r"\1\2[redacted]", text)
    text = _BEARER_VALUE.sub(r"\1[redacted]", text)
    text = _BASIC_VALUE.sub(r"\1[redacted]", text)
    text = _URL_USERINFO.sub(r"\1[redacted]@", text)
    return text[-4096:] or None


def refresh_launcher_cache(home: Path | None = None) -> dict[str, Any]:
    """Run the shared four-step native desktop-cache refresh as owner argv."""
    selected_home = home or owner_home()
    environment, _source = owner_session_environment(home=selected_home, discover=False)
    applications = selected_home / ".local/share/applications"
    ksycoca_directory = selected_home / ".cache"
    wofi_cache = selected_home / ".local/state/hometv-launcher/wofi-drun-cache"
    steps: list[dict[str, Any]] = []
    stderr_parts: list[str] = []

    def command_step(step_name: str, utility_name: str, arguments: Sequence[str]) -> None:
        utility = _owner_utility(utility_name)
        if utility is None:
            steps.append({"name": step_name, "outcome": "failed", "signal": f"launcher-cache-{step_name}-utility-missing"})
            return
        result = owner_run([utility, *arguments], environment, timeout=60)
        stderr = bounded_stderr_tail(result.stderr)
        if stderr:
            stderr_parts.append(stderr)
        steps.append({
            "name": step_name, "outcome": "succeeded" if result.returncode == 0 else "failed",
            "exit": result.returncode,
            **({"stderr_tail": stderr} if stderr else {}),
            **({"signal": f"launcher-cache-{step_name}-failed"} if result.returncode != 0 else {}),
        })

    def remove_step(step_name: str, paths: Sequence[Path]) -> None:
        rm = _owner_utility("rm")
        if rm is None:
            steps.append({"name": step_name, "outcome": "failed", "signal": f"launcher-cache-{step_name}-rm-unavailable"})
            return
        if not paths:
            steps.append({"name": step_name, "outcome": "succeeded", "count": 0, "changed": False})
            return
        result = owner_run([rm, "-f", "--", *[str(path) for path in paths]], environment, timeout=30)
        stderr = bounded_stderr_tail(result.stderr)
        if stderr:
            stderr_parts.append(stderr)
        steps.append({
            "name": step_name, "outcome": "succeeded" if result.returncode == 0 else "failed",
            "count": len(paths), "exit": result.returncode,
            **({"stderr_tail": stderr} if stderr else {}),
            **({"signal": f"launcher-cache-{step_name}-failed"} if result.returncode != 0 else {}),
        })

    # Preserve the native script's ordered work, but keep every operation in argv.
    command_step("update-desktop-database", "update-desktop-database", [str(applications)])
    try:
        if ksycoca_directory.is_symlink() or not _safe_native_target(ksycoca_directory, selected_home):
            raise FaceError("launcher-cache-ksycoca-directory-unsafe")
        matches = sorted(path for path in ksycoca_directory.iterdir() if path.name.startswith("ksycoca6_")) if ksycoca_directory.is_dir() else []
        remove_step("remove-ksycoca-cache", matches)
    except (OSError, FaceError):
        steps.append({"name": "remove-ksycoca-cache", "outcome": "failed", "signal": "launcher-cache-ksycoca-observation-failed"})
    command_step("kbuildsycoca6", "kbuildsycoca6", ["--noincremental"])
    try:
        if not _safe_native_target(wofi_cache, selected_home):
            raise FaceError("launcher-cache-wofi-cache-path-unsafe")
        remove_step("remove-wofi-cache", [wofi_cache])
    except (OSError, FaceError):
        steps.append({"name": "remove-wofi-cache", "outcome": "failed", "signal": "launcher-cache-wofi-remove-failed"})

    failures = [step for step in steps if step.get("outcome") != "succeeded"]
    aggregate_exit = 0 if not failures else next((step.get("exit") for step in failures if isinstance(step.get("exit"), int)), 1)
    return {"exit": aggregate_exit, "ok": not failures, "steps": steps, "stderr": "\n".join(stderr_parts) or None}


def launcher_cache(payload: dict[str, Any]) -> Mapping[str, Any]:
    action = _require_string(payload, "action", "face-launcher-cache-action-required")
    if action not in {"check", "apply"}:
        raise FaceError("face-launcher-cache-action-invalid")
    home = owner_home()
    cache_directory = launcher_cache_directory(home)
    if action == "check":
        observed = _cache_input_observation(home, cache_directory)
        errors = observed["errors"]
        return {
            "ok": not errors, "firstMissingSignal": errors[0] if errors else "none",
            "action": "check", "target": {"home": str(home), "cache_directory": str(cache_directory)},
            "observed": observed, "state": observed["state"], "changed": False,
        }
    before = _cache_input_observation(home, cache_directory)
    refresh = refresh_launcher_cache(home)
    final = _cache_input_observation(home, cache_directory)
    converged = final["state"] == "Empty" and not final["errors"]
    before_ok = not before["errors"]
    first_failure = next((step.get("signal") for step in refresh["steps"] if step.get("outcome") != "succeeded"), None)
    if first_failure is None and not before_ok:
        first_failure = before["errors"][0]
    if first_failure is None and final["errors"]:
        first_failure = final["errors"][0]
    if first_failure is None and not converged:
        first_failure = "launcher-cache-not-converged"
    return {
        "ok": first_failure is None, "firstMissingSignal": first_failure or "none",
        "action": "apply", "target": {"home": str(home), "cache_directory": str(cache_directory)},
        "changed": before.get("state") != final.get("state"),
        "observed": before, "could_change": {"state": "Empty", "path": str(cache_directory)},
        "attempt": {"attempted": True, "exit": refresh["exit"], "steps": refresh["steps"]},
        "final": {**final, "converged": converged},
    }

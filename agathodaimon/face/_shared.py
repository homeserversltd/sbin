from __future__ import annotations

import contextvars
import fcntl
import json
import os
import pwd
import re
import shutil
import socket
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

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
_BENCHMARK_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "agathodaimon_face_benchmark", default=None
)


def _benchmark_enabled(request: Request) -> bool:
    if not request.envelope:
        return False
    flags = request.value.get("flags")
    return isinstance(flags, Mapping) and flags.get("benchmark") is True


def _process_boot_elapsed_ms() -> tuple[int, bool]:
    try:
        stat_text = Path("/proc/self/stat").read_text(encoding="ascii")
        closing = stat_text.rfind(")")
        if closing < 0:
            return 0, False
        fields = stat_text[closing + 1 :].split()
        if len(fields) <= 19:
            return 0, False
        start_ticks = int(fields[19])
        ticks_per_second = int(os.sysconf("SC_CLK_TCK"))
        if start_ticks < 0 or ticks_per_second <= 0:
            return 0, False
        process_start_ns = start_ticks * 1_000_000_000 // ticks_per_second
        boot_now_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        elapsed_ns = boot_now_ns - process_start_ns
        if elapsed_ns < 0:
            return 0, False
        return elapsed_ns // 1_000_000, True
    except (OSError, ValueError, IndexError, AttributeError, OverflowError):
        return 0, False


def _benchmark_call(
    locus: str,
    operation: Callable[[], Any],
    *,
    success: Callable[[Any], bool] | None = None,
) -> Any:
    context = _BENCHMARK_CONTEXT.get()
    if context is None:
        return operation()
    try:
        started_ns = time.perf_counter_ns()
    except Exception:
        try:
            operation_result = operation()
        except BaseException:
            context["timings"].append({"locus": locus, "elapsed_ms": 0, "ok": False})
            raise
        context["timings"].append({"locus": locus, "elapsed_ms": 0, "ok": False})
        return operation_result
    ok = False
    try:
        result = operation()
        ok = success(result) if success is not None else True
        return result
    except BaseException:
        ok = False
        raise
    finally:
        try:
            elapsed_ns = time.perf_counter_ns() - started_ns
            if elapsed_ns < 0:
                elapsed_ns = 0
                ok = False
        except Exception:
            elapsed_ns = 0
            ok = False
        context["timings"].append({
            "locus": locus,
            "elapsed_ms": elapsed_ns // 1_000_000,
            "ok": bool(ok),
        })


def _benchmark_boot_entry() -> dict[str, Any]:
    elapsed_ms, ok = _process_boot_elapsed_ms()
    return {"locus": "staff.boot", "elapsed_ms": elapsed_ms, "ok": ok}


def read_payload() -> Request:
    """Read the public envelope and select the fields used by FaceDoor verbs."""
    return read(known_fields=("payload", "direction", "action", "desktop_id", "menu", "id", "kind", "step", "carry", "ring"))


def invoke(verb: str, operation: Callable[[dict[str, Any]], Mapping[str, Any]]) -> int:
    """Emit exactly one transient receipt for a verb, including refusals."""
    request: Request | None = None
    benchmark_context: dict[str, Any] | None = None
    benchmark_token: contextvars.Token[dict[str, Any] | None] | None = None
    try:
        request = read_payload()
        if _benchmark_enabled(request):
            benchmark_context = {"timings": []}
            benchmark_token = _BENCHMARK_CONTEXT.set(benchmark_context)
            benchmark_context["timings"].append(_benchmark_boot_entry())
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
    try:
        if request is not None:
            receipt = attach(receipt, request)
        if benchmark_context is not None:
            receipt["benchmark"] = {
                "schema": _BENCHMARK_SCHEMA,
                "timings": list(benchmark_context["timings"]),
            }
    finally:
        if benchmark_context is not None:
            benchmark_context["timings"].clear()
        if benchmark_token is not None:
            _BENCHMARK_CONTEXT.reset(benchmark_token)
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
    enter_owner: bool = False,
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
    system_observation = _benchmark_call(
        "staff.session-env.systemctl",
        lambda: _systemctl_environment_observed(account, selected_home, runtime),
        success=lambda result: isinstance(result, tuple) and len(result) == 2 and result[1] is True,
    )
    system_values = system_observation[0]
    values_by_key: dict[str, list[tuple[str, str]]] = {key: [] for key in ("SWAYSOCK", "WAYLAND_DISPLAY", "DBUS_SESSION_BUS_ADDRESS", "PULSE_SERVER")}
    for pid, values in proc_sources:
        for key in values_by_key:
            if values.get(key):
                values_by_key[key].append((f"proc:{pid}", values[key]))
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
        paths = {value for _source, value in unique}
        if len(paths) == 1:
            source, value = next(iter(unique))
            env[key] = value
            sources[key] = source
        elif len(paths) > 1:
            raise FaceError("owner-session-socket-ambiguous", socket=key)
        else:
            pattern = f"sway-ipc.{account.pw_uid}.*.sock" if key == "SWAYSOCK" else "wayland-*"
            try:
                candidates = sorted(runtime.glob(pattern))
            except OSError:
                candidates = []
            live = [candidate for candidate in candidates if _is_live_owned_socket(candidate, account, runtime)]
            if len(live) == 1:
                env[key] = str(live[0]) if key == "SWAYSOCK" else live[0].name
                sources[key] = "runtime-unique"
            elif len(live) > 1 and (require_sway or require_wayland):
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
    enter_owner: bool = False,
) -> tuple[dict[str, str], str]:
    return _benchmark_call(
        "staff.session-env",
        lambda: _owner_session_environment(
            home=home, discover=discover,
            require_sway=require_sway, require_wayland=require_wayland,
            enter_owner=enter_owner,
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


def _sway_json(args: Sequence[str], environment: Mapping[str, str]) -> Any:
    result = owner_run(["swaymsg", "-r", *args], environment, timeout=8)
    if result.returncode != 0:
        raise FaceError("swaymsg-query-failed")
    try:
        return json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        raise FaceError("swaymsg-json-invalid")


def focus(payload: dict[str, Any]) -> Mapping[str, Any]:
    direction = _require_string(payload, "direction", "face-focus-direction-required")
    if direction not in {"next", "prev"}:
        raise FaceError("face-focus-direction-invalid")
    environment, socket_source = owner_session_environment(discover=True, require_sway=True)
    tree = _sway_json(["-t", "get_tree"], environment)
    workspaces = _sway_json(["-t", "get_workspaces"], environment)
    outputs = _sway_json(["-t", "get_outputs"], environment)
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
        return {"ok": True, "firstMissingSignal": "none", "changed": False, "target": None, "socket_source": socket_source}
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
        result = owner_run(["swaymsg", action], environment, timeout=8)
        if result.returncode != 0:
            raise FaceError("swaymsg-focus-failed", target=target, socket_source=socket_source)
    return {"ok": True, "firstMissingSignal": "none", "changed": True, "target": target, "socket_source": socket_source}


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
    environment, socket_source = owner_session_environment(discover=True, require_sway=True)
    workspaces = _sway_json(["-t", "get_workspaces"], environment)
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
        result = owner_run(["swaymsg", "-r", command], environment, timeout=8)
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
    environment, socket_source = owner_session_environment(discover=True, require_sway=True)
    workspaces = _sway_json(["-t", "get_workspaces"], environment)
    if not isinstance(workspaces, list):
        raise FaceError("swaymsg-workspaces-shape-invalid")
    current = next((row for row in workspaces if isinstance(row, dict) and row.get("focused") is True), None)
    if current is None or not isinstance(current.get("name"), str):
        raise FaceError("sway-focused-workspace-missing")
    current_name = current["name"]
    workspace_names = {row.get("name") for row in workspaces if isinstance(row, dict) and isinstance(row.get("name"), str)}
    tree = _sway_json(["-t", "get_tree"], environment)
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
            result = owner_run(["swaymsg", selector], environment, timeout=8)
            if result.returncode != 0:
                failure = "swaymsg-move-failed"
                break
            moved.append(con_id)
    finally:
        refocus = owner_run(["swaymsg", f"workspace {json.dumps(current_name)}"], environment, timeout=8)
    if failure:
        raise FaceError(failure, moved_count=len(moved), requested_count=len(windows), refocus_ok=refocus.returncode == 0, socket_source=socket_source)
    if refocus.returncode != 0:
        raise FaceError("swaymsg-refocus-failed", moved_count=len(moved), requested_count=len(windows), socket_source=socket_source)
    return {"ok": True, "firstMissingSignal": "none", "moved_count": len(moved), "requested_count": len(windows), "current_workspace": current_name, "socket_source": socket_source}


def launch(payload: dict[str, Any]) -> Mapping[str, Any]:
    desktop_id = payload.get("desktop_id")
    menu = payload.get("menu")
    if desktop_id is not None:
        if menu is not None or not isinstance(desktop_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*\.desktop", desktop_id):
            raise FaceError("face-launch-desktop-id-invalid")
        home = Path(DEFAULT_OWNER_HOME)
        environment, socket_source = owner_session_environment(home=home, discover=True, require_wayland=True)
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
        environment, socket_source = owner_session_environment(home=home, discover=True, require_wayland=True)
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


def _pgrep(program: str, account: pwd.struct_passwd, environment: Mapping[str, str]) -> int:
    utility = _owner_utility("pgrep")
    if utility is None:
        raise FaceError("face-app-pgrep-unavailable")
    result = owner_run([utility, "--exact", "--uid", str(account.pw_uid), "--", program], environment, timeout=5)
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
    environment, socket_source = owner_session_environment(discover=True)
    with _runtime_lock("agathodaimon-face-waybar-toggle.lock") as (fd, lock_path):
        prior = _lock_state(fd)
        utility = _owner_utility("pkill")
        if utility is None:
            raise FaceError("face-bar-pkill-unavailable", lock_path=str(lock_path))
        result = owner_run([utility, "--signal", "USR1", "--exact", "--uid", str(account.pw_uid), "--", "waybar"], environment, timeout=5)
        if result.returncode != 0:
            raise FaceError("face-bar-signal-failed", lock_path=str(lock_path), socket_source=socket_source)
        _write_lock_state(fd, not prior)
    return {"ok": True, "firstMissingSignal": "none", "changed": True, "lock_path": str(lock_path), "hidden": not prior, "socket_source": socket_source}


def app(payload: dict[str, Any]) -> Mapping[str, Any]:
    program = _require_string(payload, "id", "face-app-id-required")
    action = _require_string(payload, "action", "face-app-action-required")
    if len(program) > 128 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", program):
        raise FaceError("face-app-id-invalid")
    if action != "toggle":
        raise FaceError("face-app-action-invalid")
    account = _owner()
    environment, socket_source = owner_session_environment(discover=True)
    lock_name = f"agathodaimon-face-app-{program}.lock"
    with _runtime_lock(lock_name) as (fd, lock_path):
        marked = _lock_state(fd)
        running = _pgrep(program, account, environment) == 0 if marked else False
        if marked and running:
            utility = _owner_utility("pkill")
            if utility is None:
                raise FaceError("face-app-pkill-unavailable", lock_path=str(lock_path))
            result = owner_run([utility, "--exact", "--uid", str(account.pw_uid), "--", program], environment, timeout=5)
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
            return {"ok": True, "firstMissingSignal": "none", "changed": True, "program": program, "running": False, "lock_path": str(lock_path), "socket_source": socket_source}
        if marked:
            # Recover a stale marker before restarting so failures stay inactive.
            _write_lock_state(fd, False)
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
        return {"ok": True, "firstMissingSignal": "none", "changed": True, "program": program, "running": True, "pid": process.pid, "lock_path": str(lock_path), "socket_source": socket_source}


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

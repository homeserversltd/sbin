"""Relaunch settings processes older than the installed GUI seat, by hand."""
from __future__ import annotations

import fcntl
import json
import os
import pwd
import select
import signal
import time
from pathlib import Path

from agathodaimon.face._shared import (
    FaceError, _is_live_owned_socket, _proc_sway_environments, _socket_path,
    _sway_command, _sway_json, owner_session_environment,
)

SCHEMA = "agathodaimon.face.settings-relaunch.v1"
CLI = "/usr/local/sbin/agathodaimon/cli.py"
GUI = Path("/usr/local/sbin/agathodaimon/gui")
LAUNCH = CLI + " gui settings"


def _stat(pid: int) -> tuple[str, int, int]:
    fields = (Path("/proc") / str(pid) / "stat").read_text().rsplit(")", 1)[1].split()
    return fields[0], int(fields[1]), int(fields[19])


def _command(pid: int) -> list[str]:
    return os.fsdecode((Path("/proc") / str(pid) / "cmdline").read_bytes()).rstrip("\0").split("\0")


def _settings(command: list[str]) -> bool:
    return len(command) == 4 and Path(command[0]).name == "python3" and command[1:] == [CLI, "gui", "settings"]


def _shell(command: list[str]) -> bool:
    return len(command) == 3 and Path(command[0]).name == "sh" and command[1:] == ["-c", LAUNCH]


def _environment(pid: int, account: pwd.struct_passwd) -> dict[str, str]:
    raw = (Path("/proc") / str(pid) / "environ").read_bytes()
    values = dict(item.split("=", 1) for item in os.fsdecode(raw).split("\0") if "=" in item)
    runtime = Path(f"/run/user/{account.pw_uid}")
    socket = _socket_path(values.get("SWAYSOCK", ""), runtime)
    if socket is None or not _is_live_owned_socket(socket, account, runtime):
        display = values.get("WAYLAND_DISPLAY")
        matches = set()
        if display:
            for _pid, compositor in _proc_sway_environments(account.pw_uid):
                if compositor.get("WAYLAND_DISPLAY") != display:
                    continue
                candidate = _socket_path(compositor.get("SWAYSOCK", ""), runtime)
                if candidate is not None and _is_live_owned_socket(candidate, account, runtime):
                    matches.add(str(candidate))
        if len(matches) != 1:
            raise FaceError("face-settings-relaunch-session-unavailable")
        socket = Path(matches.pop())
    env, _ = owner_session_environment(discover=False)
    env["SWAYSOCK"] = str(socket)
    return env


def _newest_file() -> int:
    newest = None
    def failed(error: OSError) -> None:
        raise error
    for directory, _dirs, files in os.walk(GUI, onerror=failed):
        for name in files:
            mtime = (Path(directory) / name).stat().st_mtime_ns
            newest = mtime if newest is None else max(newest, mtime)
    if newest is None:
        raise FaceError("face-settings-relaunch-seat-unavailable")
    return newest


def _pidfd(pid: int, uid: int, started: int, match) -> int:
    fd = os.pidfd_open(pid)
    try:
        state, _parent, current = _stat(pid)
        if (state in {"Z", "X"} or current != started or
                (Path("/proc") / str(pid)).stat().st_uid != uid or not match(_command(pid))):
            raise FaceError("face-settings-relaunch-process-changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _stop(fd: int, parent_fd: int | None) -> None:
    for target in (fd, parent_fd):
        if target is not None:
            try:
                signal.pidfd_send_signal(target, signal.SIGTERM)
            except ProcessLookupError:
                pass
    poller = select.poll()
    pending = {target for target in (fd, parent_fd) if target is not None}
    for target in pending:
        poller.register(target, select.POLLIN)
    deadline = time.monotonic() + 5
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        for target, _event in poller.poll(max(1, int(remaining * 1000))):
            pending.discard(target)
            poller.unregister(target)
    for target in pending:
        try:
            signal.pidfd_send_signal(target, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 1
    while pending:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FaceError("face-settings-relaunch-process-stop-failed")
        for target, _event in poller.poll(max(1, int(remaining * 1000))):
            pending.discard(target)
            poller.unregister(target)


def _window_pids(environment: dict[str, str]) -> set[int]:
    tree = _sway_json("get_tree", environment)
    if not isinstance(tree, dict):
        raise FaceError("face-settings-relaunch-tree-invalid")
    result = set()
    def visit(node: dict) -> None:
        if type(node.get("pid")) is int:
            result.add(node["pid"])
        for key in ("nodes", "floating_nodes"):
            for child in node.get(key, []):
                if isinstance(child, dict):
                    visit(child)
    visit(tree)
    return result


def _wait_for_window(environment: dict[str, str], previous: set[int], uid: int) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        for pid in _window_pids(environment) - previous:
            try:
                if (Path("/proc") / str(pid)).stat().st_uid == uid and _settings(_command(pid)):
                    return
            except (FileNotFoundError, ProcessLookupError):
                continue
        time.sleep(0.1)
    raise FaceError("face-settings-relaunch-window-unobserved")


def relaunch() -> dict:
    receipt = {"schema": SCHEMA, "ok": True, "relaunched": 0, "kept": 0, "firstMissingSignal": "none", "_attempted": False}
    def failure(name: str) -> None:
        receipt["ok"] = False
        if receipt["firstMissingSignal"] == "none":
            receipt["firstMissingSignal"] = name
    try:
        account = pwd.getpwnam("owner")
        candidates = []
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                if proc.stat().st_uid != account.pw_uid or not _settings(_command(int(proc.name))):
                    continue
                state, parent, started = _stat(int(proc.name))
                if state not in {"Z", "X"}:
                    candidates.append((int(proc.name), parent, started))
            except (FileNotFoundError, ProcessLookupError):
                continue
            except (OSError, ValueError, IndexError):
                failure("face-settings-relaunch-process-observation-failed")
        if not candidates:
            return receipt
        # Lock the existing seat directory, not a state file, across concurrent presses.
        seat_fd = os.open(GUI, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(seat_fd, fcntl.LOCK_EX)
            newest = _newest_file()
            ticks = os.sysconf("SC_CLK_TCK")
            boot_ns = time.time_ns() - time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            for pid, parent, started in candidates:
                # The kernel rounds start ticks down. Never kill an ambiguous fresh window.
                if boot_ns + (started + 1) * 1_000_000_000 // ticks >= newest:
                    receipt["kept"] += 1
                    continue
                fd = parent_fd = None
                try:
                    fd = _pidfd(pid, account.pw_uid, started, _settings)
                    env = _environment(pid, account)
                    previous_windows = _window_pids(env)
                    if parent > 1:
                        try:
                            pstate, _ppid, pstart = _stat(parent)
                            if pstate not in {"Z", "X"} and _shell(_command(parent)):
                                parent_fd = _pidfd(parent, account.pw_uid, pstart, _shell)
                        except (FileNotFoundError, ProcessLookupError):
                            pass
                    if parent_fd is not None and _stat(pid)[1] != parent:
                        raise FaceError("face-settings-relaunch-parent-changed")
                    receipt["_attempted"] = True
                    _stop(fd, parent_fd)
                    result = _sway_command("exec " + LAUNCH, env)
                    if result.returncode != 0:
                        raise FaceError("face-settings-relaunch-open-failed")
                    _wait_for_window(env, previous_windows, account.pw_uid)
                    receipt["relaunched"] += 1
                except (FileNotFoundError, ProcessLookupError):
                    failure("face-settings-relaunch-process-exited")
                except FaceError as error:
                    failure(error.signal)
                except (OSError, ValueError, IndexError):
                    failure("face-settings-relaunch-operation-failed")
                finally:
                    if parent_fd is not None:
                        os.close(parent_fd)
                    if fd is not None:
                        os.close(fd)
        finally:
            os.close(seat_fd)
    except KeyError:
        failure("owner-account-missing")
    except FaceError as error:
        failure(error.signal)
    except (OSError, ValueError):
        failure("face-settings-relaunch-observation-failed")
    return receipt


def main(argv=None) -> int:
    started = time.monotonic()
    try:
        result = relaunch()
    except Exception:
        result = {"schema": SCHEMA, "ok": False, "relaunched": 0, "kept": 0,
                  "firstMissingSignal": "face-settings-relaunch-unexpected-failure", "_attempted": False}
    if result.pop("_attempted"):
        from agathodaimon._deed import send
        send("sbin", "face-settings-relaunch", result["ok"], target="owner-settings",
             duration_ms=int((time.monotonic() - started) * 1000))
    print(json.dumps(result, sort_keys=True))
    return 0

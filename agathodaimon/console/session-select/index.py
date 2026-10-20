"""Arcadia OS sticky per-boot mode selection for the single owner session."""
from __future__ import annotations

import json
import os
import pwd
import select
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).parents[3]))

from agathodaimon.console.restart import index as console_restart
from agathodaimon.console.session import runtime as session_runtime
from agathodaimon.face import _shared as face_shared

SCHEMA = "agathodaimon.console.session-select.v1"
PROCESS_ENV_KEYS = ("XDG_RUNTIME_DIR", "SWAYSOCK", "WAYLAND_DISPLAY", "DISPLAY", "PATH")
MAX_PROCESS_ENV = 64 * 1024


def _proc_starttime(pid: int) -> str | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as source:
            raw = source.read(4096)
    except OSError:
        return None
    close = raw.rfind(b")")
    if close < 0:
        return None
    fields = raw[close + 1 :].split()
    return fields[19].decode("ascii") if len(fields) > 19 else None


def _proc_environment(pid: int) -> dict[str, str] | None:
    try:
        with open(f"/proc/{pid}/environ", "rb") as source:
            raw = source.read(MAX_PROCESS_ENV + 1)
    except OSError:
        return None
    if len(raw) > MAX_PROCESS_ENV:
        return None
    values: dict[str, str] = {}
    for item in raw.split(b"\0"):
        key, separator, value = item.partition(b"=")
        if not separator:
            continue
        try:
            decoded_key = key.decode("ascii")
            if decoded_key in PROCESS_ENV_KEYS:
                values[decoded_key] = value.decode("utf-8")
        except UnicodeError:
            continue
    return values


def _process_records(name: str, owner: pwd.struct_passwd, runtime: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise ValueError("console-session-process-scan-failed") from error
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            try:
                if entry.stat(follow_symlinks=False).st_uid != owner.pw_uid:
                    continue
                with open(f"/proc/{pid}/comm", "rb") as source:
                    comm = source.read(128).decode("utf-8").strip()
            except (OSError, UnicodeError):
                continue
            if comm != name:
                continue
            before = _proc_starttime(pid)
            env = _proc_environment(pid)
            if before is None or env is None or env.get("XDG_RUNTIME_DIR") != str(runtime):
                continue
            try:
                pidfd = os.pidfd_open(pid, 0)
            except (AttributeError, OSError):
                raise ValueError("console-session-pidfd-unavailable")
            after = _proc_starttime(pid)
            after_env = _proc_environment(pid)
            try:
                with open(f"/proc/{pid}/comm", "rb") as source:
                    after_comm = source.read(128).decode("utf-8").strip()
            except (OSError, UnicodeError):
                after_comm = None
            if (
                after is None
                or before != after
                or after_comm != name
                or after_env != env
            ):
                os.close(pidfd)
                continue
            records.append({"pid": pid, "pidfd": pidfd, "starttime": before, "env": env})
            if len(records) > 8:
                for record in records:
                    os.close(record["pidfd"])
                raise ValueError("console-session-process-ambiguous")
    return records


def _close_records(records: list[dict[str, Any]]) -> None:
    for record in records:
        try:
            os.close(record["pidfd"])
        except OSError:
            pass


def _wait_exited(pidfd: int, timeout: float = 15.0) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(max(0, int(timeout * 1000))))


def _signal_and_wait(record: dict[str, Any], signal_number: int = signal.SIGTERM) -> bool:
    sender = getattr(signal, "pidfd_send_signal", None)
    if not callable(sender):
        raise ValueError("console-session-pidfd-signal-unavailable")
    try:
        sender(record["pidfd"], signal_number, None, 0)
    except ProcessLookupError:
        return True
    return _wait_exited(record["pidfd"])


def _request_steam_shutdown(
    owner: pwd.struct_passwd, runtime: Path, steam: dict[str, Any]
) -> None:
    values = steam["env"]
    environment = {
        "HOME": owner.pw_dir,
        "USER": session_runtime.OWNER,
        "LOGNAME": session_runtime.OWNER,
        "PATH": values.get("PATH", os.defpath),
        "XDG_RUNTIME_DIR": str(runtime),
    }
    for key in ("SWAYSOCK", "WAYLAND_DISPLAY", "DISPLAY"):
        if values.get(key):
            environment[key] = values[key]
    try:
        command, outer_environment = face_shared.owner_session_command(
            [console_restart.steam_executable(), "-shutdown"], environment
        )
        subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
            env=outer_environment,
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        pass


def _stop_gamescope(owner: pwd.struct_passwd, runtime: Path) -> None:
    scopes = _process_records("gamescope", owner, runtime)
    try:
        if len(scopes) != 1:
            raise ValueError("console-session-gamescope-absent-or-ambiguous")
        gamescope = scopes[0]
        steam_records = _process_records("steam", owner, runtime)
        try:
            matching_steam = [
                record
                for record in steam_records
                if console_restart._shared_graphical_coordinates(
                    gamescope["env"], record["env"]
                )
                is not None
            ]
            if len(matching_steam) > 1:
                raise ValueError("console-session-steam-ambiguous")
            if matching_steam:
                steam = matching_steam[0]
                _request_steam_shutdown(owner, runtime, steam)
                if not _wait_exited(steam["pidfd"], 5.0) and not _signal_and_wait(steam):
                    raise ValueError("console-session-steam-did-not-exit")
        finally:
            _close_records(steam_records)
        if not _wait_exited(gamescope["pidfd"], 2.0):
            if not _signal_and_wait(gamescope):
                raise ValueError("console-session-gamescope-did-not-exit")
    finally:
        _close_records(scopes)


def _stop_sway(owner: pwd.struct_passwd, runtime: Path) -> None:
    sways = _process_records("sway", owner, runtime)
    try:
        if len(sways) != 1:
            raise ValueError("console-session-owner-sway-absent-or-ambiguous")
        sway = sways[0]
        socket_candidates: set[Path] = set()
        socket_value = sway["env"].get("SWAYSOCK")
        if socket_value:
            socket_path = face_shared._socket_path(socket_value, runtime)
            if socket_path is not None and face_shared._is_live_owned_socket(
                socket_path, owner, runtime
            ):
                socket_candidates.add(socket_path)
        socket_candidates.update(
            face_shared._runtime_socket_candidates("SWAYSOCK", owner, runtime)
        )
        if len(socket_candidates) != 1:
            raise ValueError("console-session-owner-swaysock-unverified-or-ambiguous")
        socket_path = next(iter(socket_candidates))
        result = face_shared._sway_command("exit", {"SWAYSOCK": str(socket_path)})
        if result.returncode != 0:
            raise ValueError("console-session-owner-sway-exit-refused")
        if not _wait_exited(sway["pidfd"]):
            raise ValueError("console-session-owner-sway-did-not-exit")
    finally:
        _close_records(sways)


def _stop_current(mode: str, owner: pwd.struct_passwd, runtime: Path) -> None:
    if mode == "steam":
        _stop_gamescope(owner, runtime)
    else:
        _stop_sway(owner, runtime)


def _log(outcome: str, previous: str, selected: str, started: float, signal_name: str) -> None:
    line = {
        "who": "agathodaimon",
        "verb": "console-session-select",
        "target": selected,
        "previous": previous,
        "outcome": outcome,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "signal": signal_name[:128],
    }
    print(json.dumps(line, sort_keys=True, separators=(",", ":"))[:1000], file=sys.stderr)


def _emit(
    *, ok: bool, previous: str, selected: str, changed: bool, signal_name: str = "none"
) -> int:
    print(
        json.dumps(
            {
                "schema": SCHEMA,
                "ok": ok,
                "previous": previous,
                "selected": selected,
                "mutation_performed": changed,
                "first_missing_signal": signal_name,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if len(arguments) != 1 or arguments[0] not in session_runtime.MODES:
        print("usage: console session-select {desktop|steam}", file=sys.stderr)
        return 2
    selected = arguments[0]
    try:
        directory_fd, runtime, owner = session_runtime.open_runtime()
    except (OSError, ValueError) as error:
        return _emit(
            ok=False,
            previous="unknown",
            selected=selected,
            changed=False,
            signal_name=f"console-owner-runtime-{type(error).__name__}",
        )
    try:
        if os.geteuid() not in (0, owner.pw_uid):
            return _emit(
                ok=False,
                previous="unknown",
                selected=selected,
                changed=False,
                signal_name="console-session-select-identity-refused",
            )
        try:
            previous_value = session_runtime.read_selector(directory_fd, owner.pw_uid)
            previous = previous_value or "steam"
            if previous == selected:
                return _emit(
                    ok=True,
                    previous=previous,
                    selected=selected,
                    changed=False,
                )
            with session_runtime.selector_lock(directory_fd, owner):
                previous_value = session_runtime.read_selector(directory_fd, owner.pw_uid)
                previous = previous_value or "steam"
                if previous == selected:
                    return _emit(
                        ok=True,
                        previous=previous,
                        selected=selected,
                        changed=False,
                    )
                started = time.monotonic()
                write_started = False
                try:
                    write_started = True
                    session_runtime.atomic_write_selector(directory_fd, owner, selected)
                    _stop_current(previous, owner, runtime)
                except Exception as error:
                    rollback_signal = "none"
                    if write_started:
                        try:
                            session_runtime.restore_selector(
                                directory_fd, owner, previous_value
                            )
                        except (OSError, ValueError):
                            rollback_signal = "console-session-selector-rollback-failed"
                    signal_name = (
                        rollback_signal
                        if rollback_signal != "none"
                        else f"console-session-switch-{type(error).__name__}"
                    )
                    _log("failed-rolled-back", previous, selected, started, signal_name)
                    return _emit(
                        ok=False,
                        previous=previous,
                        selected=selected,
                        changed=True,
                        signal_name=signal_name,
                    )
                _log("selected", previous, selected, started, "none")
                return _emit(
                    ok=True,
                    previous=previous,
                    selected=selected,
                    changed=True,
                )
        except (OSError, ValueError) as error:
            return _emit(
                ok=False,
                previous="unknown",
                selected=selected,
                changed=False,
                signal_name=f"console-session-selector-{type(error).__name__}",
            )
    finally:
        os.close(directory_fd)


if __name__ == "__main__":
    raise SystemExit(main())

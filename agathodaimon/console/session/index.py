"""Single-owner Arcadia OS Sway session supervisor."""
from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).parents[3]))

from agathodaimon.console.session import runtime as session_runtime

FAST_FAILURE_WINDOW_SECONDS = 5.0
INITIAL_RETRY_DELAY_SECONDS = 1.0
MAX_RETRY_DELAY_SECONDS = 30.0


def _desktop_environment() -> dict[str, str]:
    result = dict(os.environ)
    result.update(session_runtime.session_environment_updates())
    result.pop("SWAYSOCK", None)
    result.pop("WAYLAND_DISPLAY", None)
    result.pop("DISPLAY", None)
    result["XDG_SESSION_TYPE"] = "wayland"
    result["XDG_CURRENT_DESKTOP"] = "sway"
    result["XDG_SESSION_DESKTOP"] = "sway"
    return result


def _log(verb: str, target: str, outcome: str, started: float, signal_name: str = "none") -> None:
    line = {
        "who": "agathodaimon",
        "verb": verb,
        "target": target,
        "outcome": outcome,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "signal": signal_name[:128],
    }
    encoded = json.dumps(line, sort_keys=True, separators=(",", ":"))
    print(encoded[:1000], file=sys.stderr)


def _run_child(
    argv: list[str], env: dict[str, str], target: str
) -> tuple[int | None, str | None, float]:
    started = time.monotonic()
    try:
        process = subprocess.Popen(argv, env=env, start_new_session=True)
    except OSError as error:
        signal_name = f"{target}-exec-{type(error).__name__}"
        _log("launch", target, "failed", started, signal_name)
        return None, signal_name, max(0.0, time.monotonic() - started)
    except KeyboardInterrupt:
        _log("launch", target, "interrupted", started, "session-interrupted")
        return None, "session-interrupted", max(0.0, time.monotonic() - started)
    try:
        status = process.wait()
    except KeyboardInterrupt:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except OSError:
            pass
        process.wait()
        _log("launch", target, "interrupted", started, "session-interrupted")
        return (
            process.returncode,
            "session-interrupted",
            max(0.0, time.monotonic() - started),
        )
    _log("launch", target, "returned", started, f"exit-{status}")
    return status, None, max(0.0, time.monotonic() - started)


def _print_plan() -> int:
    try:
        directory_fd, _runtime_path, _owner = session_runtime.open_runtime()
    except (OSError, ValueError) as error:
        print(f"console-session-plan-invalid:{type(error).__name__}", file=sys.stderr)
        return 1
    os.close(directory_fd)
    env = _desktop_environment()
    print("# selected-mode: desktop")
    for key in sorted(set(os.environ) - set(env)):
        print("unset " + shlex.quote(key))
    for key, value in sorted(env.items()):
        if os.environ.get(key) != value:
            print(f"export {key}={shlex.quote(value)}")
    print("exec " + shlex.join(["sway"]))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--print"]:
        return _print_plan()
    if arguments:
        print("usage: console session [--print]", file=sys.stderr)
        return 2
    try:
        directory_fd, _runtime_path, owner = session_runtime.open_runtime()
    except (OSError, ValueError) as error:
        print(f"console-session-runtime-refused:{type(error).__name__}", file=sys.stderr)
        return 1
    if os.geteuid() != owner.pw_uid:
        os.close(directory_fd)
        print("console-session-must-run-as-owner", file=sys.stderr)
        return 1
    retry_delay = INITIAL_RETRY_DELAY_SECONDS
    try:
        while True:
            _status, launch_error, duration = _run_child(["sway"], _desktop_environment(), "desktop")
            if launch_error == "session-interrupted":
                return 0
            if duration >= FAST_FAILURE_WINDOW_SECONDS:
                retry_delay = INITIAL_RETRY_DELAY_SECONDS
                continue
            time.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, MAX_RETRY_DELAY_SECONDS)
    finally:
        os.close(directory_fd)


if __name__ == "__main__":
    raise SystemExit(main())

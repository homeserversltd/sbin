"""Single-owner Arcadia OS console session supervisor."""
from __future__ import annotations

import json
import os
import shlex
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).parents[3]))

from agathodaimon.console.session import runtime as session_runtime
from agathodaimon.settings.display import policy


STEAM_ARGUMENTS = ("steam", "-gamepadui", "-steamos3")
FAST_FAILURE_WINDOW_SECONDS = 5.0
INITIAL_RETRY_DELAY_SECONDS = 1.0
MAX_RETRY_DELAY_SECONDS = 30.0
DESKTOP_FAST_FAILURE_LIMIT = 3


def _refresh_text(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid-configured-refresh")
    return format(value, ".15g")


def _display_settings() -> dict[str, Any]:
    scratch = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    caduceus_root = os.environ.get("CADUCEUS_ROOT")
    if scratch:
        if caduceus_root and Path(scratch) != Path(caduceus_root):
            raise ValueError("console-scratch-roots-must-match")
        return policy._read_config_settings()
    if caduceus_root and Path(caduceus_root) != Path("/"):
        raise ValueError("console-scratch-display-root-required")
    return policy.load_settings()


def _dimensionless_fallback(configured_refresh: str, signal_name: str) -> list[str]:
    print(signal_name, file=sys.stderr)
    return ["gamescope", "-e", "-r", configured_refresh, "--", *STEAM_ARGUMENTS]


def _session_argv() -> list[str]:
    try:
        loaded = _display_settings()
        settings = {**loaded, **policy.validate_settings(loaded)}
        configured_refresh = _refresh_text(settings["refresh_rate"])
    except Exception:
        print(policy.DISPLAY_SETTING_UNREAD_DEFAULTS, file=sys.stderr)
        settings = {
            "resolution": "auto",
            "refresh_rate": policy.DEFAULT_REFRESH_RATE,
            "source": "defaults",
            "fallback": "settings-read-failed",
            "defaulted": ["resolution", "refresh_rate"],
        }
        configured_refresh = _refresh_text(policy.DEFAULT_REFRESH_RATE)
    try:
        observed = policy.connected_connectors()
    except Exception:
        observed = None
    if not isinstance(observed, dict) or observed.get("ok") is not True:
        return _dimensionless_fallback(configured_refresh, "display-drm-observation-unavailable")
    if observed.get("status") == "no-connected-screen":
        return _dimensionless_fallback(configured_refresh, "display-no-connected-screen")
    try:
        connectors = observed.get("connectors", [])
        resolved = policy.resolve_mode(connectors, settings)
    except Exception:
        return _dimensionless_fallback(configured_refresh, "display-mode-resolution-unavailable")
    if not isinstance(resolved, dict) or resolved.get("ok") is not True:
        signal_name = (
            "display-no-connected-screen"
            if isinstance(resolved, dict) and resolved.get("reason") == "no-connected-screen"
            else "display-no-eligible-progressive-mode"
        )
        return _dimensionless_fallback(configured_refresh, signal_name)
    mode = resolved.get("mode")
    if not isinstance(mode, dict):
        return _dimensionless_fallback(configured_refresh, "display-resolved-mode-missing")
    width, height = mode.get("width"), mode.get("height")
    if (
        isinstance(width, bool)
        or not isinstance(width, int)
        or width <= 0
        or isinstance(height, bool)
        or not isinstance(height, int)
        or height <= 0
    ):
        return _dimensionless_fallback(configured_refresh, "display-resolved-mode-invalid")
    rate = mode.get("vrefresh")
    if isinstance(rate, bool) or not isinstance(rate, int) or rate <= 0:
        return _dimensionless_fallback(
            configured_refresh, "display-advertised-integer-refresh-missing"
        )
    mode_reason = str(resolved.get("reason", "resolved"))
    mode_reason += (
        ";gamescope-first-matching-timing-for-equal-integer-tuples;"
        "physical-fractional-rate-not-guaranteed"
    )
    print(f"display-mode-reason={mode_reason}", file=sys.stderr)
    return [
        "gamescope",
        "-e",
        "-W",
        str(width),
        "-H",
        str(height),
        "-r",
        str(rate),
        "--",
        *STEAM_ARGUMENTS,
    ]


def _session_environment() -> dict[str, str]:
    result = dict(os.environ)
    result.update(session_runtime.session_environment_updates())
    result["MANGOHUD"] = "1"
    result.setdefault("SDL_GAMECONTROLLERCONFIG", "")
    return result


def _desktop_environment() -> dict[str, str]:
    result = dict(os.environ)
    result.update(session_runtime.session_environment_updates())
    result.pop(session_runtime.SHUTDOWN_SENTINEL, None)
    result.pop(session_runtime.REBOOT_SENTINEL, None)
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


def _clear_stale_sentinels(directory_fd: int) -> None:
    removed = session_runtime.consume_power_sentinels(directory_fd)
    if removed:
        _log("clear-stale-sentinels", "steam", "removed", time.monotonic())


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


def _reset_retry_state(
    retry_delays: dict[str, float], fast_failure_streaks: dict[str, int]
) -> None:
    for mode in ("desktop", "steam"):
        retry_delays[mode] = INITIAL_RETRY_DELAY_SECONDS
        fast_failure_streaks[mode] = 0


def _fallback_to_steam(directory_fd: int, owner: Any) -> str:
    started = time.monotonic()
    try:
        with session_runtime.selector_lock(directory_fd, owner):
            if session_runtime.read_selector(directory_fd, owner.pw_uid) != "desktop":
                return "selector-changed"
            session_runtime.atomic_write_selector(directory_fd, owner, "steam")
    except Exception as error:
        _log(
            "desktop-fallback",
            "steam",
            "failed",
            started,
            f"desktop-fallback-{type(error).__name__}",
        )
        return "failed"
    _log(
        "desktop-fallback",
        "steam",
        "changed",
        started,
        "desktop-fast-failure-limit",
    )
    return "changed"


def _power_action(directory_fd: int) -> tuple[str | None, bool]:
    consumed = session_runtime.consume_power_sentinels(directory_fd)
    if not consumed:
        return None, True
    if consumed == {
        session_runtime.SHUTDOWN_SENTINEL,
        session_runtime.REBOOT_SENTINEL,
    }:
        _log(
            "consume-power-sentinels",
            "steam",
            "conflicting-markers-refused",
            time.monotonic(),
            "both-power-sentinels-present",
        )
        return None, False
    action = "poweroff" if session_runtime.SHUTDOWN_SENTINEL in consumed else "reboot"
    started = time.monotonic()
    try:
        completed = subprocess.run(
            ["loginctl", action],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except OSError as error:
        _log(
            "logind",
            action,
            "failed",
            started,
            f"loginctl-{type(error).__name__}",
        )
        return action, False
    _log(
        "logind",
        action,
        "accepted" if completed.returncode == 0 else "failed",
        started,
        "none" if completed.returncode == 0 else f"loginctl-exit-{completed.returncode}",
    )
    return action, completed.returncode == 0


def _selected_mode(directory_fd: int, owner_uid: int) -> str:
    try:
        value = session_runtime.read_selector(directory_fd, owner_uid)
    except (OSError, ValueError):
        try:
            metadata = os.stat(
                session_runtime.SELECTOR_NAME,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                os.unlink(session_runtime.SELECTOR_NAME, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
        _log(
            "selector-repair",
            "steam",
            "invalid-selector-removed",
            time.monotonic(),
            "console-session-selector-invalid",
        )
        return "steam"
    return value or "steam"


def _print_plan() -> int:
    try:
        directory_fd, _runtime_path, owner = session_runtime.open_runtime()
    except (OSError, ValueError) as error:
        print(f"console-session-plan-invalid:{type(error).__name__}", file=sys.stderr)
        return 1
    try:
        try:
            mode = session_runtime.read_selector(directory_fd, owner.pw_uid) or "steam"
        except (OSError, ValueError) as error:
            mode = "steam"
            print(
                f"console-session-plan-selector-invalid:steam-fallback:{type(error).__name__}",
                file=sys.stderr,
            )
    finally:
        os.close(directory_fd)

    if mode == "steam":
        env = _session_environment()
        argv = _session_argv()
    else:
        env = _desktop_environment()
        argv = ["sway"]
    print(f"# selected-mode: {mode}")
    for key in sorted(set(os.environ) - set(env)):
        print("unset " + shlex.quote(key))
    for key, value in sorted(env.items()):
        if os.environ.get(key) != value:
            print(f"export {key}={shlex.quote(value)}")
    print("exec " + shlex.join(argv))
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
    retry_delays = {
        "desktop": INITIAL_RETRY_DELAY_SECONDS,
        "steam": INITIAL_RETRY_DELAY_SECONDS,
    }
    fast_failure_streaks = {"desktop": 0, "steam": 0}
    try:
        while True:
            mode = _selected_mode(directory_fd, owner.pw_uid)
            if mode == "steam":
                try:
                    _clear_stale_sentinels(directory_fd)
                except OSError as error:
                    _log(
                        "clear-stale-sentinels",
                        "steam",
                        "failed",
                        time.monotonic(),
                        f"sentinel-clear-{type(error).__name__}",
                    )
                    time.sleep(1)
                    continue
                argv_out = _session_argv()
                env = _session_environment()
            else:
                argv_out = ["sway"]
                env = _desktop_environment()
            _status, launch_error, duration = _run_child(argv_out, env, mode)
            if launch_error == "session-interrupted":
                return 0
            if mode == "steam" and launch_error is None:
                try:
                    action, accepted = _power_action(directory_fd)
                except OSError as error:
                    _log(
                        "consume-power-sentinels",
                        "steam",
                        "failed",
                        time.monotonic(),
                        f"sentinel-consume-{type(error).__name__}",
                    )
                    action, accepted = None, False
                if action is not None and accepted:
                    return 0
            if _selected_mode(directory_fd, owner.pw_uid) != mode:
                _reset_retry_state(retry_delays, fast_failure_streaks)
                continue
            if duration >= FAST_FAILURE_WINDOW_SECONDS:
                retry_delays[mode] = INITIAL_RETRY_DELAY_SECONDS
                fast_failure_streaks[mode] = 0
                continue

            streak = min(
                fast_failure_streaks[mode] + 1,
                DESKTOP_FAST_FAILURE_LIMIT,
            )
            fast_failure_streaks[mode] = streak
            delay = retry_delays[mode]
            retry_delays[mode] = min(delay * 2, MAX_RETRY_DELAY_SECONDS)
            if mode == "desktop" and streak >= DESKTOP_FAST_FAILURE_LIMIT:
                fallback = _fallback_to_steam(directory_fd, owner)
                if fallback in {"changed", "selector-changed"}:
                    _reset_retry_state(retry_delays, fast_failure_streaks)
                    continue
            time.sleep(delay)
    finally:
        os.close(directory_fd)


if __name__ == "__main__":
    raise SystemExit(main())

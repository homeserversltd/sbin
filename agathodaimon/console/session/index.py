"""Resolve and launch the stateless Gamescope Steam session."""
from __future__ import annotations

import json
import os
import shlex
import sys
import time
from pathlib import Path
from typing import Any, Sequence

sys.path.insert(0, str(Path(__file__).parents[3]))

from agathodaimon.settings.display import policy


def _refresh_text(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("invalid-configured-refresh")
    return format(value, ".15g")


def _dimensionless_fallback(configured_refresh: str, signal: str) -> list[str]:
    print(signal, file=sys.stderr)
    return ["gamescope", "-e", "-r", configured_refresh, "--", "steam", "-gamepadui"]


def _session_argv() -> list[str]:
    try:
        loaded = policy.load_settings()
        settings = {**loaded, **policy.validate_settings(loaded)}
        configured_refresh = _refresh_text(settings["refresh_rate"])
    except Exception:
        print(policy.DISPLAY_SETTING_UNREAD_DEFAULTS, file=sys.stderr)
        settings = {"resolution": "auto", "refresh_rate": policy.DEFAULT_REFRESH_RATE,
                    "source": "defaults", "fallback": "settings-read-failed",
                    "defaulted": ["resolution", "refresh_rate"]}
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
        signal = ("display-no-connected-screen" if isinstance(resolved, dict)
                  and resolved.get("reason") == "no-connected-screen"
                  else "display-no-eligible-progressive-mode")
        return _dimensionless_fallback(configured_refresh, signal)
    mode = resolved.get("mode")
    if not isinstance(mode, dict):
        return _dimensionless_fallback(configured_refresh, "display-resolved-mode-missing")
    width, height = mode.get("width"), mode.get("height")
    if (isinstance(width, bool) or not isinstance(width, int) or width <= 0
            or isinstance(height, bool) or not isinstance(height, int) or height <= 0):
        return _dimensionless_fallback(configured_refresh, "display-resolved-mode-invalid")
    rate = mode.get("vrefresh")
    if isinstance(rate, bool) or not isinstance(rate, int) or rate <= 0:
        return _dimensionless_fallback(configured_refresh, "display-advertised-integer-refresh-missing")
    mode_reason = str(resolved.get("reason", "resolved"))
    mode_reason += ";gamescope-first-matching-timing-for-equal-integer-tuples;physical-fractional-rate-not-guaranteed"
    print(f"display-mode-reason={mode_reason}", file=sys.stderr)
    return [
        "gamescope", "-e", "-W", str(width), "-H", str(height),
        "-r", str(rate), "--", "steam", "-gamepadui",
    ]


def _log_exec(outcome: str, started: float, signal: str = "none") -> None:
    line = {
        "who": "agathodaimon", "verb": "exec", "target": "gamescope",
        "outcome": outcome,
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "signal": signal[:128],
    }
    print(json.dumps(line, sort_keys=True, separators=(",", ":")), file=sys.stderr)


def main(argv: Sequence[str] | None = None) -> int:
    started = time.monotonic()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in ([], ["--print"]):
        print("usage: console session [--print]", file=sys.stderr)
        return 2
    argv_out = _session_argv()
    if arguments == ["--print"]:
        print(shlex.join(argv_out))
        return 0
    os.environ["MANGOHUD"] = "1"
    os.environ["SDL_GAMECONTROLLERCONFIG"] = os.environ.get("SDL_GAMECONTROLLERCONFIG", "")
    _log_exec("handoff", started)
    try:
        os.execvp("gamescope", argv_out)
    except OSError as exc:
        _log_exec("failed", started, f"gamescope-exec-failed:{type(exc).__name__}")
        return 127
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

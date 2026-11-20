#!/usr/bin/env python3
"""Observe and refresh the owner's desktop launcher cache."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

from agathodaimon.face._shared import refresh_launcher_cache

DEFAULT_OWNER_HOME = "/home/owner"
REFRESH_STDERR_MAX_LINES = 20
REFRESH_STDERR_MAX_CHARS = 4096
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|access[_-]?key|credential|pin)\b"
    r"(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_BEARER_VALUE = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]+")
_BASIC_VALUE = re.compile(r"(?i)\b(Basic\s+)[A-Za-z0-9+/=]+")
_URL_USERINFO = re.compile(r"(?i)(https?://)[^\s/@]+@")


def bounded_stderr_tail(stderr: bytes | str | None) -> str | None:
    if not stderr:
        return None
    text = stderr.decode("utf-8", errors="replace") if isinstance(stderr, bytes) else stderr
    tail = "\n".join(text.splitlines()[-REFRESH_STDERR_MAX_LINES :])
    tail = _SECRET_ASSIGNMENT.sub(r"\1\2[redacted]", tail)
    tail = _BEARER_VALUE.sub(r"\1[redacted]", tail)
    tail = _BASIC_VALUE.sub(r"\1[redacted]", tail)
    tail = _URL_USERINFO.sub(r"\1[redacted]@", tail)
    tail = tail[-REFRESH_STDERR_MAX_CHARS :]
    return tail or None


def owner_home() -> Path:
    return Path(os.environ.get("CADUCEUS_LAUNCHER_HOME", DEFAULT_OWNER_HOME))


def cache_directory() -> Path:
    override = os.environ.get("CADUCEUS_LAUNCHER_CACHE_DIR")
    return Path(override) if override is not None else owner_home() / ".cache"


def refresh_script() -> Path:
    override = os.environ.get("CADUCEUS_LAUNCHER_REFRESH_SCRIPT")
    return Path(override) if override is not None else owner_home() / "bin/refresh-launcher-cache.sh"


def input_directories() -> list[Path]:
    home = owner_home()
    return [
        home / ".local/share/applications",
        Path("/usr/local/share/applications"),
        Path("/usr/share/applications"),
    ]


def newest_mtime(path: Path) -> int | None:
    try:
        return path.stat().st_mtime_ns if path.is_file() else None
    except OSError:
        return None


def state() -> str:
    cache_mtimes = [
        mtime
        for item in cache_directory().glob("ksycoca6_*")
        if (mtime := newest_mtime(item)) is not None
    ]
    if not cache_mtimes:
        return "Different"
    cache_mtime = max(cache_mtimes)
    newest_input = 0
    for directory in input_directories():
        try:
            items = directory.rglob("*.desktop") if directory.is_dir() else ()
            for item in items:
                mtime = newest_mtime(item)
                if mtime is not None:
                    newest_input = max(newest_input, mtime)
        except OSError:
            continue
    refresh_mtime = newest_mtime(refresh_script())
    if refresh_mtime is not None:
        newest_input = max(newest_input, refresh_mtime)
    return "Empty" if cache_mtime >= newest_input else "Different"


def refresh_command() -> list[str] | None:
    override = os.environ.get("CADUCEUS_LAUNCHER_REFRESH_COMMAND")
    if override is None:
        return None
    command = shlex.split(override)
    if not command:
        raise ValueError("launcher-refresh-command-empty")
    return command


def _apply() -> int:
    before: str | None = None
    before_blocker: str | None = None
    final: str | None = None
    final_blocker: str | None = None
    refresh_error: str | None = None
    refresh_exit: int | None = None
    refresh_stderr_tail: str | None = None

    try:
        before = state()
    except (OSError, ValueError) as error:
        before_blocker = str(error)

    try:
        command = refresh_command()
        if command is None:
            native = refresh_launcher_cache(owner_home())
            refresh_exit = native["exit"]
            refresh_stderr_tail = bounded_stderr_tail(native.get("stderr"))
        else:
            result = subprocess.run(command, check=False, capture_output=True)
            refresh_exit = result.returncode
            refresh_stderr_tail = bounded_stderr_tail(result.stderr)
    except (OSError, ValueError) as error:
        refresh_error = str(error)

    try:
        final = state()
    except (OSError, ValueError) as error:
        final_blocker = str(error)

    changed = before != final if before is not None and final is not None else None
    if before_blocker is not None:
        signal = "launcher-cache-observation-failed"
    elif refresh_error is not None or refresh_exit != 0:
        signal = "launcher-cache-refresh-failed"
    elif final_blocker is not None:
        signal = "launcher-cache-readback-failed"
    elif final != "Empty":
        signal = "launcher-cache-not-converged"
    else:
        signal = "none"

    if before_blocker is not None:
        print(before_blocker, file=sys.stderr)
    if refresh_error is not None:
        print(refresh_error, file=sys.stderr)
    if refresh_exit not in (None, 0):
        print("launcher cache refresh failed", file=sys.stderr)
        if refresh_stderr_tail is not None:
            print(refresh_stderr_tail, file=sys.stderr)
    if final == "Different":
        print("launcher cache remains missing or stale after refresh", file=sys.stderr)
    if final_blocker is not None:
        print(final_blocker, file=sys.stderr)
    ok = signal == "none"
    print(json.dumps({"ok": ok, "firstMissingSignal": signal, "changed": changed}))
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--check"]:
        try:
            observed = state()
        except (OSError, ValueError) as error:
            print(str(error), file=sys.stderr)
            print(json.dumps({"ok": False, "firstMissingSignal": "launcher-cache-observation-failed"}))
            return 1
        print(json.dumps({"ok": True, "firstMissingSignal": "none", "observed": {"state": observed}}))
        return 0
    if args == ["--apply"]:
        return _apply()
    print("usage: launcher-cache --check|--apply", file=sys.stderr)
    print(json.dumps({"ok": False, "firstMissingSignal": "gui-launcher-cache-arguments-invalid"}))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

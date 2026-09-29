#!/usr/bin/env python3
"""Observe and refresh the owner's desktop launcher cache."""

from __future__ import annotations

import contextlib
import os
import shlex
import subprocess
import sys
import uuid
from pathlib import Path

from agathodaimon.lib.receipts.index import emit

DEFAULT_OWNER_HOME = "/home/owner"
DEFAULT_RECEIPT_ROOT = "/var/lib/caduceus/receipts"


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


def refresh_command() -> list[str]:
    override = os.environ.get("CADUCEUS_LAUNCHER_REFRESH_COMMAND")
    if override is not None:
        command = shlex.split(override)
        if not command:
            raise ValueError("launcher-refresh-command-empty")
        return command
    return ["/usr/bin/sudo", "--user", "owner", "--", str(refresh_script())]


def _write_apply_receipt(receipt: dict) -> bool:
    run_id = uuid.uuid4().hex
    receipt_path = (
        Path(os.environ.get("CADUCEUS_RECEIPT_ROOT", DEFAULT_RECEIPT_ROOT))
        / run_id
        / "run.json"
    )
    try:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with receipt_path.open("x", encoding="utf-8") as stream:
            with contextlib.redirect_stdout(stream):
                emit({**receipt, "run_id": run_id})
            stream.flush()
            os.fsync(stream.fileno())
    except (OSError, TypeError, ValueError):
        print("caduceus-receipt-write-failed", file=sys.stderr)
        return False
    return True


def _apply() -> int:
    before: str | None = None
    before_blocker: str | None = None
    final: str | None = None
    final_blocker: str | None = None
    refresh_error: str | None = None
    refresh_exit: int | None = None
    touched_paths: list[str] = []
    steps: list[dict] = []

    try:
        before = state()
        steps.append({"name": "observe-before", "outcome": "succeeded", "state": before})
    except (OSError, ValueError) as error:
        before_blocker = str(error)
        steps.append({"name": "observe-before", "outcome": "failed"})

    try:
        command = refresh_command()
        result = subprocess.run(command, check=False, capture_output=True)
        refresh_exit = result.returncode
        touched_paths.append(str(cache_directory()))
        steps.append(
            {
                "name": "owner-scoped-refresh",
                "outcome": "succeeded" if refresh_exit == 0 else "failed",
                "exit": refresh_exit,
            }
        )
    except (OSError, ValueError) as error:
        refresh_error = str(error)
        steps.append({"name": "owner-scoped-refresh", "outcome": "failed"})

    try:
        final = state()
        steps.append({"name": "observe-after", "outcome": "succeeded", "state": final})
    except (OSError, ValueError) as error:
        final_blocker = str(error)
        steps.append({"name": "observe-after", "outcome": "failed"})

    changed = before != final if before is not None and final is not None else None
    converged = final == "Empty"
    receipt = {
        "schema": "agathodaimon.launcher-cache.apply.v1",
        "kernel": "caduceus.staff.v1",
        "routine": "agathodaimon.gui.launcher-cache",
        "target": {
            "cache_directory": str(cache_directory()),
            "refresh_script": str(refresh_script()),
        },
        "flags": {"apply": True},
        "ok": (
            before_blocker is None
            and refresh_error is None
            and refresh_exit == 0
            and final_blocker is None
            and converged
        ),
        "changed": changed,
        "touched_paths": touched_paths,
        "observed": (
            {"state": before}
            if before is not None
            else {"state": None, "blocker": before_blocker or "launcher-cache-observation-failed"}
        ),
        "could_change": {"state": "Empty", "path": str(cache_directory())},
        "attempt": {"attempted": True, "steps": steps},
        "final": (
            {"state": final, "converged": converged}
            if final is not None
            else {"state": None, "converged": False, "blocker": final_blocker}
        ),
    }
    receipt_written = _write_apply_receipt(receipt)

    if final is not None:
        print(final)
    if before_blocker is not None:
        print(before_blocker, file=sys.stderr)
    if refresh_error is not None:
        print(refresh_error, file=sys.stderr)
    if refresh_exit not in (None, 0):
        print("launcher cache refresh failed", file=sys.stderr)
    if final == "Different":
        print("launcher cache remains missing or stale after refresh", file=sys.stderr)
    if final_blocker is not None:
        print(final_blocker, file=sys.stderr)
    return 0 if receipt["ok"] and receipt_written else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--check"]:
        try:
            print(state())
            return 0
        except (OSError, ValueError) as error:
            print(str(error), file=sys.stderr)
            return 1
    if args == ["--apply"]:
        return _apply()
    print("usage: launcher-cache --check|--apply", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

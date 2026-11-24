#!/usr/bin/env python3
"""Observe and converge the Caduceus staff venv import-path declaration."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from agathodaimon import _deed

EXPECTED = "/usr/local/sbin\n"
DEFAULT_STAFF_VENV = "/var/lib/caduceus/venv"


def staff_path_file() -> Path:
    venv = Path(os.environ.get("CADUCEUS_STAFF_VENV", DEFAULT_STAFF_VENV))
    try:
        roots = sorted(
            path
            for path in venv.glob("lib/python*/site-packages")
            if path.is_dir()
        )
    except OSError as error:
        raise RuntimeError("caduceus-staff-site-packages-not-unique-or-absent") from error
    if len(roots) != 1:
        raise RuntimeError("caduceus-staff-site-packages-not-unique-or-absent")
    return roots[0] / "caduceus-staff.pth"


def _open_regular(path: Path, flags: int) -> int:
    descriptor = os.open(path, flags | getattr(os, "O_NOFOLLOW", 0))
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError(f"staff path target is not a regular file: {path}")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_existing(path: Path) -> str:
    descriptor = _open_regular(path, os.O_RDONLY)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        return stream.read()


def _observe(path: Path, *, missing_is_different: bool) -> str:
    try:
        target_stat = path.lstat()
    except FileNotFoundError:
        if missing_is_different:
            return "Different"
        raise RuntimeError(f"birth-debt: existing staff path file absent: {path}")
    if stat.S_ISLNK(target_stat.st_mode):
        raise RuntimeError(f"staff path target is a symlink: {path}")
    if not stat.S_ISREG(target_stat.st_mode):
        raise RuntimeError(f"staff path target is not a regular file: {path}")
    return "/usr/local/sbin" if _read_existing(path) == EXPECTED else "Different"


def _apply() -> int:
    path: Path | None = None
    observed: str | None = None
    final: str | None = None
    blocker: str | None = None
    final_blocker: str | None = None
    changed = False
    touched_paths: list[str] = []
    steps: list[dict] = []

    try:
        path = staff_path_file()
        observed = _observe(path, missing_is_different=False)
        steps.append({"name": "observe-before", "outcome": "succeeded", "state": observed})
        if observed == "/usr/local/sbin":
            steps.append({"name": "rewrite-staff-path", "outcome": "not-needed"})
        else:
            descriptor = _open_regular(path, os.O_WRONLY)
            touched_paths.append(str(path))
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                os.ftruncate(stream.fileno(), 0)
                changed = True
                stream.write(EXPECTED)
            steps.append({"name": "rewrite-staff-path", "outcome": "succeeded"})
    except (OSError, RuntimeError, UnicodeError) as error:
        blocker = str(error)
        steps.append({"name": "converge-staff-path", "outcome": "failed"})

    try:
        if path is None:
            path = staff_path_file()
        final = _observe(path, missing_is_different=True)
        steps.append({"name": "observe-after", "outcome": "succeeded", "state": final})
    except (OSError, RuntimeError, UnicodeError) as error:
        final_blocker = str(error)
        steps.append({"name": "observe-after", "outcome": "failed"})

    converged = final == "/usr/local/sbin"
    receipt = {
        "kernel": "caduceus.staff.v1",
        "routine": "agathodaimon.python.staff-path",
        "target": {"path": str(path) if path is not None else None},
        "flags": {"apply": True},
        "ok": blocker is None and final_blocker is None and converged,
        "changed": changed,
        "touched_paths": touched_paths,
        "observed": (
            {"state": observed}
            if observed is not None
            else {"state": None, "blocker": blocker or "staff-path-observation-failed"}
        ),
        "could_change": {
            "state": "/usr/local/sbin",
            "path": str(path) if path is not None else None,
        },
        "attempt": {"attempted": True, "steps": steps},
        "final": (
            {"state": final, "converged": converged}
            if final is not None
            else {"state": None, "converged": False, "blocker": final_blocker}
        ),
    }
    if receipt["changed"] or not receipt["ok"]:
        try:
            _deed.send("sbin", "staff-path", receipt["ok"],
                       signal="staff-path-apply-failed",
                       outcome="changed" if receipt["ok"] else "failed")
        except Exception:
            print("caduceus-deed-post-failed", file=sys.stderr)

    if final is not None:
        print(final)
    if blocker is not None:
        print(blocker, file=sys.stderr)
    if final_blocker is not None:
        print(final_blocker, file=sys.stderr)
    return 0 if receipt["ok"] else 1


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--check"]:
        try:
            print(_observe(staff_path_file(), missing_is_different=True))
            return 0
        except (OSError, RuntimeError, UnicodeError) as error:
            print(str(error), file=sys.stderr)
            return 1
    if args == ["--apply"]:
        return _apply()
    print("usage: staff-path --check|--apply", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

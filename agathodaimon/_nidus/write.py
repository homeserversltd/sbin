"""One in-memory compensation walk for file-editing stops.

Each edit is a mapping with path, candidate (bytes or None), and optional
mode and owner (user, group). Callbacks either return normally or raise.
Only per-file renames are atomic; this is not a crash-atomic transaction.
"""
from __future__ import annotations

import grp
import hashlib
import os
import pwd
import stat
import tempfile
from pathlib import Path
from typing import Any


class WriteError(RuntimeError):
    def __init__(self, cause: Exception, parts: dict[str, Any], restore_errors: list[Exception]):
        self.cause = cause
        self.parts = parts
        self.restore_errors = restore_errors
        message = str(cause)
        if restore_errors:
            message += "; restore failed: " + "; ".join(map(str, restore_errors))
        super().__init__(message)


def _digest(data: bytes | None) -> str | None:
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _put(path: Path, data: bytes | None, mode: int, owner: tuple[int, int] | None, on_changed=None) -> None:
    if data is None:
        path.unlink(missing_ok=True)
        if on_changed is not None:
            on_changed()
        return
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            if owner is not None:
                os.fchown(handle.fileno(), *owner)
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
        os.replace(name, path)
        if on_changed is not None:
            on_changed()
    finally:
        Path(name).unlink(missing_ok=True)


def write(edits, *, check=None, verify=None, reload=None, readback=None):
    """Validate, replace, verify, reload and observe, compensating on fault."""
    snapshots = []
    paths = set()
    steps = []
    parts = {"observed": [], "could_change_to": [],
             "attempt": {"attempted": False, "steps": steps},
             "final_receipt": {"ok": False, "firstMissingSignal": "none"},
             "changed": False}
    phase = "observe"
    touched = False
    try:
        for edit in edits:
            path = Path(edit["path"])
            if path in paths:
                raise ValueError("duplicate target")
            paths.add(path)
            candidate = edit["candidate"]
            if candidate is not None and not isinstance(candidate, bytes):
                raise TypeError("candidate must be bytes or None")
            try:
                st = path.lstat()
                if not stat.S_ISREG(st.st_mode):
                    raise ValueError("target is not a regular file")
                before = path.read_bytes()
                old_mode, old_owner = stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)
            except FileNotFoundError:
                before, old_mode, old_owner = None, 0o644, None
            owner = edit.get("owner")
            desired_owner = (pwd.getpwnam(owner[0]).pw_uid, grp.getgrnam(owner[1]).gr_gid) if owner else None
            snapshots.append((path, candidate, before, old_mode, old_owner, edit.get("mode", old_mode), desired_owner))
            parts["observed"].append({"path": str(path), "before": _digest(before), "after": _digest(before)})
            parts["could_change_to"].append(str(path))
        changed = any(candidate != before for _, candidate, before, *_ in snapshots)
        parts["changed"] = changed
        parts["attempt"]["attempted"] = changed

        def run(name, callback):
            nonlocal phase
            if callback is None:
                return
            phase = name
            row = {"step": name, "outcome": "failed"}
            steps.append(row)
            callback()
            row["outcome"] = "ok"

        def mark_touched():
            nonlocal touched
            touched = True

        run("check", check)
        if changed:
            for path, candidate, before, _old_mode, _old_owner, mode, owner in snapshots:
                if candidate == before:
                    continue
                phase = "replace"
                row = {"step": "replace", "path": str(path), "outcome": "failed"}
                steps.append(row)
                _put(path, candidate, mode, owner, on_changed=mark_touched)
                for observed in parts["observed"]:
                    if observed["path"] == str(path):
                        observed["after"] = _digest(candidate)
                        break
                row["outcome"] = "ok"
            run("verify", verify)
            run("reload", reload)
        run("readback", readback)
        parts["final_receipt"] = {"ok": True, "firstMissingSignal": "none"}
        return parts
    except Exception as exc:
        errors = []
        if touched:
            for path, _candidate, before, mode, owner, *_ in snapshots:
                row = {"step": "restore", "path": str(path), "outcome": "failed"}
                steps.append(row)
                try:
                    _put(path, before, mode, owner)
                    for observed in parts["observed"]:
                        if observed["path"] == str(path):
                            observed["after"] = _digest(before)
                            break
                    row["outcome"] = "ok"
                except Exception as restore_error:
                    row["error_type"] = type(restore_error).__name__
                    errors.append(restore_error)
            if reload is not None:
                row = {"step": "reload-again", "outcome": "failed"}
                steps.append(row)
                try:
                    reload()
                    row["outcome"] = "ok"
                except Exception as reload_error:
                    errors.append(reload_error)
        parts["final_receipt"] = {"ok": False, "firstMissingSignal": phase + "-failed"}
        raise WriteError(exc, parts, errors) from exc

"""Observe configured NAS folders on an already attached role."""
from __future__ import annotations

import grp
import io
import json
import os
import posixpath
import pwd
import stat
import sys
from typing import Any, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.storage.nas.runtime import (
    MAX_INPUT, Refusal, _info_for, _mount_for_target, _mount_readback, _mountinfo,
    _observed_holder_info, _record, _require_root, _role_info, guarded_drive, role_partition,
)
from agathodaimon.storage.nas.setup.index import PORTAL_FOLDER_LAYOUT, _open_directory_nofollow, _read_regular_nofollow

SCHEMA = "caduceus.nas.folders.v1"


def _failure(signal: str, step: str, role: str | None = None) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": False, "firstMissingSignal": signal, "role": role,
            "partition": None, "mapper": None, "mountpoint": None, "applications": 0,
            "steps": [], "failedStep": step, "mutationPerformed": False,
            "paths": [], "differences": [], "absent": []}


def _read_request():
    raw = sys.stdin.buffer.read(MAX_INPUT + 1)
    if not raw or len(raw) > MAX_INPUT:
        raise ValueError("request-size-invalid")
    previous = sys.stdin
    try:
        sys.stdin = io.StringIO(raw.decode("utf-8"))
        return read_envelope(known_fields=("role",))
    finally:
        sys.stdin = previous


def _raw_config(receipt: dict[str, Any], mountpoint: str) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    try:
        raw, _ = _read_regular_nofollow("/etc/appliance/config.json")
        nas = json.loads(raw.decode("utf-8"))["global"]["permissions"]["nas"]
        base, applications = nas["basePath"], nas["applications"]
        included = nas.get("includedPermissions", {})
        users, groups = included.get("user", []), included.get("group", [])
        if (not isinstance(base, str) or not base.startswith("/") or base.startswith("//")
                or posixpath.normpath(base) != base or not isinstance(applications, dict)
                or not applications or not isinstance(users, list) or not isinstance(groups, list)
                or not all(isinstance(x, str) for x in users + groups)):
            raise ValueError("invalid config")
        entries = []
        for name, app in sorted(applications.items()):
            user, group, mode = app["user"], app["group"], app["permissions"]
            paths = app["paths"]
            include = app.get("includeIncludedPermissions", False)
            if (not isinstance(name, str) or not isinstance(user, str) or not isinstance(group, str)
                    or not isinstance(paths, list) or not paths or type(include) is not bool):
                raise ValueError("invalid application")
            if isinstance(mode, str) and len(mode) in (3, 4) and all(c in "01234567" for c in mode):
                mode = int(mode, 8)
            if type(mode) is not int or not 0 <= mode <= 0o777:
                raise ValueError("invalid mode")
            for path in paths:
                if not isinstance(path, str) or not path or "\x00" in path or path.startswith("//"):
                    raise ValueError("invalid path")
                if path.startswith("/"):
                    if posixpath.normpath(path) != path or not (path == base or path.startswith(base.rstrip("/") + "/")):
                        raise ValueError("path outside base")
                    relative = path[len(base):].lstrip("/")
                else:
                    relative = path
                if relative and (posixpath.normpath(relative) != relative or any(p in ("", ".", "..") for p in relative.split("/"))):
                    raise ValueError("invalid path")
                entries.append({"application": name, "path": posixpath.join(mountpoint, relative) if relative else mountpoint,
                                "configuredUser": user, "configuredGroup": group, "configuredMode": f"{mode:04o}",
                                "includeIncludedPermissions": include})
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError, AttributeError):
        _record(receipt, "config-preflight", False, source="/etc/appliance/config.json", observed="invalid-or-unreadable")
        raise Refusal("agathodaimon-nas-config-invalid", "config-preflight") from None
    _record(receipt, "config-preflight", True, source="/etc/appliance/config.json", applicationCount=len(applications))
    receipt["applications"] = len(applications)
    return entries, {"user": users, "group": groups}


def _identity(value: int, lookup: Any, field: str) -> str:
    try:
        return getattr(lookup(value), field)
    except KeyError:
        return str(value)


def _observe_layout(receipt: dict[str, Any], role: str, mountpoint: str,
                    entries: list[dict[str, Any]], included: dict[str, list[str]]) -> None:
    rows = list(entries)
    for relative, user, group, mode in PORTAL_FOLDER_LAYOUT[role]:
        rows.append({"application": None, "path": posixpath.join(mountpoint, relative) if relative else mountpoint,
                     "configuredUser": user, "configuredGroup": group, "configuredMode": f"{mode:04o}",
                     "includeIncludedPermissions": False})
    try:
        root = _open_directory_nofollow(mountpoint)
    except OSError:
        raise Refusal("agathodaimon-nas-mounted-root-unreadable", "layout-readback") from None
    try:
        root_dev = os.fstat(root).st_dev
        for row in rows:
            relative = row["path"][len(mountpoint):].lstrip("/")
            fd = os.dup(root)
            metadata = None
            try:
                parts = relative.split("/") if relative else []
                if not parts:
                    metadata = os.fstat(fd)
                for index, part in enumerate(parts):
                    if index == len(parts) - 1:
                        metadata = os.stat(part, dir_fd=fd, follow_symlinks=False)
                    else:
                        child = os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=fd)
                        os.close(fd)
                        fd = child
                        if os.fstat(fd).st_dev != root_dev:
                            raise OSError("nested mount")
            except FileNotFoundError:
                metadata = None
            except OSError:
                raise Refusal("agathodaimon-nas-layout-unreadable", "layout-readback") from None
            finally:
                os.close(fd)
            result = dict(row, exists=metadata is not None, kind=None, owner=None, group=None, mode=None, matches=False)
            if metadata is not None:
                if metadata.st_dev != root_dev:
                    raise Refusal("agathodaimon-nas-path-escape", "layout-readback")
                result.update(kind="directory" if stat.S_ISDIR(metadata.st_mode) else "file" if stat.S_ISREG(metadata.st_mode) else "symlink" if stat.S_ISLNK(metadata.st_mode) else "other",
                              owner=_identity(metadata.st_uid, pwd.getpwuid, "pw_name"),
                              group=_identity(metadata.st_gid, grp.getgrgid, "gr_name"), mode=f"{stat.S_IMODE(metadata.st_mode):04o}")
                users = included["user"] if row["includeIncludedPermissions"] else []
                groups = included["group"] if row["includeIncludedPermissions"] else []
                result["matches"] = (result["owner"] in [row["configuredUser"], *users]
                                     and result["group"] in [row["configuredGroup"], *groups]
                                     and result["mode"] == row["configuredMode"])
            receipt["paths"].append(result)
            if not result["matches"]:
                receipt["differences"].append(result)
            if not result["exists"] and row["application"] is not None:
                receipt["absent"].append(row["path"])
    finally:
        os.close(root)
    _record(receipt, "layout-readback", not receipt["absent"], pathCount=len(rows), absentCount=len(receipt["absent"]))
    if receipt["absent"]:
        raise Refusal("agathodaimon-nas-layout-absent", "layout-readback")


def _attached_info(role: str, receipt: dict[str, Any]) -> dict[str, Any]:
    _require_root(receipt)
    role_info = _role_info(role)
    receipt.update(mapper=role_info["mapper"], mountpoint=role_info["mountpoint"])
    mount = _mount_for_target(_mountinfo(), role_info["mountpoint"])
    if mount is None:
        raise Refusal("agathodaimon-nas-folders-mount-absent", "mount-readback")
    if mount["fstype"] != "xfs":
        raise Refusal("agathodaimon-nas-folders-filesystem-not-xfs", "mount-readback")
    partition = role_partition(role)
    receipt["partition"] = partition
    info = _observed_holder_info(receipt, _info_for(role, partition))
    receipt["mapper"] = info["mapper"]
    observed = _mount_readback(info)
    _record(receipt, "mount-readback", bool(observed.get("sourceMatches")), **observed)
    if observed.get("mounted") is not True:
        raise Refusal("agathodaimon-nas-folders-mount-absent", "mount-readback")
    if observed.get("fstype") != "xfs":
        raise Refusal("agathodaimon-nas-folders-filesystem-not-xfs", "mount-readback")
    if observed.get("sourceMatches") is not True:
        raise Refusal("agathodaimon-nas-folders-mapper-mismatch", "mount-readback")
    return info


@guarded_drive
def _observe(role: str, receipt: dict[str, Any]) -> None:
    info = _attached_info(role, receipt)
    entries, included = _raw_config(receipt, info["mountpoint"])
    _observe_layout(receipt, role, info["mountpoint"], entries, included)
    receipt.update(ok=True, firstMissingSignal="none", failedStep=None)


def dispatch(request: Any) -> dict[str, Any]:
    role = request.payload.get("role")
    receipt = _failure("agathodaimon-nas-not-complete", "request", role if isinstance(role, str) else None)
    try:
        if "role" not in request.payload:
            raise Refusal("agathodaimon-nas-invalid-envelope", "request")
        _role_info(role)
        _observe(role, receipt)
    except Refusal as failure:
        receipt.update(ok=False, firstMissingSignal=failure.signal_name, failedStep=failure.step)
    except Exception:
        receipt.update(ok=False, firstMissingSignal="agathodaimon-nas-folders-aborted", failedStep="folders")
    return attach_envelope(receipt, request)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        receipt = dispatch(_read_request())
    except (ValueError, UnicodeError, json.JSONDecodeError, EnvelopeError):
        receipt = _failure("agathodaimon-nas-invalid-envelope", "request-envelope")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

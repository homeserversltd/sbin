"""Root-only, single-door NAS disk setup transaction."""
from __future__ import annotations

import fcntl
import json
import os
import posixpath
import pwd
import grp
import re
import secrets
import signal
import shlex
import stat
import subprocess
import sys
import io
from pathlib import Path
from typing import Any, Callable, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.lib.keyman_export.index import KeymanExportError, export_key

SCHEMA = "caduceus.nas.setup.v1"
MAX_INPUT = 65536
LOCK_PATH = "/run/lock/agathodaimon-nas-setup.lock"
CONFIG_PATHS = ("/etc/appliance/config.json", "/etc/appliance/config.factory")
SYS_DEV_BLOCK = Path("/sys/dev/block")
MOUNTINFO = Path("/proc/self/mountinfo")
UNIT_DIR = Path("/etc/systemd/system")
KEYMAN_CREATE = "/vault/keyman/keyman-crypto"
KEYMAN_DELETE = "/vault/keyman/deletekey.sh"
MOUNT_DRIVE = "/vault/scripts/mountDrive.sh"
SGDISK = "/usr/sbin/sgdisk"
UDEVADM = "/usr/bin/udevadm"
LSBLK = "/usr/bin/lsblk"
BLKID = "/usr/sbin/blkid"
WIPEFS = "/usr/sbin/wipefs"
CRYPTSETUP = "/usr/sbin/cryptsetup"
MKFS_XFS = "/usr/sbin/mkfs.xfs"
FINDMNT = "/usr/bin/findmnt"
SYSTEMCTL = "/usr/bin/systemctl"
BASH = "/usr/bin/bash"
GPT_LINUX_LUKS_TYPE = "8309"

ROLE = {
    "primary": {
        "service": "nas",
        "partlabel": "homeserver-primary-nas",
        "mountpoint": "/mnt/nas",
    },
    "backup": {
        "service": "nas_backup",
        "partlabel": "homeserver-backup-nas",
        "mountpoint": "/mnt/nas_backup",
    },
}
_SAFE_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._-]{1,128}$")
_SAFE_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_OCTAL_MODE = re.compile(r"^(?:0?[0-7]{3})$")
_MAPPER = re.compile(r"^[A-Za-z0-9._+-]{1,128}_crypt$")
_MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")


class Refusal(Exception):
    def __init__(self, signal_name: str, step: str, return_code: int | None = None):
        super().__init__(signal_name)
        self.signal_name = signal_name
        self.step = step
        self.return_code = return_code


class Interrupted(Refusal):
    pass


_KEYMAN_SIGNAL_MAP = {
    "non-root": "agathodaimon-nas-root-required",
    "uninitialized-system": "agathodaimon-nas-keyman-uninitialized-system",
    "missing-key": "agathodaimon-nas-keyman-missing-key",
    "malformed-key-file": "agathodaimon-nas-keyman-malformed-key-file",
    "preflight-unobservable": "agathodaimon-nas-keyman-preflight-unobservable",
    "service-name-invalid": "agathodaimon-nas-keyman-service-invalid",
    "exchange-artifact-preexisting": "agathodaimon-nas-keyman-exchange-preexisting",
    "exchange-artifact-malformed": "agathodaimon-nas-key-export-invalid",
    "exchange-artifact-raced": "agathodaimon-nas-keyman-exchange-raced",
    "exchange-cleanup-failed": "agathodaimon-nas-keyman-exchange-cleanup-failed",
    "exchange-mount-failed": "agathodaimon-nas-keyman-exchange-mount-failed",
    "exchange-obliteration-failed": "agathodaimon-nas-keyman-exchange-obliteration-failed",
    "export-failed": "agathodaimon-nas-key-export-failed",
    "export-timeout": "agathodaimon-nas-key-export-failed",
    "export-unavailable": "agathodaimon-nas-key-export-failed",
    "scratch-context-invalid": "agathodaimon-nas-key-export-failed",
}


def _safe_step(value: str) -> str:
    return value if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}", value) else "unknown"


def _stop_process_group(process: subprocess.Popen[bytes]) -> bool:
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            previous[signum] = signal.signal(signum, signal.SIG_IGN)
        except ValueError:
            pass
    try:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                return False
        return True
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except ValueError:
                pass


def _run(argv: Sequence[str], input_data: bytes | None = None, timeout: int = 60,
         step: str | None = None) -> subprocess.CompletedProcess[bytes]:
    """Capture child output internally and reap its entire process group."""
    command_step = _safe_step(step or os.path.basename(argv[0]))
    process = None
    try:
        process = subprocess.Popen(list(argv), stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        stdout, stderr = process.communicate(input=input_data, timeout=timeout)
        return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        if process is not None:
            if not _stop_process_group(process):
                raise Refusal("agathodaimon-nas-command-group-unreaped", command_step, process.returncode)
            return_code = process.returncode
        else:
            return_code = None
        raise Refusal("agathodaimon-nas-command-timeout", command_step, return_code)
    except Interrupted:
        if process is not None:
            if not _stop_process_group(process):
                raise Refusal("agathodaimon-nas-command-group-unreaped", command_step)
        raise
    except OSError:
        if process is not None and not _stop_process_group(process):
            raise Refusal("agathodaimon-nas-command-group-unreaped", command_step)
        raise Refusal("agathodaimon-nas-command-unavailable", command_step)


def _record(receipt: dict[str, Any], step: str, ok: bool, **readback: Any) -> None:
    receipt["steps"].append({"step": _safe_step(step), "ok": bool(ok), "readback": readback})


def _export_named_key(receipt: dict[str, Any], service_name: str, step: str) -> bytearray:
    try:
        material = export_key(service_name)
    except KeymanExportError as failure:
        signal_name = _KEYMAN_SIGNAL_MAP.get(failure.signal, "agathodaimon-nas-key-export-failed")
        readback: dict[str, Any] = {"observed": signal_name}
        if failure.return_code is not None:
            readback["rc"] = failure.return_code
        _record(receipt, step, False, **readback)
        raise Refusal(signal_name, step, failure.return_code) from None
    except Exception:
        _record(receipt, step, False, observed="export-unavailable")
        raise Refusal("agathodaimon-nas-key-export-failed", step) from None
    _record(receipt, step, True, present=True, bytes=len(material))
    return material


def _command(receipt: dict[str, Any], step: str, argv: Sequence[str], input_data: bytes | None = None,
             timeout: int = 60) -> subprocess.CompletedProcess[bytes]:
    result = _run(argv, input_data=input_data, timeout=timeout)
    _record(receipt, step, result.returncode == 0, rc=result.returncode)
    if result.returncode != 0:
        raise Refusal("agathodaimon-nas-command-failed", step, result.returncode)
    return result


def _decode_output(result: subprocess.CompletedProcess[bytes], step: str) -> str:
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise Refusal("agathodaimon-nas-readback-invalid", step, result.returncode)


def _read_regular_nofollow(path: str, maximum: int = 1024 * 1024) -> tuple[bytes, os.stat_result]:
    parts = Path(path).parts
    if not Path(path).is_absolute() or any(p in {".", ".."} for p in parts):
        raise OSError("unsafe-path")
    dir_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("/", dir_flags)
    file_fd: int | None = None
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, dir_flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise OSError("not-bounded-regular-file")
        chunks: list[bytes] = []
        size = 0
        while size <= maximum:
            chunk = os.read(file_fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > maximum:
            raise OSError("file-too-large")
        return b"".join(chunks), metadata
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(fd)


def _mountinfo() -> list[dict[str, str]]:
    try:
        raw = MOUNTINFO.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise Refusal("agathodaimon-nas-mount-census-unavailable", "mount-census")
    entries: list[dict[str, str]] = []
    for line in raw.splitlines():
        before, sep, after = line.partition(" - ")
        fields = before.split()
        tail = after.split()
        if not sep or len(fields) < 6 or len(tail) < 2 or not re.fullmatch(r"\d+:\d+", fields[2]):
            raise Refusal("agathodaimon-nas-mount-census-invalid", "mount-census")
        def unescape(value: str) -> str:
            return _MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)
        entries.append({"dev": fields[2], "root": unescape(fields[3]), "target": unescape(fields[4]),
                        "source": unescape(tail[1]), "fstype": tail[0]})
    if not entries:
        raise Refusal("agathodaimon-nas-mount-census-empty", "mount-census")
    return entries


def _sysfs_dev(path: Path) -> str:
    try:
        value = (path / "dev").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph")
    if not re.fullmatch(r"\d+:\d+", value):
        raise Refusal("agathodaimon-nas-block-graph-invalid", "block-graph")
    return value


def _block_graph() -> tuple[dict[str, set[str]], dict[str, str]]:
    """Build undirected identity components from partition and slave ancestry."""
    try:
        names = sorted(os.listdir(SYS_DEV_BLOCK))
    except OSError:
        raise Refusal("agathodaimon-nas-block-graph-unavailable", "block-graph")
    if not names:
        raise Refusal("agathodaimon-nas-block-graph-empty", "block-graph")
    edges: dict[str, set[str]] = {}
    paths: dict[str, str] = {}
    for name in names:
        if not re.fullmatch(r"\d+:\d+", name):
            raise Refusal("agathodaimon-nas-block-graph-invalid", "block-graph")
        link = SYS_DEV_BLOCK / name
        try:
            resolved = link.resolve(strict=True)
        except OSError:
            raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph")
        identity = _sysfs_dev(resolved)
        if identity != name:
            raise Refusal("agathodaimon-nas-block-graph-identity-mismatch", "block-graph")
        edges.setdefault(identity, set())
        paths[identity] = "/dev/" + resolved.name
        parent = None
        if (resolved / "partition").exists():
            parent = _sysfs_dev(resolved.parent)
        if parent:
            edges.setdefault(parent, set()).add(identity)
            edges[identity].add(parent)
        slaves = resolved / "slaves"
        try:
            slave_names = sorted(os.listdir(slaves)) if slaves.is_dir() else []
        except OSError:
            raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph")
        for slave_name in slave_names:
            if not slave_name or "/" in slave_name or slave_name in {".", ".."}:
                raise Refusal("agathodaimon-nas-block-graph-invalid", "block-graph")
            slave = slaves / slave_name
            try:
                slave_resolved = slave.resolve(strict=True)
            except OSError:
                raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph")
            child = _sysfs_dev(slave_resolved)
            edges.setdefault(child, set()).add(identity)
            edges[identity].add(child)
    return edges, paths


def _component(edges: dict[str, set[str]], start: str) -> set[str]:
    if start not in edges:
        raise Refusal("agathodaimon-nas-block-identity-unobserved", "block-graph")
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for other in edges.get(current, set()):
            if other not in seen:
                seen.add(other)
                stack.append(other)
    return seen


def _stat_block(path: str, step: str) -> tuple[int, int, os.stat_result]:
    try:
        metadata = os.stat(path)
    except OSError:
        raise Refusal("agathodaimon-nas-device-unobservable", step)
    if not stat.S_ISBLK(metadata.st_mode):
        raise Refusal("agathodaimon-nas-block-device-required", step)
    return os.major(metadata.st_rdev), os.minor(metadata.st_rdev), metadata


def _device_identity(path: str, step: str) -> str:
    major, minor, _ = _stat_block(path, step)
    return f"{major}:{minor}"


def _lsblk_tree(receipt: dict[str, Any]) -> dict[str, Any]:
    cmd = [LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL"]
    result = _run(cmd)
    if result.returncode != 0:
        _record(receipt, "lsblk-census", False, rc=result.returncode)
        raise Refusal("agathodaimon-nas-block-census-failed", "lsblk-census", result.returncode)
    try:
        value = json.loads(result.stdout.decode("utf-8"))
        devices = value["blockdevices"]
        if not isinstance(devices, list) or not devices:
            raise ValueError
    except (UnicodeError, ValueError, KeyError, TypeError):
        _record(receipt, "lsblk-census", False, observed="invalid")
        raise Refusal("agathodaimon-nas-block-census-invalid", "lsblk-census")
    _record(receipt, "lsblk-census", True, deviceCount=_count_nodes(devices))
    return value


def _count_nodes(nodes: list[dict[str, Any]]) -> int:
    total = 0
    for node in nodes:
        if not isinstance(node, dict):
            raise Refusal("agathodaimon-nas-block-census-invalid", "lsblk-census")
        total += 1
        children = node.get("children", []) or []
        if not isinstance(children, list):
            raise Refusal("agathodaimon-nas-block-census-invalid", "lsblk-census")
        total += _count_nodes(children)
    return total


def _walk_nodes(value: dict[str, Any]):
    stack = list(reversed(value["blockdevices"]))
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.get("children", []) or []))


def _partition_path(device: str) -> str:
    name = os.path.basename(device)
    suffix = "p1" if re.fullmatch(r"(?:nvme\d+n\d+|mmcblk\d+|loop\d+)", name) else "1"
    return device + suffix


def _normalize_pkname(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if value.startswith("/dev/"):
        value = value[len("/dev/"):]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        return None
    return value


def _role_mapper(partition: str) -> str:
    mapper = os.path.basename(partition) + "_crypt"
    if not _MAPPER.fullmatch(mapper):
        raise Refusal("agathodaimon-nas-mapper-invalid", "request")
    return mapper


def _mount_for_target(entries: list[dict[str, str]], target: str) -> dict[str, str] | None:
    found = [entry for entry in entries if entry["target"] == target]
    if len(found) > 1:
        raise Refusal("agathodaimon-nas-mount-ambiguous", "mount-census")
    return found[0] if found else None


def _check_mountpoint_conflict(receipt: dict[str, Any], entries: list[dict[str, str]], mountpoint: str) -> None:
    conflicts = [entry for entry in entries if entry["target"] == mountpoint or entry["target"].startswith(mountpoint + "/")]
    if conflicts:
        _record(receipt, "mountpoint-preflight", False, mounted=True, conflictCount=len(conflicts))
        raise Refusal("agathodaimon-nas-mountpoint-in-use", "mountpoint-preflight")
    try:
        metadata = os.lstat(mountpoint)
    except FileNotFoundError:
        _record(receipt, "mountpoint-preflight", False, exists=False, empty=None)
        raise Refusal("agathodaimon-nas-mountpoint-unavailable", "mountpoint-preflight")
    except OSError:
        _record(receipt, "mountpoint-preflight", False, observed="unreadable")
        raise Refusal("agathodaimon-nas-mountpoint-unreadable", "mountpoint-preflight")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        _record(receipt, "mountpoint-preflight", False, exists=True, directory=False)
        raise Refusal("agathodaimon-nas-mountpoint-not-directory", "mountpoint-preflight")
    try:
        with os.scandir(mountpoint) as iterator:
            nonempty = next(iterator, None) is not None
    except OSError:
        _record(receipt, "mountpoint-preflight", False, exists=True, empty=None)
        raise Refusal("agathodaimon-nas-mountpoint-unreadable", "mountpoint-preflight")
    _record(receipt, "mountpoint-preflight", not nonempty, exists=True, empty=not nonempty)
    if nonempty:
        raise Refusal("agathodaimon-nas-mountpoint-not-empty", "mountpoint-preflight")


def _parse_config(value: Any, mountpoint: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise Refusal("agathodaimon-nas-config-invalid", "config-preflight")
    global_ = value.get("global")
    permissions = global_.get("permissions") if isinstance(global_, dict) else None
    nas = permissions.get("nas") if isinstance(permissions, dict) else None
    if not isinstance(nas, dict):
        raise Refusal("agathodaimon-nas-config-invalid", "config-preflight")
    base = nas.get("basePath")
    if (not isinstance(base, str) or not base.startswith("/") or base.startswith("//") or "\x00" in base
            or posixpath.normpath(base) != base or any(p in {".", ".."} for p in base.split("/"))):
        raise Refusal("agathodaimon-nas-config-base-invalid", "config-preflight")
    applications = nas.get("applications")
    if not isinstance(applications, dict) or not applications:
        raise Refusal("agathodaimon-nas-config-applications-invalid", "config-preflight")
    included = nas.get("includedPermissions", {})
    if not isinstance(included, dict):
        raise Refusal("agathodaimon-nas-config-included-invalid", "config-preflight")
    included_users = included.get("user", [])
    included_groups = included.get("group", [])
    if not isinstance(included_users, list) or not isinstance(included_groups, list):
        raise Refusal("agathodaimon-nas-config-included-invalid", "config-preflight")
    for user in included_users:
        _resolve_user(user)
    for group in included_groups:
        _resolve_group(group)
    compiled: list[dict[str, Any]] = []
    for app_name, app in sorted(applications.items()):
        if not isinstance(app_name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", app_name) or not isinstance(app, dict):
            raise Refusal("agathodaimon-nas-config-application-invalid", "config-preflight")
        user, group, mode = app.get("user"), app.get("group"), app.get("permissions")
        uid, user_name = _resolve_user(user)
        gid, group_name = _resolve_group(group)
        if isinstance(mode, bool) or not (isinstance(mode, str) and _OCTAL_MODE.fullmatch(mode)):
            if not isinstance(mode, int) or mode < 0 or mode > 0o777:
                raise Refusal("agathodaimon-nas-config-mode-invalid", "config-preflight")
            mode_value = mode
        else:
            mode_value = int(mode, 8)
        recursive = app.get("recursive", False)
        include_group = app.get("includeIncludedPermissions", False)
        if type(recursive) is not bool or type(include_group) is not bool:
            raise Refusal("agathodaimon-nas-config-permission-invalid", "config-preflight")
        if include_group and included_groups:
            gid, group_name = _resolve_group(included_groups[0])
        paths = app.get("paths")
        if not isinstance(paths, list) or not paths:
            raise Refusal("agathodaimon-nas-config-paths-invalid", "config-preflight")
        mapped: list[str] = []
        for configured in paths:
            if not isinstance(configured, str) or not configured or "\x00" in configured or configured.startswith("//"):
                raise Refusal("agathodaimon-nas-config-path-invalid", "config-preflight")
            if configured.startswith("/"):
                if posixpath.normpath(configured) != configured or any(p in {".", ".."} for p in configured.split("/")):
                    raise Refusal("agathodaimon-nas-config-path-invalid", "config-preflight")
                if configured == base:
                    relative = ""
                elif configured.startswith(base.rstrip("/") + "/"):
                    relative = configured[len(base.rstrip("/")) + 1:]
                else:
                    raise Refusal("agathodaimon-nas-config-path-outside-base", "config-preflight")
            else:
                parts = configured.split("/")
                if any(p in {"", ".", ".."} for p in parts):
                    raise Refusal("agathodaimon-nas-config-path-invalid", "config-preflight")
                relative = configured
            if relative and (posixpath.normpath(relative) != relative or any(p in {"", ".", ".."} for p in relative.split("/"))):
                raise Refusal("agathodaimon-nas-config-path-invalid", "config-preflight")
            target = posixpath.join(mountpoint, relative) if relative else mountpoint
            if target != mountpoint and not target.startswith(mountpoint + "/"):
                raise Refusal("agathodaimon-nas-config-path-outside-mount", "config-preflight")
            mapped.append(target)
        compiled.append({"application": app_name, "uid": uid, "user": user_name, "gid": gid,
                         "group": group_name, "mode": mode_value, "recursive": recursive, "paths": mapped})
    return {"basePath": base, "applications": compiled, "includedGroups": [str(g) for g in included_groups]}


def _resolve_user(value: Any) -> tuple[int, str]:
    if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
        raise Refusal("agathodaimon-nas-config-user-invalid", "config-preflight")
    try:
        entry = pwd.getpwnam(value)
    except KeyError:
        raise Refusal("agathodaimon-nas-config-user-unknown", "config-preflight")
    return entry.pw_uid, entry.pw_name


def _resolve_group(value: Any) -> tuple[int, str]:
    if not isinstance(value, str) or not _SAFE_NAME.fullmatch(value):
        raise Refusal("agathodaimon-nas-config-group-invalid", "config-preflight")
    try:
        entry = grp.getgrnam(value)
    except KeyError:
        raise Refusal("agathodaimon-nas-config-group-unknown", "config-preflight")
    return entry.gr_gid, entry.gr_name


def _load_config(receipt: dict[str, Any], mountpoint: str) -> dict[str, Any]:
    last_missing = False
    for path in CONFIG_PATHS:
        try:
            raw, _metadata = _read_regular_nofollow(path)
        except FileNotFoundError:
            last_missing = True
            continue
        except (OSError, UnicodeError):
            _record(receipt, "config-preflight", False, source=path, observed="unreadable")
            raise Refusal("agathodaimon-nas-config-unreadable", "config-preflight")
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            _record(receipt, "config-preflight", False, source=path, observed="malformed")
            raise Refusal("agathodaimon-nas-config-invalid", "config-preflight")
        config = _parse_config(value, mountpoint)
        _record(receipt, "config-preflight", True, source=path, applicationCount=len(config["applications"]))
        return config
    _record(receipt, "config-preflight", False, observed="absent")
    raise Refusal("agathodaimon-nas-config-absent", "config-preflight")


def _unit_declares_mountpoint(text: str, mountpoint: str) -> bool:
    conditions: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if "=" not in stripped:
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        if key != "ConditionPathIsMountPoint":
            continue
        if not value:
            conditions.clear()
        else:
            conditions.append(value)
    return mountpoint in conditions


def _list_enabled_nas_services(receipt: dict[str, Any], mountpoint: str) -> list[dict[str, Any]]:
    result = _run([SYSTEMCTL, "list-unit-files", "--type=service", "--no-legend", "--no-pager"])
    if result.returncode != 0:
        _record(receipt, "service-census", False, rc=result.returncode)
        raise Refusal("agathodaimon-nas-service-census-failed", "service-census", result.returncode)
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeError:
        _record(receipt, "service-census", False, observed="invalid")
        raise Refusal("agathodaimon-nas-service-census-invalid", "service-census")
    services: list[dict[str, Any]] = []
    skipped_units: list[str] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 2 or not fields[0].endswith(".service"):
            continue
        unit, enabled_state = fields[0], fields[1]
        if unit.endswith("@.service") or enabled_state in {"alias", "bad", "masked", "not-found"}:
            continue
        enabled = enabled_state in {"enabled", "enabled-runtime"}
        fragment = _run([SYSTEMCTL, "show", unit, "--property=FragmentPath", "--value"])
        cat = _run([SYSTEMCTL, "cat", unit, "--no-pager"])
        failed = cat if cat.returncode != 0 else fragment if fragment.returncode != 0 else None

        fragment_path: str | None = None
        fragment_path_unreadable = False
        try:
            candidate = fragment.stdout.decode("utf-8").strip()
            if candidate and candidate != "/dev/null":
                fragment_path = candidate
            else:
                fragment_path_unreadable = True
        except UnicodeError:
            fragment_path_unreadable = True

        text: str | None = None
        cat_unreadable = False
        try:
            candidate = cat.stdout.decode("utf-8")
            if candidate.strip():
                text = candidate
            else:
                cat_unreadable = True
        except UnicodeError:
            cat_unreadable = True
            candidate = cat.stdout.decode("utf-8", "replace")
            if candidate.strip():
                text = candidate
        if (text is None or cat_unreadable or cat.returncode != 0) and fragment_path is not None:
            try:
                raw, _metadata = _read_regular_nofollow(fragment_path, maximum=1024 * 1024)
            except OSError:
                cat_unreadable = True
            else:
                try:
                    fragment_text = raw.decode("utf-8")
                except UnicodeError:
                    cat_unreadable = True
                    fragment_text = raw.decode("utf-8", "replace")
                text = fragment_text if text is None else fragment_text + "\n" + text

        matches = text is not None and _unit_declares_mountpoint(text, mountpoint)
        unreadable = fragment_path_unreadable or cat_unreadable
        if failed is not None or unreadable:
            failed_rc = failed.returncode if failed is not None else None
            if matches:
                _record(receipt, "service-condition-readback", False, unit=unit, rc=failed_rc,
                        mountpoint=mountpoint, observed="nas-dependent")
                raise Refusal("agathodaimon-nas-service-unit-unreadable", "service-condition-readback",
                              failed_rc)
            skipped_units.append(unit)
            _record(receipt, "service-unit-skipped", True, unit=unit, rc=failed_rc,
                    reason="unit-readback-failed" if failed is not None else "declaration-unreadable",
                    observed="unreadable")
            continue
        if not matches:
            continue
        active_result = _run([SYSTEMCTL, "is-active", unit])
        if active_result.returncode not in {0, 3}:
            _record(receipt, "service-active-preflight", False, unit=unit, rc=active_result.returncode)
            raise Refusal("agathodaimon-nas-service-state-unreadable", "service-active-preflight", active_result.returncode)
        if active_result.returncode == 0 and active_result.stdout.strip() == b"active":
            active = True
        elif active_result.returncode == 3 and active_result.stdout.strip() == b"inactive":
            active = False
        else:
            _record(receipt, "service-active-preflight", False, unit=unit, rc=active_result.returncode,
                    state=active_result.stdout.decode("utf-8", "ignore").strip()[:64])
            raise Refusal("agathodaimon-nas-service-state-unreadable", "service-active-preflight", active_result.returncode)
        services.append({"unit": unit, "enabled": enabled, "activeBefore": active,
                         "condition": mountpoint, "fragment": fragment_path})
    _record(receipt, "service-census", True, nasDependentCount=len(services),
            skippedUnits=skipped_units, skippedUnitCount=len(skipped_units))
    return services


def _unit_file_path(unit: str) -> Path:
    return UNIT_DIR / unit


def _unit_file_identity(path: Path) -> tuple[dict[str, Any], bytes] | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise Refusal("agathodaimon-nas-unit-file-unreadable", "unit-preflight")
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_uid != 0:
        raise Refusal("agathodaimon-nas-unit-file-conflict", "unit-preflight")
    try:
        raw, opened = _read_regular_nofollow(str(path), maximum=1024 * 1024)
    except (OSError, UnicodeError):
        raise Refusal("agathodaimon-nas-unit-file-unreadable", "unit-preflight")
    if (st.st_dev, st.st_ino) != (opened.st_dev, opened.st_ino):
        raise Refusal("agathodaimon-nas-unit-file-raced", "unit-preflight")
    return ({"dev": st.st_dev, "ino": st.st_ino, "uid": st.st_uid, "gid": st.st_gid,
             "mode": stat.S_IMODE(st.st_mode)}, raw)


def _check_unit_conflicts(receipt: dict[str, Any], mountpoint: str, partition: str) -> dict[str, Path]:
    mount_unit = "mnt-nas.mount" if mountpoint == "/mnt/nas" else "mnt-nas_backup.mount"
    paths = {"partition": UNIT_DIR / (os.path.basename(partition) + ".service"), "mount": UNIT_DIR / mount_unit}
    for name, path in paths.items():
        identity = _unit_file_identity(path)
        if identity is not None:
            _record(receipt, "unit-preflight", False, unit=name, exists=True)
            raise Refusal("agathodaimon-nas-unit-conflict", "unit-preflight")
        unit = path.name
        result = _run([SYSTEMCTL, "show", unit, "--property=LoadState", "--value"])
        if result.returncode != 0:
            _record(receipt, "unit-load-preflight", False, unit=unit, rc=result.returncode)
            raise Refusal("agathodaimon-nas-unit-state-unreadable", "unit-load-preflight", result.returncode)
        state = _decode_output(result, "unit-load-preflight")
        if state not in {"", "not-found"}:
            _record(receipt, "unit-load-preflight", False, unit=unit, loadState=state)
            raise Refusal("agathodaimon-nas-unit-conflict", "unit-load-preflight")
    _record(receipt, "unit-preflight", True, unitCount=len(paths))
    return paths


def _validate_vault_and_protected_mounts(receipt: dict[str, Any], target_component: set[str],
                                         edges: dict[str, set[str]], paths: dict[str, str],
                                         entries: list[dict[str, str]]) -> None:
    by_target = {entry["target"]: entry for entry in entries}
    for target in ("/", "/boot", "/vault"):
        entry = by_target.get(target)
        if target == "/vault" and entry is None:
            _record(receipt, "vault-mount-preflight", False, mounted=False)
            raise Refusal("agathodaimon-nas-vault-not-mounted", "vault-mount-preflight")
        if target == "/" and entry is None:
            _record(receipt, "root-mount-preflight", False, mounted=False)
            raise Refusal("agathodaimon-nas-root-mount-unobserved", "root-mount-preflight")
        if entry is None:
            # findmnt --target would resolve /boot to the containing root mount.
            containing = [row for row in entries if target.startswith(row["target"].rstrip("/") + "/")]
            if not containing:
                _record(receipt, "protected-mount-preflight", False, mount=target, observed="unresolved")
                raise Refusal("agathodaimon-nas-protected-mount-unobserved", "protected-mount-preflight")
            entry = max(containing, key=lambda row: len(row["target"]))
        identity = entry["dev"]
        component = _component(edges, identity)
        _record(receipt, "protected-mount-preflight", not bool(component & target_component), mount=target,
                device=identity, graphNodes=len(component))
        if component & target_component:
            raise Refusal("agathodaimon-nas-system-device-refused", "protected-mount-preflight")
    if by_target["/vault"]["fstype"] == "tmpfs" or not by_target["/vault"]["source"].startswith("/dev/"):
        _record(receipt, "vault-source-preflight", False, blockBacked=False)
        raise Refusal("agathodaimon-nas-vault-source-not-block", "vault-source-preflight")


def _preflight(receipt: dict[str, Any], device: str, role: str) -> dict[str, Any]:
    if os.geteuid() != 0:
        _record(receipt, "root-preflight", False, uid=os.geteuid())
        raise Refusal("agathodaimon-nas-root-required", "root-preflight")
    _record(receipt, "root-preflight", True, uid=0)
    identity = _device_identity(device, "device-preflight")
    tree = _lsblk_tree(receipt)
    matches = [node for node in _walk_nodes(tree) if node.get("path") == device]
    if len(matches) != 1:
        _record(receipt, "device-type-preflight", False, observed="missing-or-ambiguous")
        raise Refusal("agathodaimon-nas-device-not-in-block-census", "device-type-preflight")
    node = matches[0]
    dev_type = node.get("type")
    if dev_type not in {"disk", "loop"}:
        _record(receipt, "device-type-preflight", False, deviceType=dev_type)
        raise Refusal("agathodaimon-nas-whole-disk-required", "device-type-preflight")
    if node.get("maj:min") != identity:
        _record(receipt, "device-identity-preflight", False, statIdentity=identity, lsblkIdentity=node.get("maj:min"))
        raise Refusal("agathodaimon-nas-device-identity-mismatch", "device-identity-preflight")
    _record(receipt, "device-type-preflight", True, deviceType=dev_type, identity=identity)
    graph, graph_paths = _block_graph()
    target_component = _component(graph, identity)
    _record(receipt, "block-graph-preflight", True, graphNodes=len(graph), targetComponentNodes=len(target_component))
    entries = _mountinfo()
    _validate_vault_and_protected_mounts(receipt, target_component, graph, graph_paths, entries)
    _record(receipt, "vault-mount-preflight", True, mounted=True)
    mounted_ids = {entry["dev"] for entry in entries if entry["source"].startswith("/dev/") or entry["dev"] != "0:0"}
    for mounted_id in mounted_ids:
        if mounted_id in graph and _component(graph, mounted_id) & target_component:
            _record(receipt, "mounted-device-preflight", False, identity=mounted_id)
            raise Refusal("agathodaimon-nas-device-mounted", "mounted-device-preflight")
    _record(receipt, "mounted-device-preflight", True, observedMounts=len(entries))
    expected = ROLE[role]
    other_label = ROLE["backup" if role == "primary" else "primary"]["partlabel"]
    requested_labels = [row for row in _walk_nodes(tree) if row.get("partlabel") == expected["partlabel"]]
    target_labels = []
    target_stack = [node]
    while target_stack:
        current = target_stack.pop()
        if current.get("partlabel") == other_label:
            target_labels.append(current)
        children = current.get("children", []) or []
        if isinstance(children, list):
            target_stack.extend(children)
    if requested_labels or target_labels:
        _record(receipt, "partlabel-preflight", False, partlabel=expected["partlabel"],
                requestedLabelCount=len(requested_labels), oppositeRoleOnTarget=len(target_labels))
        raise Refusal("agathodaimon-nas-partlabel-already-taken", "partlabel-preflight")
    _record(receipt, "partlabel-preflight", True, partlabel=expected["partlabel"], matches=0)
    partition = _partition_path(device)
    mapper = _role_mapper(partition)
    mapper_path = Path("/dev/mapper") / mapper
    try:
        os.lstat(mapper_path)
    except FileNotFoundError:
        mapper_exists = False
    except OSError:
        raise Refusal("agathodaimon-nas-mapper-unobservable", "mapper-preflight")
    else:
        mapper_exists = True
    _record(receipt, "mapper-preflight", not mapper_exists, mapper=mapper, exists=mapper_exists)
    if mapper_exists:
        raise Refusal("agathodaimon-nas-mapper-conflict", "mapper-preflight")
    _check_mountpoint_conflict(receipt, entries, expected["mountpoint"])
    unit_paths = _check_unit_conflicts(receipt, expected["mountpoint"], partition)
    config = _load_config(receipt, expected["mountpoint"])
    services = _list_enabled_nas_services(receipt, expected["mountpoint"])
    return {"deviceIdentity": identity, "deviceType": dev_type, "partition": partition,
            "mapper": mapper, "mountpoint": expected["mountpoint"], "partlabel": expected["partlabel"],
            "serviceRole": expected["service"], "graph": graph, "targetComponent": target_component,
            "mountinfo": entries, "config": config, "services": services, "unitPaths": unit_paths}


def _probe_block_from_tree(receipt: dict[str, Any], device: str, expected_type: str | None = None) -> dict[str, Any] | None:
    result = _run([LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL", device])
    if result.returncode != 0:
        _record(receipt, "partition-readback", False, rc=result.returncode)
        return None
    try:
        value = json.loads(result.stdout.decode("utf-8"))
        nodes = list(_walk_nodes(value))
    except (UnicodeError, ValueError, KeyError, TypeError, Refusal):
        _record(receipt, "partition-readback", False, observed="invalid")
        return None
    matching = [row for row in nodes if row.get("path") == device]
    if len(matching) != 1:
        _record(receipt, "partition-readback", False, present=False)
        return None
    node = matching[0]
    try:
        stat_identity = _device_identity(device, "partition-readback")
    except Refusal:
        stat_identity = None
    okay = ((expected_type is None or node.get("type") == expected_type)
            and stat_identity is not None and node.get("maj:min") == stat_identity)
    _record(receipt, "partition-readback", okay, present=True, deviceType=node.get("type"), identity=node.get("maj:min"))
    return node if okay else None


def _probe_partlabel(receipt: dict[str, Any], partition: str, expected: str | None = None) -> bool:
    result = _run([BLKID, "-s", "PARTLABEL", "-o", "value", "--", partition])
    observed = _decode_output(result, "partlabel-readback") if result.returncode == 0 else ""
    okay = result.returncode == 0 and (expected is None or observed == expected)
    _record(receipt, "partlabel-readback", okay, matches=okay, partlabel=observed if observed in {ROLE["primary"]["partlabel"], ROLE["backup"]["partlabel"]} else None)
    return okay


def _capture_early_partition_identity(receipt: dict[str, Any], info: dict[str, Any]) -> None:
    """Bind rollback custody only to an exact, newly visible child partition."""
    device, partition = info["device"], info["partition"]
    expected_device = info["deviceIdentity"]
    try:
        device_identity = _device_identity(device, "early-partition-identity")
    except Refusal:
        _record(receipt, "early-partition-identity", False, observed=False,
                reason="whole-device-identity-unavailable")
        return
    if device_identity != expected_device:
        _record(receipt, "early-partition-identity", False, observed=False,
                reason="whole-device-identity-mismatch")
        return
    try:
        result = _run([LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL", device],
                      step="early-partition-identity")
    except Refusal as failure:
        _record(receipt, "early-partition-identity", False, observed=False,
                rc=failure.return_code, reason=failure.signal_name)
        return
    if result.returncode != 0:
        _record(receipt, "early-partition-identity", False, observed=False, rc=result.returncode)
        return
    try:
        value = json.loads(result.stdout.decode("utf-8"))
        nodes = list(_walk_nodes(value))
        roots = [row for row in nodes if row.get("path") == device]
        if (len(roots) != 1 or roots[0].get("type") not in {"disk", "loop"}
                or roots[0].get("maj:min") != expected_device):
            _record(receipt, "early-partition-identity", False, observed=False,
                    reason="whole-device-lsblk-identity-mismatch")
            return
        parent_name = os.path.basename(device)
        candidates = [row for row in nodes if row.get("type") == "part"
                      and _normalize_pkname(row.get("pkname")) == parent_name]
    except (UnicodeError, ValueError, KeyError, TypeError, Refusal):
        _record(receipt, "early-partition-identity", False, observed=False, reason="lsblk-invalid")
        return
    if not candidates:
        # Before udev, GPT may exist before either lsblk or /dev exposes the node.
        _record(receipt, "early-partition-identity", True, observed=False, present=False)
        return
    if len(candidates) != 1 or candidates[0].get("path") != partition:
        _record(receipt, "early-partition-identity", True, observed=False,
                present=True, candidateCount=len(candidates), reason="partition-ambiguous-or-unexpected")
        return
    row_identity = candidates[0].get("maj:min")
    if not isinstance(row_identity, str) or not re.fullmatch(r"\d+:\d+", row_identity):
        _record(receipt, "early-partition-identity", False, observed=False,
                reason="partition-lsblk-identity-invalid")
        return
    try:
        partition_identity = _device_identity(partition, "early-partition-identity")
    except Refusal:
        _record(receipt, "early-partition-identity", True, observed=False,
                present=True, reason="partition-node-not-yet-visible")
        return
    if partition_identity != row_identity:
        _record(receipt, "early-partition-identity", False, observed=False,
                reason="partition-identity-mismatch")
        return
    info["createdPartitionIdentity"] = partition_identity
    _record(receipt, "early-partition-identity", True, observed=True,
            identity=partition_identity, deviceIdentity=device_identity)


def _probe_partition_type(receipt: dict[str, Any], device: str) -> bool:
    result = _run([SGDISK, "--info=1", "--", device])
    if result.returncode != 0:
        _record(receipt, "partition-type-readback", False, rc=result.returncode)
        return False
    try:
        text = result.stdout.decode("utf-8")
    except UnicodeError:
        _record(receipt, "partition-type-readback", False, observed="invalid")
        return False
    matches = re.findall(
        r"(?m)^\s*Partition GUID code:\s*(8309|ca7d7ccb-63ed-4c53-861c-1742536059cc)(?=\s|$|\()",
        text, flags=re.IGNORECASE)
    normalized = [match.lower() for match in matches]
    okay = len(normalized) == 1 and normalized[0] in {
        "8309", "ca7d7ccb-63ed-4c53-861c-1742536059cc"}
    _record(receipt, "partition-type-readback", okay,
            typecode=GPT_LINUX_LUKS_TYPE if okay else None)
    return okay


def _preflight_reobserve(receipt: dict[str, Any], request: dict[str, Any], first: dict[str, Any]) -> dict[str, Any]:
    second = _preflight(receipt, request["device"], request["role"])
    if second["deviceIdentity"] != first["deviceIdentity"]:
        raise Refusal("agathodaimon-nas-device-changed-before-erasure", "device-stability-preflight")
    _record(receipt, "device-stability-preflight", True, identity=second["deviceIdentity"], stable=True)
    return second


def _read_key_file(path: str) -> os.stat_result | None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise Refusal("agathodaimon-nas-key-unobservable", "key-preflight")
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Refusal("agathodaimon-nas-key-conflict", "key-preflight")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        opened = os.fstat(fd)
        os.close(fd)
    except OSError:
        raise Refusal("agathodaimon-nas-key-unreadable", "key-preflight")
    if (st.st_dev, st.st_ino) != (opened.st_dev, opened.st_ino) or not stat.S_ISREG(opened.st_mode):
        raise Refusal("agathodaimon-nas-key-raced", "key-preflight")
    return st


def _key_path(service_role: str) -> str:
    return f"/vault/.keys/{service_role}.key"


def _create_key(receipt: dict[str, Any], service_role: str, info: dict[str, Any]) -> tuple[bytearray, dict[str, Any] | None]:
    path = _key_path(service_role)
    existing = _read_key_file(path)
    if existing is not None:
        _record(receipt, "key-preflight", True, present=True, regular=True)
        return _export_named_key(receipt, service_role, "key-export"), None
    _record(receipt, "key-preflight", True, present=False, regular=False)
    password = secrets.token_hex(32)
    input_data = f"service={service_role}\nusername=nas\npassword={password}\n".encode("utf-8")
    # The creator owns the encrypted record; neither child stream is surfaced.
    result = _run([KEYMAN_CREATE, "create-exclusive", "/dev/stdin"], input_data=input_data, step="key-create")
    del password, input_data
    created = _read_key_file(path)
    created_identity = None
    if result.returncode == 0 and created is not None:
        created_identity = {"dev": created.st_dev, "ino": created.st_ino, "uid": created.st_uid,
                            "mode": stat.S_IMODE(created.st_mode)}
        info["createdKeyIdentity"] = created_identity
    _record(receipt, "key-create", result.returncode == 0 and created is not None,
            rc=result.returncode, created=created is not None, regular=created is not None)
    if result.returncode != 0 or created is None:
        raise Refusal("agathodaimon-nas-key-create-failed", "key-create", result.returncode)
    return _export_named_key(receipt, service_role, "key-export"), created_identity


def _zero(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _luks_is_luks(partition: str) -> tuple[bool, str | None]:
    result = _run([CRYPTSETUP, "isLuks", "--type", "luks2", "--", partition], step="luks-readback")
    if result.returncode == 0:
        return True, "luks2"
    if result.returncode == 1:
        return False, None
    raise Refusal("agathodaimon-nas-luks-readback-failed", "luks-readback", result.returncode)


def _verify_luks2(receipt: dict[str, Any], partition: str) -> None:
    is_luks, _ = _luks_is_luks(partition)
    if not is_luks:
        _record(receipt, "luks-readback", False, isLuks=False, type=None)
        raise Refusal("agathodaimon-nas-luks-readback-missing", "luks-readback")
    dump = _run([CRYPTSETUP, "luksDump", "--", partition], step="luks-readback")
    if dump.returncode != 0:
        _record(receipt, "luks-readback", False, isLuks=True, rc=dump.returncode)
        raise Refusal("agathodaimon-nas-luks-readback-failed", "luks-readback", dump.returncode)
    try:
        version_two = re.search(rb"(?m)^Version:\s*2\s*$", dump.stdout) is not None
    except TypeError:
        version_two = False
    _record(receipt, "luks-readback", version_two, isLuks=True, type="luks2" if version_two else "unknown")
    if not version_two:
        raise Refusal("agathodaimon-nas-luks-version-mismatch", "luks-readback")


def _mapper_state(mapper: str, partition: str | None = None) -> dict[str, Any]:
    path = f"/dev/mapper/{mapper}"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return {"exists": False, "backingMatches": False}
    except OSError:
        raise Refusal("agathodaimon-nas-mapper-readback-failed", "mapper-readback")
    if not stat.S_ISBLK(st.st_mode):
        return {"exists": True, "block": False, "backingMatches": False}
    result = _run([CRYPTSETUP, "status", mapper], step="mapper-readback")
    if result.returncode != 0:
        raise Refusal("agathodaimon-nas-mapper-readback-failed", "mapper-readback", result.returncode)
    backing_matches = None
    if partition is not None:
        graph, _ = _block_graph()
        expected = _device_identity(partition, "mapper-readback")
        actual = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        backing_matches = expected in _component(graph, actual)
    return {"exists": True, "block": True, "identity": f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}",
            "statusRc": result.returncode, "backingMatches": backing_matches}


def _filesystem_type(device: str) -> str | None:
    result = _run([BLKID, "-s", "TYPE", "-o", "value", "--", device], step="xfs-readback")
    if result.returncode != 0:
        return None
    value = _decode_output(result, "xfs-readback")
    return value if value in {"xfs", "crypto_LUKS"} else None


def _unit_values(path: Path) -> dict[str, str]:
    try:
        raw, _ = _read_regular_nofollow(str(path), maximum=1024 * 1024)
        text = raw.decode("utf-8")
    except (OSError, UnicodeError):
        raise Refusal("agathodaimon-nas-helper-unit-unreadable", "helper-unit-readback")
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")) or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _shell_script(value: str) -> str | None:
    try:
        argv = shlex.split(value)
    except ValueError:
        return None
    if not argv or os.path.basename(argv[0]) not in {"bash", "sh"} or argv.count("-c") != 1:
        return None
    index = argv.index("-c")
    return argv[index + 1] if index + 1 < len(argv) else None


def _shell_command(value: str) -> list[str] | None:
    current_text = value
    for _ in range(8):
        try:
            argv = shlex.split(current_text)
        except ValueError:
            return None
        if not argv:
            return None
        if os.path.basename(argv[0]) not in {"bash", "sh"}:
            return argv
        if argv.count("-c") != 1:
            return None
        index = argv.index("-c")
        if index + 1 >= len(argv):
            return None
        current_text = argv[index + 1]
    return None


def _pipeline_parts(command: list[str] | None) -> tuple[list[str], list[str]] | None:
    if command is None or command.count("|") != 1:
        return None
    if any(token in {";", "&&", "||", "&", ">", "<"} for token in command):
        return None
    split = command.index("|")
    if split == 0 or split == len(command) - 1:
        return None
    return command[:split], command[split + 1:]


def _mountdrive_producer_pipeline(info: dict[str, Any]) -> list[str] | None:
    try:
        raw, _metadata = _read_regular_nofollow(MOUNT_DRIVE, maximum=1024 * 1024)
        text = raw.decode("utf-8")
    except (OSError, UnicodeError):
        return None
    candidates = []
    required = ("$NAS_KEY_NAME", "$DEVICE", "$MAPPER_NAME", "luksOpen")
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if (separator and key.strip() == "ExecStart"
                and all(token in value for token in required)):
            candidates.append(value.strip())
    if len(candidates) != 1:
        return None
    command = _shell_script(candidates[0])
    if command is None:
        return None
    replacements = {
        "$NAS_KEY_NAME": info["serviceRole"],
        "$DEVICE": info["partition"],
        "$MAPPER_NAME": info["mapper"],
    }
    for token, value in replacements.items():
        if command.count(token) != 1:
            return None
        command = command.replace(token, value)
    if "$" in command:
        return None
    try:
        pipeline = _pipeline_parts(shlex.split(command))
    except ValueError:
        return None
    if pipeline is None:
        return None
    export_command, open_command = pipeline
    if (not export_command or export_command[-1] != info["serviceRole"]
            or open_command.count("luksOpen") != 1
            or info["partition"] not in open_command or info["mapper"] not in open_command):
        return None
    return export_command + ["|"] + open_command


def _partition_unit_pipeline(raw: bytes) -> list[str] | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        return None
    values = []
    for line in text.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "ExecStart":
            values.append(value.strip())
    if len(values) != 1:
        return None
    return _shell_command(values[0])


def _helper_unit_readback(receipt: dict[str, Any], info: dict[str, Any], paths: dict[str, Path]) -> None:
    observed: dict[str, tuple[dict[str, Any], bytes] | None] = {}
    for name, path in paths.items():
        try:
            identity = _unit_file_identity(path)
        except Refusal:
            identity = None
        observed[name] = identity
        if identity is not None:
            fingerprint, raw = identity
            info.setdefault("createdUnitFiles", {})[name] = {**fingerprint, "bytes": raw}
    missing = [name for name, identity in observed.items() if identity is None]
    if missing:
        for name in missing:
            _record(receipt, "helper-unit-readback", False, unit=name, exists=False)
        raise Refusal("agathodaimon-nas-helper-unit-missing", "helper-unit-readback")
    for name, path in paths.items():
        identity = observed[name]
        assert identity is not None
        fingerprint, raw = identity
        values = _unit_values(path)
        if name == "partition":
            expected_pipeline = _mountdrive_producer_pipeline(info)
            actual_pipeline = _partition_unit_pipeline(raw)
            expected_parts = _pipeline_parts(expected_pipeline)
            actual_parts = _pipeline_parts(actual_pipeline)
            service = info["serviceRole"]
            has_export = (expected_parts is not None and actual_parts is not None
                          and expected_parts[0][-1] == service
                          and actual_parts[0] == expected_parts[0])
            has_open = (expected_parts is not None and actual_parts is not None
                        and "luksOpen" in expected_parts[1]
                        and actual_parts[1] == expected_parts[1])
            pipeline_matches = (expected_pipeline is not None and actual_pipeline == expected_pipeline)
            okay = has_export and has_open and pipeline_matches
            _record(receipt, "helper-unit-readback", okay, unit=path.name,
                    exportRole=has_export, luksOpenMatches=has_open, partition=info["partition"],
                    mapper=info["mapper"])
            if not okay:
                raise Refusal("agathodaimon-nas-helper-boot-command-mismatch", "helper-unit-readback")
        else:
            expected_where = info["mountpoint"]
            expected_what = f"/dev/mapper/{info['mapper']}"
            okay = (values.get("Where") == expected_where and values.get("What") == expected_what
                    and values.get("Type") in {"auto", "xfs"})
            _record(receipt, "helper-unit-readback", okay, unit=path.name, where=values.get("Where"),
                    whatMatches=values.get("What") == expected_what, type=values.get("Type"))
            if not okay:
                raise Refusal("agathodaimon-nas-helper-mount-unit-mismatch", "helper-unit-readback")
def _systemctl_state(receipt: dict[str, Any], action: str, unit: str, allowed: set[int] = {0}) -> tuple[int, str]:
    result = _run([SYSTEMCTL, action, unit])
    state = result.stdout.decode("utf-8", "ignore").strip()[:64]
    _record(receipt, "systemd-" + action, result.returncode in allowed, unit=unit,
            state=state if state in {"active", "inactive", "failed", "enabled", "disabled", "static", "masked"} else "other",
            rc=result.returncode)
    if result.returncode not in allowed:
        raise Refusal("agathodaimon-nas-systemd-readback-failed", "systemd-" + action, result.returncode)
    return result.returncode, state


def _mount_readback(info: dict[str, Any]) -> dict[str, Any]:
    entries = _mountinfo()
    matches = [entry for entry in entries if entry["target"] == info["mountpoint"]]
    try:
        findmnt = _run([FINDMNT, "--json", "--mountpoint", info["mountpoint"],
                        "--output", "SOURCE,FSTYPE,MAJ:MIN,TARGET"], step="findmnt-mount-readback")
    except Refusal as failure:
        return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": failure.return_code, "reason": failure.signal_name}

    if findmnt.returncode == 1 and not matches:
        if not findmnt.stdout.strip():
            return {"mounted": False, "sourceMatches": False, "fstype": None,
                    "findmntRc": findmnt.returncode, "findmntAbsent": True}
        try:
            empty = json.loads(findmnt.stdout.decode("utf-8")).get("filesystems") == []
        except (UnicodeError, ValueError, TypeError, AttributeError):
            empty = False
        if empty:
            return {"mounted": False, "sourceMatches": False, "fstype": None,
                    "findmntRc": findmnt.returncode, "findmntAbsent": True}
    if findmnt.returncode == 0 and not matches:
        try:
            empty = json.loads(findmnt.stdout.decode("utf-8")).get("filesystems") == []
        except (UnicodeError, ValueError, TypeError, AttributeError):
            empty = False
        if empty:
            return {"mounted": False, "sourceMatches": False, "fstype": None,
                    "findmntRc": findmnt.returncode, "findmntAbsent": True}
    if findmnt.returncode != 0:
        return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": findmnt.returncode, "reason": "findmnt-command-failed"}
    try:
        decoded = json.loads(findmnt.stdout.decode("utf-8"))
        filesystems = decoded["filesystems"]
        if not isinstance(filesystems, list) or len(filesystems) != 1 or not isinstance(filesystems[0], dict):
            raise ValueError("findmnt-row-count")
        row = filesystems[0]
        source = row["source"]
        fstype = row["fstype"]
        findmnt_identity = row["maj:min"]
        target = row["target"]
        if not all(isinstance(value, str) for value in (source, fstype, findmnt_identity, target)):
            raise ValueError("findmnt-field-type")
        if not re.fullmatch(r"\d+:\d+", findmnt_identity):
            raise ValueError("findmnt-identity")
    except (UnicodeError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": findmnt.returncode, "reason": "findmnt-readback-invalid"}

    if len(matches) != 1:
        return {"mounted": True, "sourceMatches": False, "fstype": fstype, "target": target,
                "findmntSource": source, "findmntIdentity": findmnt_identity,
                "findmntRc": findmnt.returncode, "reason": "mountinfo-findmnt-disagree"}
    try:
        mapper_identity = _device_identity(f"/dev/mapper/{info['mapper']}", "mount-readback")
        source_identity = _device_identity(source, "mount-readback")
        root_stat = os.stat(info["mountpoint"], follow_symlinks=False)
    except Refusal as failure:
        return {"mounted": True, "sourceMatches": False, "fstype": fstype,
                "findmntSource": source, "findmntIdentity": findmnt_identity,
                "findmntRc": findmnt.returncode, "reason": failure.signal_name,
                "readbackRc": failure.return_code}
    except OSError:
        return {"mounted": True, "sourceMatches": False, "fstype": fstype,
                "findmntSource": source, "findmntIdentity": findmnt_identity,
                "findmntRc": findmnt.returncode, "reason": "mount-stat-unavailable"}
    stat_identity = f"{os.major(root_stat.st_dev)}:{os.minor(root_stat.st_dev)}"
    identity_matches = (matches[0]["dev"] == mapper_identity == stat_identity
                        and source_identity == mapper_identity and findmnt_identity == mapper_identity)
    target_matches = target == info["mountpoint"] and matches[0]["target"] == info["mountpoint"]
    filesystem_matches = fstype == "xfs" and matches[0]["fstype"] == "xfs"
    source_matches = identity_matches and target_matches and filesystem_matches
    return {"mounted": True, "sourceMatches": source_matches,
            "mountinfoIdentity": matches[0]["dev"], "statIdentity": stat_identity,
            "findmntIdentity": findmnt_identity, "findmntSource": source,
            "findmntRc": findmnt.returncode, "findmntMatches": source_matches,
            "fstype": fstype, "target": target,
            "mountinfoFstype": matches[0]["fstype"]}


def _ensure_mountpoint_directory(path: str) -> None:
    try:
        st = os.lstat(path)
    except OSError:
        raise Refusal("agathodaimon-nas-mountpoint-readback-failed", "mountpoint-preflight")
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Refusal("agathodaimon-nas-mountpoint-not-directory", "mountpoint-preflight")
    try:
        with os.scandir(path) as entries:
            if next(entries, None) is not None:
                raise Refusal("agathodaimon-nas-mountpoint-not-empty", "mountpoint-preflight")
    except Refusal:
        raise
    except OSError:
        raise Refusal("agathodaimon-nas-mountpoint-readback-failed", "mountpoint-preflight")


def _same_filesystem_tree(path: str, root_dev: int) -> list[Path]:
    result: list[Path] = []
    stack = [Path(path)]
    while stack:
        current = stack.pop()
        try:
            st = os.lstat(current)
        except OSError:
            raise Refusal("agathodaimon-nas-path-readback-failed", "permissions-readback")
        if stat.S_ISLNK(st.st_mode) or st.st_dev != root_dev:
            raise Refusal("agathodaimon-nas-path-escape", "permissions-readback")
        result.append(current)
        if stat.S_ISDIR(st.st_mode):
            try:
                with os.scandir(current) as entries:
                    children = [Path(entry.path) for entry in entries]
            except OSError:
                raise Refusal("agathodaimon-nas-path-readback-failed", "permissions-readback")
            stack.extend(children)
    return result


def _open_directory_nofollow(path: str) -> int:
    if not Path(path).is_absolute() or any(part in {".", ".."} for part in Path(path).parts):
        raise OSError("unsafe-directory")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open("/", flags)
    try:
        for component in Path(path).parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _permission_mount_guard(root_fd: int, mountpoint: str, mapper_identity: str,
                            root_identity: tuple[int, int]) -> None:
    root_stat = os.fstat(root_fd)
    if (root_stat.st_dev, root_stat.st_ino) != root_identity:
        raise Refusal("agathodaimon-nas-mount-readback-mismatch", "permissions-boundary")
    current_fd = None
    try:
        current_fd = _open_directory_nofollow(mountpoint)
        current = os.fstat(current_fd)
    except OSError:
        raise Refusal("agathodaimon-nas-mount-readback-mismatch", "permissions-boundary")
    finally:
        if current_fd is not None:
            os.close(current_fd)
    current_identity = f"{os.major(current.st_dev)}:{os.minor(current.st_dev)}"
    if (current.st_dev, current.st_ino) != root_identity or current_identity != mapper_identity:
        raise Refusal("agathodaimon-nas-mount-readback-mismatch", "permissions-boundary")
    entries = _mountinfo()
    roots = [entry for entry in entries if entry["target"] == mountpoint]
    nested = [entry for entry in entries if entry["target"].startswith(mountpoint + "/")]
    if len(roots) != 1 or roots[0]["dev"] != mapper_identity or roots[0]["fstype"] != "xfs" or nested:
        raise Refusal("agathodaimon-nas-mount-readback-mismatch", "permissions-boundary")


def _open_or_create_child(parent_fd: int, component: str, root_dev: int, root_fd: int,
                          mountpoint: str, mapper_identity: str) -> int:
    if component in {"", ".", ".."} or "/" in component:
        raise Refusal("agathodaimon-nas-config-path-invalid", "permissions-preflight")
    root_stat = os.fstat(root_fd)
    _permission_mount_guard(root_fd, mountpoint, mapper_identity, (root_stat.st_dev, root_stat.st_ino))
    if os.fstat(parent_fd).st_dev != root_dev:
        raise Refusal("agathodaimon-nas-path-escape", "permissions-preflight")
    try:
        os.mkdir(component, 0o755, dir_fd=parent_fd)
    except FileExistsError:
        pass
    except OSError:
        raise Refusal("agathodaimon-nas-directory-create-failed", "permissions-create")
    try:
        child_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                           dir_fd=parent_fd)
    except OSError:
        raise Refusal("agathodaimon-nas-path-escape", "permissions-preflight")
    st = os.fstat(child_fd)
    if st.st_dev != root_dev:
        os.close(child_fd)
        raise Refusal("agathodaimon-nas-path-escape", "permissions-preflight")
    _permission_mount_guard(root_fd, mountpoint, mapper_identity, (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino))
    return child_fd


def _collect_fd_tree(directory_fd: int, root_dev: int) -> list[int]:
    targets = [os.dup(directory_fd)]
    stack = [directory_fd]
    try:
        while stack:
            parent = stack.pop()
            for name in os.listdir(parent):
                st = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if st.st_dev != root_dev or stat.S_ISLNK(st.st_mode):
                    raise Refusal("agathodaimon-nas-path-escape", "permissions-readback")
                if stat.S_ISDIR(st.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                                    dir_fd=parent)
                elif stat.S_ISREG(st.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                                    dir_fd=parent)
                else:
                    raise Refusal("agathodaimon-nas-path-kind-refused", "permissions-readback")
                opened = os.fstat(child)
                if (opened.st_dev != root_dev or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino)):
                    os.close(child)
                    raise Refusal("agathodaimon-nas-path-escape", "permissions-readback")
                targets.append(child)
                if stat.S_ISDIR(opened.st_mode):
                    stack.append(child)
        return targets
    except Exception:
        for fd in targets:
            os.close(fd)
        raise


def _apply_permissions(receipt: dict[str, Any], info: dict[str, Any]) -> None:
    mountpoint = info["mountpoint"]
    expected_mapper = _device_identity(f"/dev/mapper/{info['mapper']}", "permissions-preflight")
    try:
        root_fd = _open_directory_nofollow(mountpoint)
    except OSError:
        raise Refusal("agathodaimon-nas-mounted-root-unreadable", "permissions-preflight")
    try:
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise Refusal("agathodaimon-nas-mounted-root-invalid", "permissions-preflight")
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        root_dev = root_stat.st_dev
        if f"{os.major(root_dev)}:{os.minor(root_dev)}" != expected_mapper:
            raise Refusal("agathodaimon-nas-mount-readback-mismatch", "permissions-preflight")
        _permission_mount_guard(root_fd, mountpoint, expected_mapper, root_identity)
        for app in info["config"]["applications"]:
            for path in app["paths"]:
                relative = path[len(mountpoint):].lstrip("/")
                components = relative.split("/") if relative else []
                current_fd = os.dup(root_fd)
                targets: list[int] = []
                try:
                    for component in components:
                        _permission_mount_guard(root_fd, mountpoint, expected_mapper, root_identity)
                        child_fd = _open_or_create_child(current_fd, component, root_dev, root_fd,
                                                         mountpoint, expected_mapper)
                        os.close(current_fd)
                        current_fd = child_fd
                    targets = _collect_fd_tree(current_fd, root_dev) if app["recursive"] else [os.dup(current_fd)]
                    for fd in targets:
                        st = os.fstat(fd)
                        if st.st_dev != root_dev:
                            raise Refusal("agathodaimon-nas-path-escape", "permissions-apply")
                        _permission_mount_guard(root_fd, mountpoint, expected_mapper, root_identity)
                        os.fchown(fd, app["uid"], app["gid"])
                        _permission_mount_guard(root_fd, mountpoint, expected_mapper, root_identity)
                        os.fchmod(fd, app["mode"])
                    _permission_mount_guard(root_fd, mountpoint, expected_mapper, root_identity)
                    os.fchmod(current_fd, app["mode"] | stat.S_IWGRP)
                    observed_entries = [os.fstat(fd) for fd in targets]
                    current = os.fstat(current_fd)
                    all_permissions = all(
                        entry.st_dev == root_dev and entry.st_uid == app["uid"] and entry.st_gid == app["gid"]
                        and stat.S_IMODE(entry.st_mode) == (app["mode"] | stat.S_IWGRP if (entry.st_dev, entry.st_ino) == (current.st_dev, current.st_ino) else app["mode"])
                        for entry in observed_entries)
                    _record(receipt, "permissions-readback", all_permissions, application=app["application"],
                            path=path, uid=current.st_uid, gid=current.st_gid, mode=stat.S_IMODE(current.st_mode),
                            recursive=app["recursive"], entries=len(targets), allEntriesMatched=all_permissions)
                    if not all_permissions:
                        raise Refusal("agathodaimon-nas-permission-readback-mismatch", "permissions-readback")
                except Refusal:
                    raise
                except OSError:
                    raise Refusal("agathodaimon-nas-permission-change-failed", "permissions-apply")
                finally:
                    for fd in targets:
                        os.close(fd)
                    os.close(current_fd)
    finally:
        os.close(root_fd)


def _service_active(unit: str) -> bool:
    result = _run([SYSTEMCTL, "is-active", unit])
    if result.returncode == 0 and result.stdout.strip() == b"active":
        return True
    if result.returncode == 3 and result.stdout.strip() == b"inactive":
        return False
    raise Refusal("agathodaimon-nas-service-state-unreadable", "service-state-readback", result.returncode)


def _start_nas_services(receipt: dict[str, Any], info: dict[str, Any]) -> None:
    for service in info["services"]:
        active = _service_active(service["unit"])
        if service["activeBefore"]:
            if not active:
                raise Refusal("agathodaimon-nas-preactive-service-stopped", "service-state-readback")
            continue
        if active:
            if service["unit"] not in info["servicesStarted"]:
                info["servicesStarted"].append(service["unit"])
            continue
        if not service["enabled"]:
            continue
        if service["unit"] not in info["servicesStarted"]:
            info["servicesStarted"].append(service["unit"])
        command = _run([SYSTEMCTL, "start", service["unit"]], step="service-start")
        observed = _service_active(service["unit"])
        _record(receipt, "service-start", command.returncode == 0 and observed,
                unit=service["unit"], enabled=True, active=observed, rc=command.returncode)
        if command.returncode != 0 or not observed:
            raise Refusal("agathodaimon-nas-service-start-failed", "service-start", command.returncode)


def _unit_matches_snapshot(path: Path, identity: dict[str, Any]) -> bool:
    try:
        st = os.lstat(path)
        raw, opened = _read_regular_nofollow(str(path), maximum=1024 * 1024)
    except (OSError, UnicodeError):
        return False
    return (stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and
            st.st_uid == identity["uid"] and st.st_gid == identity["gid"] and
            stat.S_IMODE(st.st_mode) == identity["mode"] and st.st_dev == identity["dev"] and st.st_ino == identity["ino"] and
            (opened.st_dev, opened.st_ino) == (st.st_dev, st.st_ino) and raw == identity["bytes"])


def _run_rollback_command(rollback: list[dict[str, Any]], step: str, argv: Sequence[str],
                          verify: Callable[[], Any]) -> bool:
    try:
        result = _run(argv, timeout=90, step=step)
    except Refusal as failure:
        result = None
    try:
        observed = verify()
        okay = bool(observed)
    except Exception:
        observed = False
        okay = False
    rollback.append({"step": _safe_step(step), "ok": bool(result and result.returncode == 0 and okay),
                     "readback": {"rc": result.returncode if result else None, "observed": observed}})
    return okay


def _rollback_systemctl_state(unit: str, step: str, allow_missing: bool = False) -> dict[str, Any]:
    try:
        result = _run([SYSTEMCTL, "is-active", unit], step=step)
    except Refusal as failure:
        return {"state": None, "rc": failure.return_code, "reason": failure.signal_name}
    observed = result.stdout.decode("utf-8", "ignore").strip()[:64]
    running = {"active", "reloading", "refreshing"}
    if result.returncode == 0 and observed in running:
        return {"state": observed, "rc": result.returncode}
    if result.returncode == 3 and observed in {"inactive", "failed", "activating", "deactivating"}:
        return {"state": observed, "rc": result.returncode}
    if result.returncode == 4 and observed == "inactive" and allow_missing:
        return {"state": observed, "rc": result.returncode, "missing": True}
    return {"state": None, "rc": result.returncode,
            "observed": observed or "empty", "reason": "service-state-unrecognized"}


def _rollback_unit_path_exists(path: Path) -> tuple[bool | None, str | None]:
    try:
        return os.path.lexists(path), None
    except OSError:
        return None, "unit-path-unreadable"


def _rollback_stop_owned_unit(rollback: list[dict[str, Any]], unit: str, step: str,
                              initial: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    stop_result = None
    stop_failure: str | None = None
    try:
        stop_result = _run([SYSTEMCTL, "stop", unit], timeout=180, step=step)
    except Refusal as failure:
        stop_failure = failure.signal_name
        stop_rc = failure.return_code
    else:
        stop_rc = stop_result.returncode

    after_stop = _rollback_systemctl_state(unit, step + "-state")
    reset_needed = initial.get("state") == "failed" or after_stop.get("state") == "failed"
    reset_rc = None
    reset_failure: str | None = None
    reset_ok = True
    final_state = after_stop
    if reset_needed:
        try:
            reset = _run([SYSTEMCTL, "reset-failed", unit], timeout=180,
                         step=step + "-reset-failed")
        except Refusal as failure:
            reset_failure = failure.signal_name
            reset_rc = failure.return_code
            reset_ok = False
        else:
            reset_rc = reset.returncode
            reset_ok = reset.returncode == 0
        final_state = _rollback_systemctl_state(unit, step + "-final-state")

    initial_known = initial.get("state") is not None
    state_known = after_stop.get("state") is not None and final_state.get("state") is not None
    inactive = final_state.get("state") == "inactive"
    stop_ok = stop_result is not None and stop_rc == 0
    reason = "inactive-after-stop"
    if not initial_known:
        reason = initial.get("reason", "initial-state-unknown")
    elif stop_failure is not None:
        reason = stop_failure
    elif stop_rc != 0:
        reason = "stop-command-failed"
    elif not state_known:
        reason = after_stop.get("reason", final_state.get("reason", "post-stop-state-unknown"))
    elif reset_failure is not None:
        reason = reset_failure
    elif not reset_ok:
        reason = "reset-failed-command-failed"
    elif not inactive:
        reason = "unit-not-inactive"
    okay = bool(initial_known and stop_ok and state_known and reset_ok and inactive)
    rollback.append({"step": _safe_step(step), "ok": okay,
                     "readback": {"unit": unit, "owned": True, "initialState": initial.get("state"),
                                  "initialStateRc": initial.get("rc"),
                                  "initialStateReason": initial.get("reason"),
                                  "stopRc": stop_rc, "stopReason": stop_failure,
                                  "stateAfterStop": after_stop.get("state"),
                                  "stateAfterStopRc": after_stop.get("rc"),
                                  "stateAfterStopReason": after_stop.get("reason"),
                                  "resetFailedAttempted": reset_needed, "resetFailedRc": reset_rc,
                                  "resetFailedReason": reset_failure,
                                  "finalState": final_state.get("state"),
                                  "finalStateRc": final_state.get("rc"),
                                  "finalStateReason": final_state.get("reason"),
                                  "inactive": inactive, "reason": reason}})
    return okay, final_state


def _rollback_target_guard(info: dict[str, Any],
                           whole_disk_erasure_step: str | None = None) -> tuple[bool, dict[str, Any]]:
    device, partition = info["device"], info["partition"]
    expected_device = info["deviceIdentity"]
    expected_partition = info.get("createdPartitionIdentity")
    allowed_erasure_steps = {"wipe-created-disk-signatures", "zap-created-gpt"}
    if whole_disk_erasure_step not in {None, *allowed_erasure_steps}:
        return False, {"valid": False, "wholeDiskErasureStep": whole_disk_erasure_step,
                       "reason": "unrecognized-whole-disk-erasure-phase", "rc": None}
    try:
        observed_device = _device_identity(device, "rollback-device-identity")
    except Refusal as failure:
        return False, {"valid": False, "wholeDiskErasureStep": whole_disk_erasure_step,
                       "reason": failure.signal_name, "rc": failure.return_code}
    try:
        result = _run([LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL", device],
                      step="rollback-block-census")
    except Refusal as failure:
        return False, {"deviceIdentity": observed_device, "valid": False,
                       "wholeDiskErasureStep": whole_disk_erasure_step,
                       "reason": failure.signal_name, "rc": failure.return_code}
    if result.returncode != 0:
        return False, {"deviceIdentity": observed_device, "lsblkRc": result.returncode,
                       "wholeDiskErasureStep": whole_disk_erasure_step,
                       "rc": result.returncode, "valid": False, "reason": "block-census-failed"}
    try:
        value = json.loads(result.stdout.decode("utf-8"))
        nodes = list(_walk_nodes(value))
        roots = [row for row in nodes if row.get("path") == device]
        if len(roots) != 1 or roots[0].get("maj:min") != expected_device:
            return False, {"deviceIdentity": observed_device, "lsblkRc": result.returncode,
                           "wholeDiskErasureStep": whole_disk_erasure_step,
                           "rc": result.returncode, "lsblkRootCount": len(roots), "valid": False,
                           "reason": "whole-device-identity-mismatch"}
        partition_nodes = [row for row in nodes if row.get("type") == "part"]
        partitions = [row for row in partition_nodes if row.get("path") == partition]
        partition_node_identity = partitions[0].get("maj:min") if len(partitions) == 1 else None
        partition_parent_matches = (len(partitions) == 1
                                    and _normalize_pkname(partitions[0].get("pkname"))
                                    == os.path.basename(device))
        try:
            os.lstat(partition)
            partition_node_exists = True
        except FileNotFoundError:
            partition_node_exists = False
        except OSError:
            partition_node_exists = None

        partition_present = bool(partition_nodes) or partition_node_exists is True
        created_partition_matches = (partition_node_identity == expected_partition
                                     and partition_parent_matches)
        foreign_partition_count = len(partition_nodes) - (1 if created_partition_matches else 0)
        if expected_partition is None:
            partition_ok = not partition_nodes and partition_node_exists is False
            partition_reason = ("no-created-partition-identity-and-no-partitions" if partition_ok
                                else "unexpected-or-unreadable-partition-present")
        elif partition_present:
            partition_ok = (len(partition_nodes) == 1 and len(partitions) == 1
                            and partition_node_identity == expected_partition and partition_parent_matches
                            and partition_node_exists is True)
            if partition_ok:
                partition_ok = (_device_identity(partition, "rollback-partition-identity")
                                == expected_partition)
            partition_reason = ("created-partition-identity-preserved" if partition_ok
                                else "partition-or-parent-identity-mismatch")
        else:
            absence_observed = not partition_nodes and partition_node_exists is False
            partition_ok = absence_observed and whole_disk_erasure_step in allowed_erasure_steps
            if not absence_observed:
                partition_reason = "partition-absence-unproven-or-foreign-partition-present"
            elif partition_ok:
                partition_reason = "created-partition-absent-after-owned-whole-disk-erasure"
            else:
                partition_reason = "created-partition-absent-before-owned-whole-disk-erasure"
        if observed_device != expected_device or not partition_ok:
            return False, {"deviceIdentity": observed_device, "partitionIdentity": partition_node_identity,
                           "partitionExpected": expected_partition, "partitionPresent": partition_present,
                           "partitionParentMatches": partition_parent_matches,
                           "foreignPartitionCount": foreign_partition_count,
                           "wholeDiskErasureStep": whole_disk_erasure_step,
                           "partitionReason": partition_reason, "lsblkRc": result.returncode,
                           "rc": result.returncode, "valid": False,
                           "reason": "partition-or-device-identity-mismatch"}
        graph, _paths = _block_graph()
        component = _component(graph, expected_device)
        mapper_state = _mapper_state(info["mapper"], partition)
        if mapper_state.get("exists") is not False:
            return False, {"deviceIdentity": observed_device, "partitionIdentity": partition_node_identity,
                           "partitionExpected": expected_partition, "partitionPresent": partition_present,
                           "partitionParentMatches": partition_parent_matches,
                           "foreignPartitionCount": foreign_partition_count,
                           "wholeDiskErasureStep": whole_disk_erasure_step,
                           "mapperAbsent": False, "mapperStatusRc": mapper_state.get("statusRc"),
                           "lsblkRc": result.returncode, "rc": result.returncode,
                           "valid": False, "reason": "mapper-not-absent"}
        holders = []
        for identity in sorted(component):
            resolved = (SYS_DEV_BLOCK / identity).resolve(strict=True)
            holder_dir = resolved / "holders"
            if not holder_dir.is_dir():
                return False, {"deviceIdentity": observed_device, "partitionIdentity": partition_node_identity,
                               "partitionExpected": expected_partition, "partitionPresent": partition_present,
                               "wholeDiskErasureStep": whole_disk_erasure_step,
                               "holdersReadable": False, "lsblkRc": result.returncode, "rc": result.returncode,
                               "valid": False, "reason": "holders-unreadable"}
            names = sorted(os.listdir(holder_dir))
            if names:
                holders.extend(names)
        entries = _mountinfo()
        mounts = [entry for entry in entries if entry["target"] == info["mountpoint"]
                  or entry["target"].startswith(info["mountpoint"] + "/")
                  or (entry["dev"] in graph and bool(_component(graph, entry["dev"]) & component))]
        valid = not holders and not mounts
        reason = (partition_reason if valid and expected_partition is not None and not partition_present
                  else "no-created-partition-identity-and-no-partitions" if valid and expected_partition is None
                  else "identity-holders-mounts-clear" if valid else "holders-or-mounts-present")
        return valid, {"deviceIdentity": observed_device, "partitionIdentity": partition_node_identity,
                       "partitionExpected": expected_partition, "partitionPresent": partition_present,
                       "partitionParentMatches": partition_parent_matches,
                       "foreignPartitionCount": foreign_partition_count,
                       "wholeDiskErasureStep": whole_disk_erasure_step,
                       "mapperAbsent": True, "holders": holders, "mountCount": len(mounts),
                       "lsblkRc": result.returncode, "rc": result.returncode, "valid": valid,
                       "reason": reason}
    except Refusal as failure:
        return False, {"valid": False, "wholeDiskErasureStep": whole_disk_erasure_step,
                       "reason": failure.signal_name, "rc": failure.return_code,
                       "lsblkRc": result.returncode}
    except (OSError, UnicodeError, ValueError, KeyError, TypeError):
        return False, {"valid": False, "observation": "incomplete",
                       "wholeDiskErasureStep": whole_disk_erasure_step,
                       "reason": "guard-observation-incomplete", "rc": result.returncode,
                       "lsblkRc": result.returncode}


def _cleanup_key(receipt: dict[str, Any], service_role: str, identity: dict[str, Any] | None,
                 cleanup_certain: bool, rollback: list[dict[str, Any]]) -> None:
    if identity is None:
        return
    path = _key_path(service_role)
    try:
        st = os.lstat(path)
        same = (stat.S_ISREG(st.st_mode) and not stat.S_ISLNK(st.st_mode) and st.st_dev == identity["dev"]
                and st.st_ino == identity["ino"] and st.st_uid == identity["uid"]
                and stat.S_IMODE(st.st_mode) == identity["mode"])
    except FileNotFoundError:
        same = False
    except OSError:
        same = False
    if not cleanup_certain or not same:
        rollback.append({"step": "retain-created-key", "ok": False,
                         "readback": {"present": same, "cleanupCertain": cleanup_certain,
                                      "rc": None,
                                      "reason": "rollback-incomplete" if not cleanup_certain else "key-identity-mismatch"}})
        return
    result = None
    failure_reason = None
    try:
        result = _run([KEYMAN_DELETE, service_role], step="delete-created-key")
        result_rc = result.returncode
    except Refusal as failure:
        result_rc = failure.return_code
        failure_reason = failure.signal_name
    try:
        os.lstat(path)
        absent = False
    except FileNotFoundError:
        absent = True
    except OSError:
        absent = False
    okay = result is not None and result.returncode == 0 and absent
    reason = "deleted-and-absent" if okay else (failure_reason or
             ("delete-command-failed" if result is not None and result.returncode != 0 else "key-still-present-or-unreadable"))
    rollback.append({"step": "delete-created-key", "ok": okay,
                     "readback": {"rc": result_rc, "absent": absent, "identityMatched": same,
                                  "reason": reason}})


def _rollback(receipt: dict[str, Any], info: dict[str, Any] | None, key_identity: dict[str, Any] | None,
              mutations: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    if info is None:
        return records
    device, partition, mapper, mountpoint = (info[k] for k in ("device", "partition", "mapper", "mountpoint"))
    helper_attempted = bool(mutations.get("helperAttempted"))
    units_clean = True
    unit_snapshots = info.get("createdUnitFiles", {})
    if helper_attempted:
        for unit_name, path in info["unitPaths"].items():
            snapshot = unit_snapshots.get(unit_name)
            try:
                exists: bool | None = os.path.lexists(path)
            except OSError:
                exists = None
            if exists:
                identity_matched = snapshot is not None and _unit_matches_snapshot(path, snapshot)
                okay = identity_matched
                reason = "snapshot-matches" if okay else "unit-snapshot-conflict"
                rc = None
            elif exists is False:
                state = _rollback_systemctl_state(path.name, "rollback-unit-snapshot-state",
                                                  allow_missing=snapshot is None)
                if snapshot is not None:
                    okay = False
                    reason = "owned-unit-file-disappeared"
                else:
                    okay = state.get("state") == "inactive"
                    reason = "no-owned-file-and-inactive" if okay else state.get(
                        "reason", "unowned-unit-state-not-inactive")
                identity_matched = snapshot is None
                rc = state.get("rc")
            else:
                okay, identity_matched, rc, reason = False, False, None, "unit-file-state-unreadable"
            units_clean = units_clean and okay
            records.append({"step": "helper-unit-snapshot", "ok": okay,
                            "readback": {"unit": path.name, "exists": exists,
                                         "identityMatched": identity_matched, "rc": rc,
                                         "reason": reason}})
    mount_state: dict[str, Any] = {"mounted": True, "sourceMatches": False, "reason": "not-observed"}
    mount_conflict = False
    nested: list[dict[str, str]] = []
    try:
        mount_state = _mount_readback(info)
        all_mounts = _mountinfo()
        nested = [entry for entry in all_mounts if entry["target"].startswith(mountpoint + "/")]
    except Exception:
        mount_conflict = True
        mount_state = {"mounted": True, "sourceMatches": False, "reason": "mount-readback-unavailable"}
    if nested:
        mount_conflict = True
        records.append({"step": "foreign-nested-mount-conflict", "ok": False,
                        "readback": {"nestedCount": len(nested), "rc": mount_state.get("findmntRc"),
                                     "reason": "nested-mount-present"}})
    if mount_state.get("mounted") and not (helper_attempted and mount_state.get("sourceMatches")
                                             and mount_state.get("fstype") == "xfs"):
        mount_conflict = True
        records.append({"step": "foreign-mount-conflict", "ok": False,
                        "readback": {"mounted": True, "sourceMatches": mount_state.get("sourceMatches", False),
                                     "rc": mount_state.get("findmntRc"),
                                     "reason": mount_state.get("reason", "mount-identity-or-filesystem-mismatch")}})
    if not units_clean:
        mount_conflict = True
    records.append({"step": "mount-pre-unmount-readback", "ok": not mount_conflict,
                    "readback": {**mount_state, "nestedCount": len(nested),
                                 "reason": "owned-mount-or-absent" if not mount_conflict else "mount-cleanup-conflict"}})

    services_clean = True
    if helper_attempted:
        running_states = {"active", "activating", "reloading", "refreshing", "deactivating"}
        for service in info.get("services", []):
            unit = service["unit"]
            initial = _rollback_systemctl_state(unit, "rollback-service-state")
            state = initial.get("state")
            if service.get("activeBefore"):
                preserved = state == "active"
                reason = "preactive-service-still-running" if state in running_states else "preactive-state-not-active"
                services_clean = False
                records.append({"step": "preserve-preactive-service", "ok": preserved,
                                "readback": {"unit": unit, "activeBefore": True, "state": state,
                                             "rc": initial.get("rc"), "reason": reason}})
                continue
            listed = unit in info.get("servicesStarted", [])
            owned = state in running_states | {"failed"} or listed
            if owned:
                if unit not in info.setdefault("servicesStarted", []):
                    info["servicesStarted"].append(unit)
                stopped, _final = _rollback_stop_owned_unit(records, unit, "stop-new-service", initial)
                services_clean = services_clean and stopped
            elif state == "inactive":
                records.append({"step": "leave-inactive-service", "ok": True,
                                "readback": {"unit": unit, "state": state, "rc": initial.get("rc"),
                                             "reason": "inactive-not-transaction-owned"}})
            else:
                services_clean = False
                records.append({"step": "dependent-service-cleanup-blocked", "ok": False,
                                "readback": {"unit": unit, "state": state, "rc": initial.get("rc"),
                                             "reason": initial.get("reason", "service-state-unknown")}})
    elif info.get("servicesStarted"):
        services_clean = False
        records.append({"step": "dependent-service-cleanup-blocked", "ok": False,
                        "readback": {"reason": "service-ownership-without-helper-attempt", "rc": None}})

    mount_absent = not mount_state.get("mounted") and not nested
    if helper_attempted:
        mount_stop_clean = False
        partition_stop_clean = False
        stop_ready = units_clean and services_clean and not mount_conflict
        if not stop_ready:
            reason = ("unit-snapshot-conflict" if not units_clean else
                      "dependent-service-not-stopped" if not services_clean else "foreign-or-nested-mount")
            records.append({"step": "stop-helper-mount-unit", "ok": False,
                            "readback": {"rc": None, "reason": reason}})
            records.append({"step": "stop-helper-partition-unit", "ok": False,
                            "readback": {"rc": None, "reason": "mount-unit-not-stopped"}})
        else:
            mount_path = info["unitPaths"]["mount"]
            mount_snapshot = unit_snapshots.get("mount")
            mount_exists, mount_path_error = _rollback_unit_path_exists(mount_path)
            if mount_snapshot is not None and _unit_matches_snapshot(mount_path, mount_snapshot):
                initial = _rollback_systemctl_state(mount_path.name, "rollback-mount-unit-state")
                mount_stop_clean, _final = _rollback_stop_owned_unit(
                    records, mount_path.name, "stop-helper-mount-unit", initial)
                try:
                    after_mount = _mount_readback(info)
                    nested_after = [row for row in _mountinfo()
                                    if row["target"].startswith(mountpoint + "/")]
                    mount_absent = not after_mount.get("mounted") and not nested_after
                except Exception:
                    after_mount, nested_after, mount_absent = {
                        "mounted": True, "sourceMatches": False, "reason": "mount-readback-unavailable"}, [], False
                absent_ok = mount_stop_clean and mount_absent
                records.append({"step": "mount-absence-after-unit-stop", "ok": absent_ok,
                                "readback": {**after_mount, "nestedCount": len(nested_after),
                                             "reason": "mount-absent" if mount_absent else "mount-remains-or-unreadable"}})
                mount_stop_clean = absent_ok
            elif mount_snapshot is None and mount_exists is False and mount_absent:
                mount_stop_clean = True
                records.append({"step": "stop-helper-mount-unit", "ok": True,
                                "readback": {"unit": mount_path.name, "rc": None,
                                             "reason": "no-owned-mount-unit-and-mount-absent"}})
            else:
                records.append({"step": "stop-helper-mount-unit", "ok": False,
                                "readback": {"unit": mount_path.name, "rc": None,
                                             "reason": mount_path_error or "mount-unit-snapshot-unavailable"}})

            partition_path = info["unitPaths"]["partition"]
            partition_snapshot = unit_snapshots.get("partition")
            partition_exists, partition_path_error = _rollback_unit_path_exists(partition_path)
            if mount_stop_clean and partition_snapshot is not None and _unit_matches_snapshot(
                    partition_path, partition_snapshot):
                initial = _rollback_systemctl_state(partition_path.name, "rollback-partition-unit-state")
                partition_stop_clean, _final = _rollback_stop_owned_unit(
                    records, partition_path.name, "stop-helper-partition-unit", initial)
            elif mount_stop_clean and partition_snapshot is None and partition_exists is False:
                partition_stop_clean = True
                records.append({"step": "stop-helper-partition-unit", "ok": True,
                                "readback": {"unit": partition_path.name, "rc": None,
                                             "reason": "no-owned-partition-unit"}})
            else:
                records.append({"step": "stop-helper-partition-unit", "ok": False,
                                "readback": {"unit": partition_path.name, "rc": None,
                                             "reason": partition_path_error or
                                             "mount-unit-not-stopped-or-partition-snapshot-conflict"}})

        units_clean = units_clean and mount_stop_clean and partition_stop_clean
        files_removed = False
        if units_clean and mount_absent:
            for unit_name, path in reversed(list(info["unitPaths"].items())):
                snapshot = unit_snapshots.get(unit_name)
                if snapshot is None:
                    exists, path_error = _rollback_unit_path_exists(path)
                    absent = exists is False
                    records.append({"step": "remove-helper-unit", "ok": absent,
                                    "readback": {"unit": path.name, "identityMatched": False,
                                                 "absent": absent, "rc": None,
                                                 "reason": "no-owned-file" if absent else
                                                 path_error or "unowned-file-present"}})
                    units_clean = units_clean and absent
                    continue
                if not _unit_matches_snapshot(path, snapshot):
                    units_clean = False
                    exists, path_error = _rollback_unit_path_exists(path)
                    records.append({"step": "remove-helper-unit", "ok": False,
                                    "readback": {"unit": path.name, "identityMatched": False,
                                                 "absent": exists is False, "rc": None,
                                                 "reason": path_error or "unit-snapshot-conflict"}})
                    continue
                try:
                    os.unlink(path)
                    files_removed = True
                    exists, path_error = _rollback_unit_path_exists(path)
                    absent = exists is False
                    reason = "identical-snapshot-removed" if absent else path_error or "unit-still-present"
                except OSError:
                    absent = False
                    reason = "unit-unlink-failed"
                okay = absent
                units_clean = units_clean and okay
                records.append({"step": "remove-helper-unit", "ok": okay,
                                "readback": {"unit": path.name, "identityMatched": True,
                                             "absent": absent, "rc": None, "reason": reason}})
            if files_removed:
                reload = None
                reload_failure = None
                try:
                    reload = _run([SYSTEMCTL, "daemon-reload"], timeout=180,
                                  step="reload-after-unit-removal")
                    reload_rc = reload.returncode
                except Refusal as failure:
                    reload_failure = failure.signal_name
                    reload_rc = failure.return_code
                reload_ok = reload is not None and reload.returncode == 0
                records.append({"step": "reload-after-unit-removal", "ok": reload_ok,
                                "readback": {"rc": reload_rc,
                                             "reason": "daemon-reload-complete" if reload_ok else
                                             reload_failure or "daemon-reload-command-failed"}})
                units_clean = units_clean and reload_ok
                for unit_name, path in info["unitPaths"].items():
                    snapshot = unit_snapshots.get(unit_name)
                    if snapshot is None:
                        continue
                    state = _rollback_systemctl_state(path.name, "rollback-reloaded-unit-state", allow_missing=True)
                    reset_rc = None
                    reset_reason = None
                    reset_ok = True
                    if state.get("state") == "failed":
                        try:
                            reset = _run([SYSTEMCTL, "reset-failed", path.name], timeout=180,
                                         step="rollback-reloaded-reset-failed")
                            reset_rc = reset.returncode
                            reset_ok = reset.returncode == 0
                        except Refusal as failure:
                            reset_rc = failure.return_code
                            reset_reason = failure.signal_name
                            reset_ok = False
                        state = _rollback_systemctl_state(path.name, "rollback-reloaded-final-state",
                                                          allow_missing=True)
                    exists, path_error = _rollback_unit_path_exists(path)
                    absent = exists is False
                    state_ok = state.get("state") == "inactive"
                    okay = absent and state_ok and reset_ok
                    reason = ("unit-absent-and-inactive" if okay else
                              path_error or state.get("reason", "unit-not-absent-or-inactive"))
                    records.append({"step": "helper-unit-reload-readback", "ok": okay,
                                    "readback": {"unit": path.name, "rc": state.get("rc"),
                                                 "reloadRc": reload_rc, "resetFailedRc": reset_rc,
                                                 "resetFailedReason": reset_reason, "absent": absent,
                                                 "state": state.get("state"), "reason": reason}})
                    units_clean = units_clean and okay
        else:
            reason = ("unit-stop-failed" if units_clean is False else
                      "mount-not-absent" if not mount_absent else "unit-cleanup-blocked")
            for path in info["unitPaths"].values():
                exists, path_error = _rollback_unit_path_exists(path)
                records.append({"step": "remove-helper-unit", "ok": False,
                                "readback": {"unit": path.name, "identityMatched": False,
                                             "absent": exists is False, "rc": None,
                                             "reason": reason if path_error is None else path_error}})

    try:
        after_mount = _mount_readback(info)
        nested_after = [row for row in _mountinfo() if row["target"].startswith(mountpoint + "/")]
        mount_absent = not after_mount.get("mounted") and not nested_after
        mount_reason = "mount-and-nested-mounts-absent" if mount_absent else "mount-remains-or-readback-conflict"
        mount_rc = after_mount.get("findmntRc")
    except Refusal as failure:
        after_mount, nested_after, mount_absent = {"mounted": True, "sourceMatches": False}, [], False
        mount_reason, mount_rc = failure.signal_name, failure.return_code
    except Exception:
        after_mount, nested_after, mount_absent = {"mounted": True, "sourceMatches": False}, [], False
        mount_reason, mount_rc = "mount-readback-unavailable", None
    records.append({"step": "mount-final-readback", "ok": mount_absent,
                    "readback": {**after_mount, "nestedCount": len(nested_after),
                                 "rc": mount_rc, "reason": mount_reason}})
    mapper_closed = True
    has_disk_mutation = bool(mutations.get("diskMutationAttempted") or mutations.get("mapperOpenAttempted")
                              or mutations.get("mountAttempted"))
    mapper_close_safe = mount_absent and units_clean and services_clean
    if not mapper_close_safe and has_disk_mutation:
        mapper_closed = False
        reason = ("mount-not-absent" if not mount_absent else
                  "helper-units-not-stopped-and-removed" if not units_clean else "dependent-services-not-stopped")
        records.append({"step": "mapper-close-blocked", "ok": False,
                        "readback": {"mountAbsent": mount_absent, "unitsClean": units_clean,
                                     "servicesClean": services_clean, "rc": None, "reason": reason}})
    elif has_disk_mutation:
        mapper_failure = None
        try:
            mapper_state = _mapper_state(mapper, partition)
        except Refusal as failure:
            mapper_state = {"exists": None, "backingMatches": None}
            mapper_failure = failure
        if mapper_state.get("exists") is True and mapper_state.get("backingMatches") is True:
            close = None
            close_failure = None
            try:
                close = _run([CRYPTSETUP, "close", mapper], timeout=180, step="close-format-mapper")
                close_rc = close.returncode
            except Refusal as failure:
                close_failure = failure.signal_name
                close_rc = failure.return_code
            try:
                after_close = _mapper_state(mapper, partition)
                mapper_absent = after_close.get("exists") is False
                readback_reason = "mapper-absent" if mapper_absent else "mapper-still-present-or-unknown"
                readback_rc = None
            except Refusal as failure:
                after_close = {"exists": None, "backingMatches": None}
                mapper_absent = False
                readback_reason = failure.signal_name
                readback_rc = failure.return_code
            mapper_closed = close is not None and close.returncode == 0 and mapper_absent
            reason = ("closed-and-absent" if mapper_closed else close_failure or
                      ("close-command-failed" if close is not None and close.returncode != 0 else readback_reason))
            records.append({"step": "close-format-mapper", "ok": mapper_closed,
                            "readback": {"rc": close_rc, "readbackRc": readback_rc,
                                         "initialMapperStatusRc": mapper_state.get("statusRc"),
                                         "finalMapperStatusRc": after_close.get("statusRc"),
                                         "absent": mapper_absent, "backingMatches": True, "reason": reason}})
        elif mapper_state.get("exists") is False:
            mapper_closed = True
            records.append({"step": "mapper-absent", "ok": True,
                            "readback": {"absent": True, "rc": None, "reason": "mapper-already-absent"}})
        else:
            mapper_closed = False
            records.append({"step": "mapper-identity-conflict", "ok": False,
                            "readback": {"exists": mapper_state.get("exists"),
                                         "backingMatches": mapper_state.get("backingMatches"),
                                         "rc": mapper_failure.return_code if mapper_failure else None,
                                         "reason": mapper_failure.signal_name if mapper_failure else
                                         "mapper-identity-not-proven"}})

    disk_clean = not mutations.get("diskMutationAttempted")
    if mutations.get("diskMutationAttempted"):
        expected_partition = info.get("createdPartitionIdentity")
        actions: list[tuple[str, list[str]]] = []
        if expected_partition is not None:
            actions.append(("wipe-created-partition", [WIPEFS, "--all", "--force", "--", partition]))
        else:
            records.append({"step": "partition-absent-before-rollback", "ok": True,
                            "readback": {"identity": None, "rc": None,
                                         "reason": "no-created-partition-identity"}})
        actions.extend([("wipe-created-disk-signatures", [WIPEFS, "--all", "--force", "--", device]),
                        ("zap-created-gpt", [SGDISK, "--zap-all", "--", device])])
        safe_to_wipe = mount_absent and mapper_closed and units_clean and services_clean
        dependencies = []
        if not mount_absent:
            dependencies.append("mount-not-absent")
        if not mapper_closed:
            dependencies.append("mapper-not-closed")
        if not units_clean:
            dependencies.append("helper-units-not-clean")
        if not services_clean:
            dependencies.append("dependent-services-not-clean")
        wipe_sequence_ok = safe_to_wipe
        whole_disk_erasure_step = None
        if not safe_to_wipe:
            reason = "+".join(dependencies) or "rollback-dependency-not-clean"
            records.append({"step": "disk-wipe-blocked", "ok": False,
                            "readback": {"mountAbsent": mount_absent, "mapperClosed": mapper_closed,
                                         "unitsClean": units_clean, "servicesClean": services_clean,
                                         "rc": None, "reason": reason}})
            for step, _argv in actions:
                records.append({"step": step, "ok": False,
                                "readback": {"attempted": False, "rc": None,
                                             "reason": "rollback-dependency-not-clean"}})
        else:
            for step, argv in actions:
                if not wipe_sequence_ok:
                    records.append({"step": step, "ok": False,
                                    "readback": {"attempted": False, "rc": None,
                                                 "reason": "prior-guard-or-wipe-failed"}})
                    continue
                guarded, guard = _rollback_target_guard(
                    info, whole_disk_erasure_step=whole_disk_erasure_step)
                records.append({"step": "guard-" + step, "ok": guarded,
                                "readback": {**guard, "rc": guard.get("rc"),
                                             "reason": guard.get("reason", "guard-valid" if guarded else "guard-refused")}})
                if not guarded:
                    wipe_sequence_ok = False
                    records.append({"step": step, "ok": False,
                                    "readback": {"attempted": False, "rc": None,
                                                 "guard": guard, "reason": "disk-identity-guard-refused"}})
                    continue
                command = None
                command_failure = None
                try:
                    command = _run(argv, step=step)
                    command_rc = command.returncode
                except Refusal as failure:
                    command_failure = failure.signal_name
                    command_rc = failure.return_code
                command_ok = command is not None and command.returncode == 0
                records.append({"step": step, "ok": command_ok,
                                "readback": {"attempted": True, "rc": command_rc, "guard": guard,
                                             "wholeDiskErasureStep": step if command_ok and step in {
                                                 "wipe-created-disk-signatures", "zap-created-gpt"}
                                             else whole_disk_erasure_step,
                                             "reason": "wipe-command-complete" if command_ok else
                                             command_failure or "wipe-command-failed"}})
                if not command_ok:
                    wipe_sequence_ok = False
                elif step in {"wipe-created-disk-signatures", "zap-created-gpt"}:
                    whole_disk_erasure_step = step
            if wipe_sequence_ok:
                def observe_rollback_command(step: str, argv: Sequence[str]) -> subprocess.CompletedProcess[bytes] | None:
                    try:
                        result = _run(argv, step=step)
                    except Refusal as failure:
                        records.append({"step": step, "ok": False,
                                        "readback": {"rc": failure.return_code,
                                                     "reason": failure.signal_name}})
                        return None
                    okay = result.returncode == 0
                    records.append({"step": step, "ok": okay,
                                    "readback": {"rc": result.returncode,
                                                 "reason": "command-complete" if okay else "command-failed"}})
                    return result

                trigger = observe_rollback_command(
                    "rollback-udev-trigger", [UDEVADM, "trigger", "--subsystem-match=block", "--action=change"])
                settle = observe_rollback_command("rollback-udev-settle", [UDEVADM, "settle", "--timeout=30"])
                signatures = observe_rollback_command(
                    "rollback-signature-readback", [WIPEFS, "--noheadings", "--output", "TYPE", "--", device])
                tree = observe_rollback_command(
                    "rollback-partition-readback",
                    [LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL", device])
                signature_text = signatures.stdout.decode("utf-8", "ignore").strip() if signatures else ""
                roots: list[dict[str, Any]] = []
                partitions_absent = False
                parse_reason = None
                if tree is not None and tree.returncode == 0:
                    try:
                        nodes = list(_walk_nodes(json.loads(tree.stdout.decode("utf-8"))))
                        roots = [row for row in nodes if row.get("path") == device
                                 and row.get("maj:min") == info["deviceIdentity"]]
                        partitions_absent = bool(roots) and not any(row.get("type") == "part" for row in nodes)
                    except (UnicodeError, ValueError, KeyError, TypeError, Refusal):
                        parse_reason = "partition-readback-invalid"
                elif tree is not None:
                    parse_reason = "partition-readback-command-failed"
                else:
                    parse_reason = "partition-readback-command-unavailable"
                if parse_reason is not None:
                    records.append({"step": "disk-partition-readback", "ok": False,
                                    "readback": {"rc": tree.returncode if tree else None,
                                                 "reason": parse_reason}})
                signatures_absent = signatures is not None and signatures.returncode == 0 and not signature_text
                disk_clean = (trigger is not None and trigger.returncode == 0
                              and settle is not None and settle.returncode == 0
                              and signatures_absent and tree is not None and tree.returncode == 0
                              and partitions_absent and bool(roots))
                verify_reasons = []
                if trigger is None or trigger.returncode != 0:
                    verify_reasons.append("udev-trigger-failed")
                if settle is None or settle.returncode != 0:
                    verify_reasons.append("udev-settle-failed")
                if not signatures_absent:
                    verify_reasons.append("disk-signatures-remain-or-unreadable")
                if not partitions_absent or not roots:
                    verify_reasons.append("partition-or-device-readback-mismatch")
                records.append({"step": "disk-clean-readback", "ok": disk_clean,
                                "readback": {"udevTriggerRc": trigger.returncode if trigger else None,
                                             "udevSettleRc": settle.returncode if settle else None,
                                             "signatureRc": signatures.returncode if signatures else None,
                                             "signaturesAbsent": signatures_absent,
                                             "lsblkRc": tree.returncode if tree else None,
                                             "partitionsAbsent": partitions_absent,
                                             "deviceIdentityMatched": bool(roots),
                                             "reason": "disk-blank-verified" if disk_clean else
                                             "+".join(verify_reasons) or "disk-readback-incomplete"}})
            else:
                disk_clean = False
                records.append({"step": "disk-clean-readback", "ok": False,
                                "readback": {"attempted": False, "rc": None,
                                             "reason": "wipe-guard-or-command-failed"}})
    else:
        records.append({"step": "disk-unchanged", "ok": True,
                        "readback": {"mutationAttempted": False, "rc": None,
                                     "reason": "no-disk-mutation-attempted"}})
    cleanup_certain = disk_clean and mapper_closed and mount_absent and units_clean and services_clean
    _cleanup_key(receipt, info["serviceRole"], key_identity, cleanup_certain, records)
    receipt["servicesStarted"] = list(info.get("servicesStarted", []))
    return records


def _execute(receipt: dict[str, Any], request: dict[str, Any], info: dict[str, Any]) -> tuple[dict[str, Any] | None, bytearray]:
    key_identity = None
    material = bytearray()
    mutations = {"diskMutationAttempted": False, "mapperOpenAttempted": False, "mountAttempted": False,
                 "helperAttempted": False}
    info["device"] = request["device"]
    info["createdUnitFiles"] = {}
    info["servicesStarted"] = []
    info["mutations"] = mutations
    partition, device, mapper = info["partition"], request["device"], info["mapper"]
    info.update(_preflight_reobserve(receipt, request, info))
    material, key_identity = _create_key(receipt, info["serviceRole"], info)
    info["secretMaterial"] = material
    info.update(_preflight_reobserve(receipt, request, info))
    if key_identity is not None:
        info["createdKeyIdentity"] = key_identity

    # Record possible partial effects before each command that can mutate disk state.
    mutations["diskMutationAttempted"] = True
    sgdisk = [SGDISK, "--zap-all", "--new=1:0:0", f"--typecode=1:{GPT_LINUX_LUKS_TYPE}", "--", device]
    try:
        result = _run(sgdisk, step="gpt-partition")
    except Refusal as failure:
        if failure.signal_name == "agathodaimon-nas-command-group-unreaped":
            _record(receipt, "early-partition-identity", False, observed=False,
                    reason="gpt-child-group-unreaped")
        else:
            # A completed failing command may still have left a partial GPT write.
            _capture_early_partition_identity(receipt, info)
        raise
    # sgdisk can leave a partition behind even when it returns a failure status.
    _capture_early_partition_identity(receipt, info)
    if result.returncode != 0:
        raise Refusal("agathodaimon-nas-command-failed", "gpt-partition", result.returncode)
    if not _probe_partition_type(receipt, device):
        raise Refusal("agathodaimon-nas-partition-type-mismatch", "partition-type-readback")

    trigger = _run([UDEVADM, "trigger", "--subsystem-match=block", "--action=change"], step="udev-trigger")
    trigger_ok = trigger.returncode == 0
    _record(receipt, "udev-trigger", trigger_ok, rc=trigger.returncode)
    if not trigger_ok:
        raise Refusal("agathodaimon-nas-udev-trigger-failed", "udev-trigger", trigger.returncode)
    settle = _run([UDEVADM, "settle", "--timeout=30"], step="udev-settle")
    settle_ok = settle.returncode == 0
    _record(receipt, "udev-settle", settle_ok, rc=settle.returncode)
    if not settle_ok:
        raise Refusal("agathodaimon-nas-udev-settle-failed", "udev-settle", settle.returncode)
    partition_node = _probe_block_from_tree(receipt, partition, "part")
    if partition_node is None:
        raise Refusal("agathodaimon-nas-partition-readback-missing", "partition-readback")
    info["createdPartitionIdentity"] = partition_node["maj:min"]
    _record(receipt, "gpt-partition", True, rc=result.returncode, partitionExists=True,
            partitionType=partition_node.get("type"), identity=partition_node.get("maj:min"),
            typecode=GPT_LINUX_LUKS_TYPE)

    mutations["diskMutationAttempted"] = True
    format_command = [CRYPTSETUP, "luksFormat", "--type", "luks2", "--batch-mode", "--key-file", "-", "--", partition]
    formatted = _run(format_command, input_data=bytes(material), timeout=180, step="luks-format")
    _zero(material)
    try:
        _verify_luks2(receipt, partition)
    except Refusal as readback_failure:
        if formatted.returncode != 0:
            raise Refusal("agathodaimon-nas-command-failed", "luks-format", formatted.returncode)
        raise readback_failure
    if formatted.returncode != 0:
        raise Refusal("agathodaimon-nas-command-failed", "luks-format", formatted.returncode)
    _record(receipt, "luks-format", True, rc=formatted.returncode, luks2=True)

    mutations["mapperOpenAttempted"] = True
    open_material = _export_again(receipt, info["serviceRole"])
    try:
        opened = _run([CRYPTSETUP, "open", "--batch-mode", "--key-file", "-", "--", partition, mapper],
                      input_data=bytes(open_material), timeout=120, step="cryptsetup-open")
    finally:
        _zero(open_material)
    mapper_state = _mapper_state(mapper, partition)
    _record(receipt, "cryptsetup-open", bool(opened.returncode == 0 and mapper_state.get("exists") and mapper_state.get("backingMatches")),
            rc=opened.returncode, mapper=mapper, **mapper_state)
    if opened.returncode != 0 or not mapper_state.get("exists") or not mapper_state.get("backingMatches"):
        raise Refusal("agathodaimon-nas-mapper-open-failed", "cryptsetup-open", opened.returncode)

    mkfs = _run([MKFS_XFS, "-f", f"/dev/mapper/{mapper}"], timeout=180, step="mkfs-xfs")
    xfs_type = _filesystem_type(f"/dev/mapper/{mapper}")
    _record(receipt, "mkfs-xfs", mkfs.returncode == 0 and xfs_type == "xfs", rc=mkfs.returncode, filesystem=xfs_type)
    if mkfs.returncode != 0 or xfs_type != "xfs":
        raise Refusal("agathodaimon-nas-xfs-format-failed", "mkfs-xfs", mkfs.returncode)

    close = _run([CRYPTSETUP, "close", mapper], step="cryptsetup-close-format-mapper")
    closed = not _mapper_state(mapper).get("exists")
    _record(receipt, "cryptsetup-close-format-mapper", close.returncode == 0 and closed, rc=close.returncode, absent=closed)
    if close.returncode != 0 or not closed:
        raise Refusal("agathodaimon-nas-mapper-close-failed", "cryptsetup-close-format-mapper", close.returncode)
    mutations["mapperOpenAttempted"] = False

    label = info["partlabel"]
    label_command = _run([SGDISK, f"--change-name=1:{label}", "--", device], step="partlabel-assign")
    trigger = _run([UDEVADM, "trigger", "--subsystem-match=block", "--action=change"], step="partlabel-trigger")
    settle = _run([UDEVADM, "settle", "--timeout=30"], step="partlabel-settle")
    label_readback = _probe_partlabel(receipt, partition, label)
    okay = label_command.returncode == 0 and trigger.returncode == 0 and settle.returncode == 0 and label_readback
    _record(receipt, "partlabel-assign", okay, rc=label_command.returncode, udevTriggerRc=trigger.returncode,
            udevSettleRc=settle.returncode, partlabel=label if label_readback else None)
    if not okay:
        bad = next((r for r in (label_command, trigger, settle) if r.returncode != 0), label_command)
        raise Refusal("agathodaimon-nas-partlabel-failed", "partlabel-assign", bad.returncode)

    _ensure_mountpoint_directory(info["mountpoint"])
    mutations["mountAttempted"] = True
    mutations["helperAttempted"] = True
    mount_command = None
    helper_failure: Exception | None = None
    try:
        mount_command = _run([BASH, MOUNT_DRIVE, "mount", partition, info["mountpoint"], mapper],
                             timeout=180, step="mount-helper")
    except Exception as failure:
        helper_failure = failure
    finally:
        try:
            _helper_unit_readback(receipt, info, info["unitPaths"])
        except Exception as failure:
            helper_failure = helper_failure or failure
    if helper_failure is not None:
        if isinstance(helper_failure, Refusal):
            raise helper_failure
        raise Refusal("agathodaimon-nas-helper-command-aborted", "mount-helper")
    assert mount_command is not None
    partition_unit = Path(info["unitPaths"]["partition"]).name
    for unit in (partition_unit, Path(info["unitPaths"]["mount"]).name):
        _systemctl_state(receipt, "is-active", unit, {0})
    mount_readback = _mount_readback(info)
    _record(receipt, "mount-helper", bool(mount_command.returncode == 0 and mount_readback.get("mounted")
            and mount_readback.get("sourceMatches") and mount_readback.get("fstype") == "xfs"),
            rc=mount_command.returncode, **mount_readback)
    if mount_command.returncode != 0 or not mount_readback.get("mounted") or not mount_readback.get("sourceMatches") or mount_readback.get("fstype") != "xfs":
        raise Refusal("agathodaimon-nas-mount-readback-mismatch", "mount-helper", mount_command.returncode)

    _apply_permissions(receipt, info)
    # Helper Wants may have started units; retain the before-mount snapshot and stop only new starts on rollback.
    _start_nas_services(receipt, info)
    _record(receipt, "transaction-complete", True, applications=len(info["config"]["applications"]),
            servicesStarted=list(info["servicesStarted"]))
    return key_identity, material


def _export_again(receipt: dict[str, Any], service_role: str) -> bytearray:
    return _export_named_key(receipt, service_role, "key-export-for-open")


def _rollback_receipt(receipt: dict[str, Any], info: dict[str, Any], key_identity: dict[str, Any] | None,
                      mutations: dict[str, Any], failure_signal: str | None = None,
                      failure_return_code: int | None = None) -> list[dict[str, Any]]:
    if failure_signal == "agathodaimon-nas-command-group-unreaped":
        steps = [{"step": "rollback-blocked-child-group", "ok": False,
                  "readback": {"childGroupReaped": False, "rc": failure_return_code,
                               "reason": "avoided-racing-unknown-child-mutation"}}]
        if key_identity is not None:
            steps.append({"step": "retain-created-key", "ok": False,
                          "readback": {"identityKnown": True, "cleanupCertain": False, "rc": None,
                                       "reason": "rollback-incomplete"}})
        return steps
    prior = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            prior[signum] = signal.signal(signum, signal.SIG_IGN)
        except ValueError:
            pass
    try:
        return _rollback(receipt, info, key_identity, mutations)
    except Exception:
        steps = [{"step": "rollback-observation", "ok": False,
                  "readback": {"observed": "rollback-raised", "rc": None,
                               "reason": "rollback-observation-raised"}}]
        if key_identity is not None:
            steps.append({"step": "retain-created-key", "ok": False,
                          "readback": {"identityKnown": True, "cleanupCertain": False, "rc": None,
                                       "reason": "rollback-incomplete"}})
        return steps
    finally:
        for signum, handler in prior.items():
            try:
                signal.signal(signum, handler)
            except ValueError:
                pass


def _perform(request: dict[str, Any]) -> dict[str, Any]:
    receipt: dict[str, Any] = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete",
                               "role": request.get("role"), "device": request.get("device"), "partition": None,
                               "partlabel": None, "mapper": None, "mountpoint": None, "steps": [],
                               "servicesStarted": [], "rolledBack": False, "rollbackSteps": []}
    lock_fd = None
    info = None
    key_identity = None
    material = bytearray()
    try:
        if os.geteuid() != 0:
            raise Refusal("agathodaimon-nas-root-required", "root-preflight")
        try:
            lock_fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
            lock_st = os.fstat(lock_fd)
            if not stat.S_ISREG(lock_st.st_mode) or lock_st.st_uid != 0:
                raise OSError("unsafe-lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError):
            raise Refusal("agathodaimon-nas-transaction-lock-unavailable", "transaction-lock")
        _record(receipt, "transaction-lock", True, acquired=True)
        info = _preflight(receipt, request["device"], request["role"])
        receipt.update(partition=info["partition"], partlabel=info["partlabel"], mapper=info["mapper"], mountpoint=info["mountpoint"])
        key_identity, material = _execute(receipt, request, info)
        receipt["ok"] = True
        receipt["firstMissingSignal"] = "none"
        receipt["servicesStarted"] = list(info["servicesStarted"])
        return receipt
    except Refusal as failure:
        if not receipt["steps"] or receipt["steps"][-1]["step"] != failure.step:
            _record(receipt, failure.step, False, rc=failure.return_code)
        receipt["firstMissingSignal"] = failure.signal_name
        receipt["failedStep"] = _safe_step(failure.step)
        if failure.return_code is not None:
            receipt["returnCode"] = failure.return_code
        if info is not None:
            receipt["servicesStarted"] = list(info.get("servicesStarted", []))
        if info is not None:
            key_identity = key_identity or info.get("createdKeyIdentity")
            if info.get("mutations", {}).get("diskMutationAttempted") or key_identity is not None:
                steps = _rollback_receipt(receipt, info, key_identity, info.get("mutations", {}),
                                          receipt["firstMissingSignal"], failure.return_code)
                receipt["rollbackSteps"] = steps
                receipt["rolledBack"] = bool(steps) and all(step.get("ok") is True for step in steps)
        return receipt
    except Exception:
        receipt["firstMissingSignal"] = "agathodaimon-nas-transaction-aborted"
        receipt["failedStep"] = "transaction"
        if info is not None:
            receipt["servicesStarted"] = list(info.get("servicesStarted", []))
        if info is not None:
            key_identity = key_identity or info.get("createdKeyIdentity")
            if info.get("mutations", {}).get("diskMutationAttempted") or key_identity is not None:
                steps = _rollback_receipt(receipt, info, key_identity, info.get("mutations", {}), receipt["firstMissingSignal"])
                receipt["rollbackSteps"] = steps
                receipt["rolledBack"] = bool(steps) and all(step.get("ok") is True for step in steps)
        return receipt
    finally:
        _zero(material)
        if info is not None:
            _zero(info.get("secretMaterial", bytearray()))
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except OSError:
                pass


def _request(value: Any) -> dict[str, str]:
    if not all(hasattr(value, field) for field in ("value", "payload", "envelope")):
        raise Refusal("agathodaimon-nas-request-invalid", "request")
    raw = value.value
    if not isinstance(raw, dict):
        raise Refusal("agathodaimon-nas-request-invalid", "request")
    payload = value.payload
    original_payload = raw.get("payload") if value.envelope else raw
    if (not isinstance(payload, dict) or not isinstance(original_payload, dict)
            or set(original_payload) != {"device", "role"}):
        raise Refusal("agathodaimon-nas-request-invalid", "request")
    device, role = payload.get("device"), payload.get("role")
    if not isinstance(device, str) or not _SAFE_DEVICE.fullmatch(device) or device in {"/dev/.", "/dev/.."}:
        raise Refusal("agathodaimon-nas-device-invalid", "request")
    if not isinstance(role, str) or role not in ROLE:
        raise Refusal("agathodaimon-nas-role-invalid", "request")
    return {"device": device, "role": role}


def _read_envelope_text(raw: str):
    previous_stdin = sys.stdin
    try:
        sys.stdin = io.StringIO(raw)
        return read_envelope(known_fields=("device", "role"))
    finally:
        sys.stdin = previous_stdin


def _envelope_refusal(error: EnvelopeError) -> Refusal:
    message = str(error)
    if "foreign envelope schema" in message:
        return Refusal("agathodaimon-nas-envelope-schema-foreign", "request-envelope")
    if "missing envelope kernel keys" in message:
        return Refusal("agathodaimon-nas-envelope-kernel-missing", "request-envelope")
    return Refusal("agathodaimon-nas-envelope-invalid", "request-envelope")


def _attach_success_outcome(receipt: dict[str, Any], envelope_request: Any) -> dict[str, Any]:
    result = attach_envelope(receipt, envelope_request)
    if (envelope_request.envelope and result.get("ok") is True
            and result.get("firstMissingSignal") == "none"):
        if isinstance(result.get("staff"), dict):
            result["staff"]["outcome"] = "ok"
        if isinstance(result.get("stamps"), list) and result["stamps"]:
            result["stamps"][-1]["outcome"] = "ok"
        carried = result.get("envelope")
        if isinstance(carried, dict) and isinstance(carried.get("stamps"), list) and carried["stamps"]:
            carried["stamps"][-1]["outcome"] = "ok"
    return result


def dispatch(value: Any) -> dict[str, Any]:
    try:
        if all(hasattr(value, field) for field in ("value", "payload", "envelope")):
            envelope_request = value
        else:
            raw = value.decode("utf-8") if isinstance(value, bytes) else value if isinstance(value, str) else json.dumps(value)
            envelope_request = _read_envelope_text(raw)
        request = _request(envelope_request)
    except Refusal as failure:
        return {"schema": SCHEMA, "ok": False, "firstMissingSignal": failure.signal_name,
                "role": None, "device": None, "partition": None, "partlabel": None, "mapper": None,
                "mountpoint": None, "steps": [{"step": failure.step, "ok": False,
                "readback": {"rc": failure.return_code}}], "servicesStarted": [], "rolledBack": False,
                "rollbackSteps": []}
    except (UnicodeError, json.JSONDecodeError, EnvelopeError) as error:
        failure = _envelope_refusal(error) if isinstance(error, EnvelopeError) else Refusal("agathodaimon-nas-request-invalid", "request")
        return {"schema": SCHEMA, "ok": False, "firstMissingSignal": failure.signal_name,
                "role": None, "device": None, "partition": None, "partlabel": None, "mapper": None,
                "mountpoint": None, "steps": [{"step": failure.step, "ok": False,
                "readback": {"rc": None}}], "servicesStarted": [], "rolledBack": False, "rollbackSteps": []}
    return _attach_success_outcome(_perform(request), envelope_request)


def _handle_signal(signum: int, _frame: Any) -> None:
    raise Interrupted("agathodaimon-nas-interrupted", "signal-interrupted", signum)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    previous = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.signal(signum, _handle_signal)
    try:
        try:
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
            if not raw or len(raw) > MAX_INPUT:
                raise Refusal("agathodaimon-nas-request-invalid", "request")
            receipt = dispatch(raw)
        except (UnicodeError, json.JSONDecodeError, Refusal):
            receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-request-invalid",
                       "role": None, "device": None, "partition": None, "partlabel": None, "mapper": None,
                       "mountpoint": None, "steps": [{"step": "request", "ok": False, "readback": {}}],
                       "servicesStarted": [], "rolledBack": False, "rollbackSteps": []}
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        return 0 if receipt["ok"] else 1
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())

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

SCHEMA = "caduceus.nas.setup.v1"
MAX_INPUT = 65536
LOCK_PATH = "/run/lock/agathodaimon-nas-setup.lock"
CONFIG_PATHS = ("/etc/appliance/config.json", "/etc/appliance/config.factory")
SYS_DEV_BLOCK = Path("/sys/dev/block")
MOUNTINFO = Path("/proc/self/mountinfo")
UNIT_DIR = Path("/etc/systemd/system")
KEYMAN_CREATE = "/vault/keyman/keyman-crypto"
KEYMAN_DELETE = "/vault/keyman/deletekey.sh"
EXPORT_NAS = "/vault/scripts/exportNAS.sh"
MOUNT_DRIVE = "/vault/scripts/mountDrive.sh"
UNMOUNT_DRIVE = "/vault/scripts/unmountDrive.sh"
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
                raise Refusal("agathodaimon-nas-command-group-unreaped", command_step)
        raise Refusal("agathodaimon-nas-command-timeout", command_step)
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
    for line in lines:
        fields = line.split()
        if len(fields) < 2 or not fields[0].endswith(".service"):
            continue
        unit, enabled_state = fields[0], fields[1]
        enabled = enabled_state in {"enabled", "enabled-runtime"}
        if enabled_state == "masked":
            continue
        fragment = _run([SYSTEMCTL, "show", unit, "--property=FragmentPath", "--value"])
        cat = _run([SYSTEMCTL, "cat", unit, "--no-pager"])
        if fragment.returncode != 0 or cat.returncode != 0:
            failed = fragment if fragment.returncode != 0 else cat
            _record(receipt, "service-condition-readback", False, unit=unit, rc=failed.returncode)
            raise Refusal("agathodaimon-nas-service-unit-unreadable", "service-condition-readback", failed.returncode)
        fragment_path = _decode_output(fragment, "service-condition-readback")
        if not fragment_path or fragment_path == "/dev/null":
            _record(receipt, "service-condition-readback", False, unit=unit, observed="unreadable")
            raise Refusal("agathodaimon-nas-service-unit-unreadable", "service-condition-readback")
        try:
            text = cat.stdout.decode("utf-8")
        except UnicodeError:
            raise Refusal("agathodaimon-nas-service-unit-invalid", "service-condition-readback")
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
        matches = mountpoint in conditions
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
    _record(receipt, "service-census", True, nasDependentCount=len(services))
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
        exported = _run([BASH, EXPORT_NAS, service_role], step="key-export")
        if exported.returncode != 0 or not exported.stdout:
            _record(receipt, "key-export", False, rc=exported.returncode)
            raise Refusal("agathodaimon-nas-key-export-failed", "key-export", exported.returncode)
        material = bytearray(exported.stdout.rstrip(b"\r\n"))
        if not material or b"\x00" in material:
            _zero(material)
            _record(receipt, "key-export", False, observed="invalid")
            raise Refusal("agathodaimon-nas-key-export-invalid", "key-export")
        _record(receipt, "key-export", True, present=True, bytes=len(material))
        return material, None
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
    exported = _run([BASH, EXPORT_NAS, service_role], step="key-export")
    if exported.returncode != 0 or not exported.stdout:
        raise Refusal("agathodaimon-nas-key-export-failed", "key-export", exported.returncode)
    material = bytearray(exported.stdout.rstrip(b"\r\n"))
    if not material or b"\x00" in material:
        _zero(material)
        raise Refusal("agathodaimon-nas-key-export-invalid", "key-export")
    _record(receipt, "key-export", True, present=True, bytes=len(material))
    return material, created_identity


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
            "backingMatches": backing_matches}


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
            try:
                text = raw.decode("utf-8")
            except UnicodeError:
                text = ""
            service = info["serviceRole"]
            commands = []
            for line in text.splitlines():
                key, sep, value = line.partition("=")
                if sep and key.strip() in {"ExecStart", "ExecStartPre", "ExecStartPost"}:
                    try:
                        argv = shlex.split(value.strip())
                    except ValueError:
                        commands.append([])
                        continue
                    layers = [argv]
                    current = argv
                    for _ in range(8):
                        if not current or os.path.basename(current[0]) not in {"bash", "sh"}:
                            break
                        try:
                            command_index = current.index("-c")
                            nested = shlex.split(current[command_index + 1])
                        except (ValueError, IndexError):
                            break
                        if not nested:
                            break
                        layers.append(nested)
                        current = nested
                    commands.extend(layers)
            partition = info["partition"]
            mapper = info["mapper"]
            has_export = any(EXPORT_NAS in command and service in command for command in commands)
            has_open = any("luksOpen" in command and partition in command
                            and (mapper in command or f"/dev/mapper/{mapper}" in command) for command in commands)
            _record(receipt, "helper-unit-readback", has_export and has_open, unit=path.name,
                    exportRole=has_export, luksOpenMatches=has_open, partition=partition, mapper=mapper)
            if not has_export or not has_open:
                raise Refusal("agathodaimon-nas-helper-boot-command-mismatch", "helper-unit-readback")
        else:
            expected_where = info["mountpoint"]
            expected_what = f"/dev/mapper/{info['mapper']}"
            okay = values.get("Where") == expected_where and values.get("What") == expected_what and values.get("Type") == "xfs"
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
    if len(matches) != 1:
        return {"mounted": False, "sourceMatches": False, "fstype": None}
    try:
        mapper_identity = _device_identity(f"/dev/mapper/{info['mapper']}", "mount-readback")
        root_stat = os.stat(info["mountpoint"], follow_symlinks=False)
    except Refusal:
        return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"]}
    except OSError:
        return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"]}
    stat_identity = f"{os.major(root_stat.st_dev)}:{os.minor(root_stat.st_dev)}"
    source_matches = matches[0]["dev"] == mapper_identity == stat_identity
    return {"mounted": True, "sourceMatches": source_matches,
            "mountinfoIdentity": matches[0]["dev"], "statIdentity": stat_identity,
            "fstype": matches[0]["fstype"], "target": matches[0]["target"]}


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


def _inactive_unit(unit: str) -> bool:
    result = _run([SYSTEMCTL, "is-active", unit], step="rollback-unit-state")
    return result.returncode == 3 and result.stdout.strip() == b"inactive"


def _rollback_target_guard(info: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    device, partition = info["device"], info["partition"]
    expected_device = info["deviceIdentity"]
    expected_partition = info.get("createdPartitionIdentity")
    try:
        observed_device = _device_identity(device, "rollback-device-identity")
        result = _run([LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL", device],
                      step="rollback-block-census")
        if result.returncode != 0:
            return False, {"deviceIdentity": observed_device, "lsblkRc": result.returncode, "valid": False}
        value = json.loads(result.stdout.decode("utf-8"))
        nodes = list(_walk_nodes(value))
        roots = [row for row in nodes if row.get("path") == device]
        if len(roots) != 1 or roots[0].get("maj:min") != expected_device:
            return False, {"deviceIdentity": observed_device, "lsblkRootCount": len(roots), "valid": False}
        partitions = [row for row in nodes if row.get("path") == partition and row.get("type") == "part"]
        if expected_partition is None:
            partition_ok = not partitions
            try:
                os.lstat(partition)
                partition_ok = False
            except FileNotFoundError:
                pass
            except OSError:
                partition_ok = False
        else:
            partition_ok = (len(partitions) == 1 and partitions[0].get("maj:min") == expected_partition
                            and _normalize_pkname(partitions[0].get("pkname")) == os.path.basename(device))
            partition_stat_identity = _device_identity(partition, "rollback-partition-identity")
            partition_ok = partition_ok and partition_stat_identity == expected_partition
        if observed_device != expected_device or not partition_ok:
            return False, {"deviceIdentity": observed_device, "partitionIdentity": partitions[0].get("maj:min") if len(partitions) == 1 else None,
                           "partitionExpected": expected_partition, "valid": False}
        graph, _paths = _block_graph()
        component = _component(graph, expected_device)
        mapper_state = _mapper_state(info["mapper"], partition)
        if mapper_state.get("exists") is not False:
            return False, {"deviceIdentity": observed_device, "partitionIdentity": expected_partition,
                           "mapperAbsent": False, "valid": False}
        holders = []
        for identity in sorted(component):
            resolved = (SYS_DEV_BLOCK / identity).resolve(strict=True)
            holder_dir = resolved / "holders"
            if not holder_dir.is_dir():
                return False, {"deviceIdentity": observed_device, "partitionIdentity": expected_partition,
                               "holdersReadable": False, "valid": False}
            names = sorted(os.listdir(holder_dir))
            if names:
                holders.extend(names)
        entries = _mountinfo()
        mounts = [entry for entry in entries if entry["target"] == info["mountpoint"]
                  or entry["target"].startswith(info["mountpoint"] + "/")
                  or (entry["dev"] in graph and bool(_component(graph, entry["dev"]) & component))]
        valid = not holders and not mounts
        return valid, {"deviceIdentity": observed_device, "partitionIdentity": expected_partition,
                       "mapperAbsent": True, "holders": holders, "mountCount": len(mounts), "valid": valid}
    except (Refusal, OSError, UnicodeError, ValueError, KeyError, TypeError):
        return False, {"valid": False, "observation": "incomplete"}


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
                                      "reason": "rollback-incomplete"}})
        return
    try:
        result = _run([KEYMAN_DELETE, service_role], step="delete-created-key")
    except Refusal:
        result = None
    try:
        os.lstat(path)
        absent = False
    except FileNotFoundError:
        absent = True
    except OSError:
        absent = False
    okay = result is not None and result.returncode == 0 and absent
    rollback.append({"step": "delete-created-key", "ok": okay,
                     "readback": {"rc": result.returncode if result else None,
                                  "absent": absent, "identityMatched": same}})


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
                exists = os.path.lexists(path)
            except OSError:
                exists = True
            if not exists:
                try:
                    inactive = _inactive_unit(path.name)
                except Refusal:
                    inactive = False
                if not inactive:
                    units_clean = False
                    records.append({"step": "helper-unit-state-conflict", "ok": False,
                                    "readback": {"unit": path.name, "absent": True, "inactive": False}})
            if exists and (snapshot is None or not _unit_matches_snapshot(path, snapshot)):
                units_clean = False
                records.append({"step": "helper-unit-identity-conflict", "ok": False,
                                "readback": {"unit": path.name, "exists": exists, "identityMatched": False}})
    mount_state: dict[str, Any] = {"mounted": False, "sourceMatches": False}
    mount_conflict = False
    try:
        mount_state = _mount_readback(info)
        all_mounts = _mountinfo()
        nested = [entry for entry in all_mounts if entry["target"].startswith(mountpoint + "/")]
        if nested:
            mount_conflict = True
    except Exception:
        mount_conflict = True
        mount_state = {"mounted": True, "sourceMatches": False, "observed": "unreadable"}
    if mount_state.get("mounted") and not (helper_attempted and mount_state.get("sourceMatches")):
        mount_conflict = True
        records.append({"step": "foreign-mount-conflict", "ok": False,
                        "readback": {"mounted": True, "sourceMatches": mount_state.get("sourceMatches", False)}})
    if not units_clean:
        mount_conflict = True
    if mount_conflict:
        records.append({"step": "mount-cleanup-blocked", "ok": False,
                        "readback": {"nestedOrUnreadable": True, "helperUnmountAttempted": False}})
    elif mount_state.get("mounted"):
        try:
            unmount = _run([BASH, UNMOUNT_DRIVE, partition, mountpoint, mapper], timeout=120, step="unmount-nas")
        except Refusal:
            unmount = None
        try:
            after = _mount_readback(info)
            absent = not after.get("mounted") and not any(row["target"].startswith(mountpoint + "/") for row in _mountinfo())
        except Exception:
            after, absent = {"mounted": True, "sourceMatches": False}, False
        records.append({"step": "unmount-nas", "ok": bool(unmount and unmount.returncode == 0 and absent),
                        "readback": {"rc": unmount.returncode if unmount else None, "mountAbsent": absent,
                                     "sourceMatches": after.get("sourceMatches", False)}})
    else:
        records.append({"step": "mount-absent", "ok": True, "readback": {"mounted": False}})

    services_clean = True
    if helper_attempted and units_clean and not mount_conflict:
        for service in info.get("services", []):
            unit = service["unit"]
            if service.get("activeBefore"):
                try:
                    active = _service_active(unit)
                except Refusal:
                    active = None
                okay = active is True
                services_clean = services_clean and okay
                records.append({"step": "preserve-preactive-service", "ok": okay,
                                "readback": {"unit": unit, "activeBefore": True, "active": active}})
            else:
                try:
                    active = _service_active(unit)
                except Refusal:
                    active = None
                if active is True:
                    if unit not in info.get("servicesStarted", []):
                        info["servicesStarted"].append(unit)
                    try:
                        stop = _run([SYSTEMCTL, "stop", unit], step="stop-new-service")
                    except Refusal:
                        stop = None
                    try:
                        inactive = _inactive_unit(unit)
                    except Refusal:
                        inactive = False
                    okay = bool(stop and stop.returncode == 0 and inactive)
                else:
                    stop, inactive = None, active is False
                    okay = inactive
                services_clean = services_clean and okay
                records.append({"step": "stop-new-service", "ok": okay,
                                "readback": {"unit": unit, "active": active,
                                             "rc": stop.returncode if stop else None, "inactive": inactive}})
    elif helper_attempted:
        services_clean = False
        records.append({"step": "dependent-service-cleanup-blocked", "ok": False,
                        "readback": {"unitIdentityConflict": not units_clean, "mountConflict": mount_conflict}})

    if helper_attempted and units_clean and not mount_conflict:
        files_removed = False
        for unit_name, path in reversed(list(info["unitPaths"].items())):
            snapshot = unit_snapshots.get(unit_name)
            if not os.path.lexists(path):
                try:
                    inactive = _inactive_unit(path.name)
                except Refusal:
                    inactive = False
                okay = inactive
                units_clean = units_clean and okay
                records.append({"step": "stop-helper-unit", "ok": okay,
                                "readback": {"unit": path.name, "absent": True, "inactive": inactive}})
                continue
            if snapshot is None or not _unit_matches_snapshot(path, snapshot):
                units_clean = False
                records.append({"step": "stop-helper-unit", "ok": False,
                                "readback": {"unit": path.name, "identityMatched": False}})
                continue
            try:
                stopped = _run([SYSTEMCTL, "stop", path.name], step="stop-helper-unit")
            except Refusal:
                stopped = None
            try:
                inactive = _inactive_unit(path.name)
            except Refusal:
                inactive = False
            stopped_ok = bool(stopped and stopped.returncode == 0 and inactive)
            units_clean = units_clean and stopped_ok
            records.append({"step": "stop-helper-unit", "ok": stopped_ok,
                            "readback": {"unit": path.name, "rc": stopped.returncode if stopped else None,
                                         "inactive": inactive, "identityMatched": True}})
        if units_clean:
            for unit_name, path in reversed(list(info["unitPaths"].items())):
                snapshot = unit_snapshots.get(unit_name)
                if snapshot is not None and os.path.lexists(path):
                    if not _unit_matches_snapshot(path, snapshot):
                        units_clean = False
                        records.append({"step": "remove-helper-unit", "ok": False,
                                        "readback": {"unit": path.name, "identityMatched": False, "absent": False}})
                        continue
                    try:
                        os.unlink(path)
                        files_removed = True
                    except OSError:
                        units_clean = False
                try:
                    absent = not os.path.lexists(path)
                    inactive = _inactive_unit(path.name) if absent else False
                except (OSError, Refusal):
                    absent, inactive = False, False
                okay = absent and inactive
                units_clean = units_clean and okay
                records.append({"step": "remove-helper-unit", "ok": okay,
                                "readback": {"unit": path.name, "identityMatched": snapshot is not None,
                                             "absent": absent, "inactive": inactive}})
            if files_removed:
                try:
                    reload = _run([SYSTEMCTL, "daemon-reload"], step="reload-after-unit-removal")
                except Refusal:
                    reload = None
                okay = bool(reload and reload.returncode == 0)
                records.append({"step": "reload-after-unit-removal", "ok": okay,
                                "readback": {"rc": reload.returncode if reload else None}})
                units_clean = units_clean and okay

    try:
        after_mount = _mount_readback(info)
        nested_after = [row for row in _mountinfo() if row["target"].startswith(mountpoint + "/")]
        mount_absent = not after_mount.get("mounted") and not nested_after
    except Exception:
        mount_absent = False
    mapper_closed = True
    mapper_close_safe = mount_absent and units_clean and services_clean
    if not mapper_close_safe and (mutations.get("diskMutationAttempted") or mutations.get("mapperOpenAttempted") or mutations.get("mountAttempted")):
        mapper_closed = False
        records.append({"step": "mapper-close-blocked", "ok": False,
                        "readback": {"mountAbsent": mount_absent, "unitsClean": units_clean,
                                     "servicesClean": services_clean}})
    elif mutations.get("diskMutationAttempted") or mutations.get("mapperOpenAttempted") or mutations.get("mountAttempted"):
        try:
            mapper_state = _mapper_state(mapper, partition)
        except Refusal:
            mapper_state = {"exists": None, "backingMatches": None}
        if mapper_state.get("exists") is True and mapper_state.get("backingMatches") is True:
            try:
                close = _run([CRYPTSETUP, "close", mapper], step="close-format-mapper")
            except Refusal:
                close = None
            try:
                mapper_closed = not _mapper_state(mapper, partition).get("exists")
            except Refusal:
                mapper_closed = False
            mapper_closed = bool(close and close.returncode == 0 and mapper_closed)
            records.append({"step": "close-format-mapper", "ok": mapper_closed,
                            "readback": {"rc": close.returncode if close else None, "absent": mapper_closed,
                                         "backingMatches": True}})
        elif mapper_state.get("exists") is False:
            mapper_closed = True
            records.append({"step": "mapper-absent", "ok": True, "readback": {"absent": True}})
        else:
            mapper_closed = False
            records.append({"step": "mapper-identity-conflict", "ok": False,
                            "readback": {"exists": mapper_state.get("exists"),
                                         "backingMatches": mapper_state.get("backingMatches")}})

    disk_clean = not mutations.get("diskMutationAttempted")
    if mutations.get("diskMutationAttempted"):
        safe_to_wipe = mount_absent and mapper_closed and units_clean and services_clean
        commands_ok = True
        if not safe_to_wipe:
            records.append({"step": "disk-wipe-blocked", "ok": False,
                            "readback": {"mountAbsent": mount_absent, "mapperClosed": mapper_closed,
                                         "unitsClean": units_clean, "servicesClean": services_clean}})
        else:
            expected_partition = info.get("createdPartitionIdentity")
            actions: list[tuple[str, list[str]]] = []
            if expected_partition is not None:
                actions.append(("wipe-created-partition", [WIPEFS, "--all", "--force", "--", partition]))
            else:
                records.append({"step": "partition-absent-before-rollback", "ok": True,
                                "readback": {"identity": None}})
            actions.extend([("wipe-created-disk-signatures", [WIPEFS, "--all", "--force", "--", device]),
                            ("zap-created-gpt", [SGDISK, "--zap-all", "--", device])])
            for step, argv in actions:
                guarded, readback = _rollback_target_guard(info)
                if not guarded:
                    commands_ok = False
                    records.append({"step": step, "ok": False,
                                    "readback": {"attempted": False, "guard": readback}})
                    break
                try:
                    command = _run(argv, step=step)
                except Refusal:
                    command = None
                command_ok = bool(command and command.returncode == 0)
                commands_ok = commands_ok and command_ok
                records.append({"step": step, "ok": command_ok,
                                "readback": {"attempted": True, "rc": command.returncode if command else None,
                                             "guard": readback}})
            if commands_ok:
                try:
                    trigger = _run([UDEVADM, "trigger", "--subsystem-match=block", "--action=change"], step="rollback-udev-trigger")
                    settle = _run([UDEVADM, "settle", "--timeout=30"], step="rollback-udev-settle")
                    signatures = _run([WIPEFS, "--noheadings", "--output", "TYPE", "--", device], step="rollback-signature-readback")
                    signature_text = signatures.stdout.decode("utf-8").strip()
                    tree = _run([LSBLK, "--json", "--paths", "--output", "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL", device],
                                step="rollback-partition-readback")
                    nodes = list(_walk_nodes(json.loads(tree.stdout.decode("utf-8")))) if tree.returncode == 0 else []
                    roots = [row for row in nodes if row.get("path") == device and row.get("maj:min") == info["deviceIdentity"]]
                    partitions_absent = bool(roots) and not any(row.get("type") == "part" for row in nodes)
                    signatures_absent = signatures.returncode == 0 and not signature_text
                    disk_clean = (trigger.returncode == 0 and settle.returncode == 0 and signatures_absent
                                  and partitions_absent)
                    records.append({"step": "disk-clean-readback", "ok": disk_clean,
                                    "readback": {"udevTriggerRc": trigger.returncode, "udevSettleRc": settle.returncode,
                                                 "signatureRc": signatures.returncode, "signaturesAbsent": signatures_absent,
                                                 "lsblkRc": tree.returncode, "partitionsAbsent": partitions_absent,
                                                 "deviceIdentityMatched": bool(roots)}})
                except (Refusal, OSError, UnicodeError, ValueError, KeyError, TypeError):
                    disk_clean = False
                    records.append({"step": "disk-clean-readback", "ok": False,
                                    "readback": {"observed": "incomplete"}})
            else:
                disk_clean = False
    else:
        records.append({"step": "disk-unchanged", "ok": True, "readback": {"mutationAttempted": False}})
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
    result = _run([BASH, EXPORT_NAS, service_role], step="key-export-for-open")
    if result.returncode != 0 or not result.stdout:
        _record(receipt, "key-export-for-open", False, rc=result.returncode)
        raise Refusal("agathodaimon-nas-key-export-failed", "key-export-for-open", result.returncode)
    material = bytearray(result.stdout.rstrip(b"\r\n"))
    if not material or b"\x00" in material:
        _zero(material)
        raise Refusal("agathodaimon-nas-key-export-invalid", "key-export-for-open")
    _record(receipt, "key-export-for-open", True, present=True, bytes=len(material))
    return material


def _rollback_receipt(receipt: dict[str, Any], info: dict[str, Any], key_identity: dict[str, Any] | None,
                      mutations: dict[str, Any], failure_signal: str | None = None) -> list[dict[str, Any]]:
    if failure_signal == "agathodaimon-nas-command-group-unreaped":
        steps = [{"step": "rollback-blocked-child-group", "ok": False,
                  "readback": {"childGroupReaped": False, "reason": "avoided-racing-unknown-child-mutation"}}]
        if key_identity is not None:
            steps.append({"step": "retain-created-key", "ok": False,
                          "readback": {"identityKnown": True, "cleanupCertain": False,
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
                  "readback": {"observed": "rollback-raised"}}]
        if key_identity is not None:
            steps.append({"step": "retain-created-key", "ok": False,
                          "readback": {"identityKnown": True, "cleanupCertain": False,
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
                steps = _rollback_receipt(receipt, info, key_identity, info.get("mutations", {}), receipt["firstMissingSignal"])
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

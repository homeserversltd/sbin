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
import stat
import subprocess
import sys
import io
from pathlib import Path
from typing import Any, Callable, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.lib.keyman_export.index import KeymanExportError, export_key
from agathodaimon.storage.nas.runtime import (
    Refusal,
    ROLE,
    _block_graph,
    _component,
    _device_identity,
    _list_enabled_nas_services,
    _mapper_state,
    _mount_readback,
    _mountinfo,
    _start_nas_services,
    _systemctl_state,
    attach_role,
    command_argv,
    require_fixed_units,
    runtime_path,
)

SCHEMA = "caduceus.nas.setup.v1"
MAX_INPUT = 65536
LOCK_PATH = "/run/lock/agathodaimon-nas-setup.lock"
CONFIG_PATHS = ("/etc/appliance/config.json", "/etc/appliance/config.factory")
SYS_DEV_BLOCK = Path("/sys/dev/block")
KEYMAN_CREATE = "/vault/keyman/keyman-crypto"
KEYMAN_DELETE = "/vault/keyman/deletekey.sh"
SGDISK = "/usr/sbin/sgdisk"
UDEVADM = "/usr/bin/udevadm"
LSBLK = "/usr/bin/lsblk"
BLKID = "/usr/sbin/blkid"
WIPEFS = "/usr/sbin/wipefs"
CRYPTSETUP = "/usr/sbin/cryptsetup"
MKFS_XFS = "/usr/sbin/mkfs.xfs"
SYSTEMCTL = "/usr/bin/systemctl"
GPT_LINUX_LUKS_TYPE = "8309"
_SAFE_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._-]{1,128}$")
_SAFE_NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
_OCTAL_MODE = re.compile(r"^(?:0?[0-7]{3})$")

PortalFolderLayoutRow = tuple[str, str, str, int]
PORTAL_FOLDER_LAYOUT: dict[str, tuple[PortalFolderLayoutRow, ...]] = {
    "primary": (
        ("", "www-data", "www-data", 0o777),
        ("books", "calibre", "www-data", 0o775),
        ("books/upload", "calibre", "www-data", 0o775),
        ("downloads", "debian-transmission", "www-data", 0o775),
        ("media", "jellyfin", "www-data", 0o775),
        ("music", "navidrome", "www-data", 0o775),
        ("photos", "piwigo", "www-data", 0o777),
    ),
    "backup": (
        ("", "www-data", "www-data", 0o777),
    ),
}


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
    safe_argv = list(command_argv(argv))
    process = None
    try:
        process = subprocess.Popen(safe_argv, stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        stdout, stderr = process.communicate(input=input_data, timeout=timeout)
        return subprocess.CompletedProcess(safe_argv, process.returncode, stdout, stderr)
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
    path = str(runtime_path(path))
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


def _check_mountpoint_conflict(receipt: dict[str, Any], entries: list[dict[str, str]], mountpoint: str) -> None:
    conflicts = [entry for entry in entries if entry["target"] == mountpoint or entry["target"].startswith(mountpoint + "/")]
    if conflicts:
        _record(receipt, "mountpoint-preflight", False, mounted=True, conflictCount=len(conflicts))
        raise Refusal("agathodaimon-nas-mountpoint-in-use", "mountpoint-preflight")
    physical_mountpoint = runtime_path(mountpoint)
    try:
        metadata = os.lstat(physical_mountpoint)
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
        with os.scandir(physical_mountpoint) as iterator:
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
    mapper = expected["mapper"]
    mapper_path = runtime_path(f"/dev/mapper/{mapper}")
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
    unit_states_before = require_fixed_units(role, receipt, require_mount_inactive=True)
    config = _load_config(receipt, expected["mountpoint"])
    services = _list_enabled_nas_services(receipt, expected["mountpoint"])
    return {"deviceIdentity": identity, "deviceType": dev_type, "partition": partition,
            "mapper": mapper, "mountpoint": expected["mountpoint"], "partlabel": expected["partlabel"],
            "serviceRole": expected["service"], "role": role,
            "mountUnit": expected["mount_unit"], "openUnit": expected["open_unit"],
            "graph": graph, "targetComponent": target_component, "mountinfo": entries,
            "config": config, "services": services, "unitStatesBefore": unit_states_before,
            "unitsStarted": [], "servicesStarted": []}


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
    path = str(runtime_path(path))
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


def _filesystem_type(device: str) -> str | None:
    result = _run([BLKID, "-s", "TYPE", "-o", "value", "--", device], step="xfs-readback")
    if result.returncode != 0:
        return None
    value = _decode_output(result, "xfs-readback")
    return value if value in {"xfs", "crypto_LUKS"} else None


def _ensure_mountpoint_directory(path: str) -> None:
    path = str(runtime_path(path))
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
    stack = [Path(runtime_path(path))]
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
    path = str(runtime_path(path))
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
    try:
        st = os.fstat(child_fd)
        if st.st_dev != root_dev:
            raise Refusal("agathodaimon-nas-path-escape", "permissions-preflight")
        _permission_mount_guard(root_fd, mountpoint, mapper_identity,
                                (os.fstat(root_fd).st_dev, os.fstat(root_fd).st_ino))
        return child_fd
    except BaseException:
        try:
            os.close(child_fd)
        except OSError:
            pass
        raise


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


def _portal_layout_actual(fd: int | None, path: str | None) -> dict[str, Any]:
    actual: dict[str, Any] = {
        "path": None, "owner": None, "group": None,
        "mode": None, "actualDevice": None, "uid": None, "gid": None,
    }
    if fd is None:
        return actual
    try:
        metadata = os.fstat(fd)
    except OSError:
        return actual
    try:
        owner = pwd.getpwuid(metadata.st_uid).pw_name
    except (KeyError, OSError):
        owner = None
    try:
        group = grp.getgrgid(metadata.st_gid).gr_name
    except (KeyError, OSError):
        group = None
    actual.update({
        "path": path, "owner": owner, "group": group,
        "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
        "actualDevice": metadata.st_dev, "uid": metadata.st_uid, "gid": metadata.st_gid,
    })
    return actual


def _seed_portal_layout(receipt: dict[str, Any], info: dict[str, Any]) -> None:
    """Apply only the fixed role rows through descriptors rooted at the verified mount."""
    role = info.get("role")
    rows = PORTAL_FOLDER_LAYOUT.get(role) if isinstance(role, str) else None
    if rows is None:
        _record(receipt, "portal-layout-preflight", False, role=role, reason="role-invalid")
        raise Refusal("agathodaimon-nas-portal-layout-role-invalid",
                      "portal-layout-preflight", receipt=receipt)

    mountpoint = info["mountpoint"]
    try:
        mapper_identity = _device_identity(f"/dev/mapper/{info['mapper']}", "portal-layout-preflight")
    except Refusal as failure:
        _record(receipt, "portal-layout-preflight", False, reason=failure.signal_name,
                mapperIdentity=None)
        raise Refusal(failure.signal_name, "portal-layout-preflight",
                      failure.return_code, receipt) from None

    root_fd: int | None = None
    try:
        root_fd = _open_directory_nofollow(mountpoint)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise Refusal("agathodaimon-nas-mounted-root-invalid", "portal-layout-preflight")
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        root_dev = root_stat.st_dev
        _permission_mount_guard(root_fd, mountpoint, mapper_identity, root_identity)
    except Refusal as failure:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass
        _record(receipt, "portal-layout-preflight", False, reason=failure.signal_name,
                mapperIdentity=mapper_identity)
        raise Refusal(failure.signal_name, "portal-layout-preflight",
                      failure.return_code, receipt) from None
    except OSError:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass
        _record(receipt, "portal-layout-preflight", False, reason="mounted-root-unreadable",
                mapperIdentity=mapper_identity)
        raise Refusal("agathodaimon-nas-mounted-root-unreadable",
                      "portal-layout-preflight", receipt=receipt) from None
    except BaseException:
        if root_fd is not None:
            try:
                os.close(root_fd)
            except OSError:
                pass
        raise

    try:
        _record(receipt, "portal-layout-preflight", True, mountpoint=mountpoint,
                mapperIdentity=mapper_identity, rootDevice=root_dev, nestedMounts=False)
        for relative, owner_name, group_name, mode in rows:
            expected_path = relative if isinstance(relative, str) and relative else "." if relative == "" else None
            expected_mode = f"{mode:04o}" if isinstance(mode, int) and not isinstance(mode, bool) else None
            expected: dict[str, Any] = {
                "expectedPath": expected_path, "expectedOwner": owner_name,
                "expectedGroup": group_name, "expectedMode": expected_mode,
                "expectedUid": None, "expectedGid": None,
            }

            path_valid = (isinstance(relative, str) and "\x00" not in relative
                          and not relative.startswith("/")
                          and (not relative or (posixpath.normpath(relative) == relative
                               and all(part not in {"", ".", ".."} for part in relative.split("/")))))
            names_valid = (isinstance(owner_name, str) and _SAFE_NAME.fullmatch(owner_name)
                           and isinstance(group_name, str) and _SAFE_NAME.fullmatch(group_name))
            mode_valid = (isinstance(mode, int) and not isinstance(mode, bool)
                          and 0 <= mode <= 0o777)
            if not path_valid or not names_valid or not mode_valid:
                _record(receipt, "portal-layout-row-refused", False, reason="declared-row-invalid",
                        **expected, **_portal_layout_actual(None, None))
                raise Refusal("agathodaimon-nas-portal-layout-row-invalid",
                              "portal-layout-row-refused", receipt=receipt)
            actual_path = posixpath.join(mountpoint, relative) if relative else mountpoint

            try:
                owner_entry = pwd.getpwnam(owner_name)
            except KeyError:
                _record(receipt, "portal-layout-row-skipped", True, skipped=True,
                        reason="owner-user-absent", **expected,
                        **_portal_layout_actual(None, None))
                continue
            except OSError:
                _record(receipt, "portal-layout-row-refused", False, reason="owner-user-unreadable",
                        **expected, **_portal_layout_actual(None, None))
                raise Refusal("agathodaimon-nas-portal-layout-user-unreadable",
                              "portal-layout-row-refused", receipt=receipt) from None
            expected["expectedUid"] = owner_entry.pw_uid

            try:
                group_entry = grp.getgrnam(group_name)
            except KeyError:
                _record(receipt, "portal-layout-row-refused", False, reason="owner-group-absent",
                        **expected, **_portal_layout_actual(None, None))
                raise Refusal("agathodaimon-nas-portal-layout-group-absent",
                              "portal-layout-row-refused", receipt=receipt) from None
            except OSError:
                _record(receipt, "portal-layout-row-refused", False, reason="owner-group-unreadable",
                        **expected, **_portal_layout_actual(None, None))
                raise Refusal("agathodaimon-nas-portal-layout-group-unreadable",
                              "portal-layout-row-refused", receipt=receipt) from None
            expected["expectedGid"] = group_entry.gr_gid

            current_fd: int | None = None
            row_recorded = False
            try:
                current_fd = os.dup(root_fd)
                if relative:
                    for component in relative.split("/"):
                        child_fd = _open_or_create_child(current_fd, component, root_dev, root_fd,
                                                         mountpoint, mapper_identity)
                        parent_fd = current_fd
                        current_fd = child_fd
                        try:
                            os.close(parent_fd)
                        except OSError:
                            pass
                _permission_mount_guard(root_fd, mountpoint, mapper_identity, root_identity)
                opened = os.fstat(current_fd)
                if opened.st_dev != root_dev:
                    raise Refusal("agathodaimon-nas-path-escape", "portal-layout-row-refused")
                os.fchown(current_fd, owner_entry.pw_uid, group_entry.gr_gid)
                _permission_mount_guard(root_fd, mountpoint, mapper_identity, root_identity)
                os.fchmod(current_fd, mode)
                _permission_mount_guard(root_fd, mountpoint, mapper_identity, root_identity)
                observed = _portal_layout_actual(current_fd, actual_path)
                if (observed["actualDevice"] != root_dev
                        or observed["uid"] != owner_entry.pw_uid
                        or observed["gid"] != group_entry.gr_gid
                        or observed["owner"] != owner_entry.pw_name
                        or observed["group"] != group_entry.gr_name
                        or observed["mode"] != expected_mode):
                    raise Refusal("agathodaimon-nas-portal-layout-readback-mismatch",
                                  "portal-layout-row-refused")
                _record(receipt, "portal-layout-row-readback", True, applied=True, skipped=False,
                        **expected, **observed)
                row_recorded = True
            except Refusal as failure:
                if not row_recorded:
                    _record(receipt, "portal-layout-row-refused", False,
                            reason=failure.signal_name, **expected,
                            **_portal_layout_actual(current_fd, actual_path if current_fd is not None else None))
                    row_recorded = True
                raise Refusal(failure.signal_name, "portal-layout-row-refused",
                              failure.return_code, receipt) from None
            except Exception:
                if not row_recorded:
                    _record(receipt, "portal-layout-row-refused", False,
                            reason="directory-change-or-readback-failed", **expected,
                            **_portal_layout_actual(current_fd, actual_path if current_fd is not None else None))
                raise Refusal("agathodaimon-nas-portal-layout-row-failed",
                              "portal-layout-row-refused", receipt=receipt) from None
            finally:
                if current_fd is not None:
                    try:
                        os.close(current_fd)
                    except OSError:
                        pass
    finally:
        if root_fd is not None:
            os.close(root_fd)


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


def _rollback_systemctl_state(receipt: dict[str, Any], unit: str, step: str) -> dict[str, Any]:
    try:
        return_code, observed = _systemctl_state(receipt, "is-active", unit, allowed={0, 3})
    except Refusal as failure:
        return {"state": None, "rc": failure.return_code, "reason": failure.signal_name}
    running = {"active", "reloading", "refreshing"}
    if return_code == 0 and observed in running:
        return {"state": observed, "rc": return_code}
    if return_code == 3 and observed in {"inactive", "failed", "activating", "deactivating"}:
        return {"state": observed, "rc": return_code}
    return {"state": None, "rc": return_code,
            "observed": observed or "empty", "reason": "service-state-unrecognized", "step": step}


def _rollback_stop_owned_unit(rollback: list[dict[str, Any]], receipt: dict[str, Any],
                              unit: str, step: str, initial: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
    stop_result = None
    stop_failure: str | None = None
    try:
        stop_result = _run([SYSTEMCTL, "stop", unit], timeout=180, step=step)
    except Refusal as failure:
        stop_failure = failure.signal_name
        stop_rc = failure.return_code
    else:
        stop_rc = stop_result.returncode

    final_state = _rollback_systemctl_state(receipt, unit, step + "-state")
    initial_known = initial.get("state") is not None
    final_known = final_state.get("state") is not None
    inactive = final_state.get("state") == "inactive"
    stop_ok = stop_result is not None and stop_rc == 0
    if not initial_known:
        reason = initial.get("reason", "initial-state-unknown")
    elif stop_failure is not None:
        reason = stop_failure
    elif stop_rc != 0:
        reason = "stop-command-failed"
    elif not final_known:
        reason = final_state.get("reason", "post-stop-state-unknown")
    elif not inactive:
        reason = "unit-not-inactive"
    else:
        reason = "inactive-after-stop"
    okay = bool(initial_known and stop_ok and final_known and inactive)
    rollback.append({"step": _safe_step(step), "ok": okay,
                     "readback": {"unit": unit, "owned": True, "initialState": initial.get("state"),
                                  "initialStateRc": initial.get("rc"),
                                  "initialStateReason": initial.get("reason"),
                                  "stopRc": stop_rc, "stopReason": stop_failure,
                                  "finalState": final_state.get("state"),
                                  "finalStateRc": final_state.get("rc"),
                                  "finalStateReason": final_state.get("reason"),
                                  "inactive": inactive, "reason": reason}})
    return okay, final_state


def _rollback_target_guard(receipt: dict[str, Any], info: dict[str, Any],
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
            os.lstat(runtime_path(partition))
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
        mapper_state = _mapper_state(receipt, info)
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
            resolved = Path(runtime_path(SYS_DEV_BLOCK / identity)).resolve(strict=True)
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
    path = runtime_path(_key_path(service_role))
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
    attachment_attempted = bool(mutations.get("mountAttempted"))
    raw_owned_units = info.get("unitsStarted", [])
    owned_units = {unit for unit in raw_owned_units if isinstance(unit, str)} if isinstance(raw_owned_units, list) else set()
    mount_unit, open_unit = info["mountUnit"], info["openUnit"]
    units_clean = True
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
    if mount_state.get("mounted") and not (attachment_attempted and mount_unit in owned_units
                                             and mount_state.get("sourceMatches")
                                             and mount_state.get("fstype") == "xfs"):
        mount_conflict = True
        records.append({"step": "foreign-mount-conflict", "ok": False,
                        "readback": {"mounted": True, "sourceMatches": mount_state.get("sourceMatches", False),
                                     "rc": mount_state.get("findmntRc"),
                                     "reason": mount_state.get("reason", "mount-identity-or-filesystem-mismatch")}})
    records.append({"step": "mount-pre-unmount-readback", "ok": not mount_conflict,
                    "readback": {**mount_state, "nestedCount": len(nested),
                                 "reason": "owned-mount-or-absent" if not mount_conflict else "mount-cleanup-conflict"}})

    services_clean = True
    if attachment_attempted:
        running_states = {"active", "activating", "reloading", "refreshing", "deactivating"}
        owned_services = set(info.get("servicesStarted", []))
        for service in info.get("services", []):
            unit = service["unit"]
            initial = _rollback_systemctl_state(receipt, unit, "rollback-service-state")
            state = initial.get("state")
            if service.get("activeBefore"):
                preserved = state == "active"
                reason = "preactive-service-still-running" if state in running_states else "preactive-state-not-active"
                services_clean = False
                records.append({"step": "preserve-preactive-service", "ok": preserved,
                                "readback": {"unit": unit, "activeBefore": True, "state": state,
                                             "rc": initial.get("rc"), "reason": reason}})
                continue
            if unit in owned_services:
                if state in running_states | {"failed"}:
                    stopped, _final = _rollback_stop_owned_unit(records, receipt, unit, "stop-new-service", initial)
                    services_clean = services_clean and stopped
                elif state == "inactive":
                    records.append({"step": "leave-inactive-service", "ok": True,
                                    "readback": {"unit": unit, "owned": True, "state": state,
                                                 "rc": initial.get("rc"), "reason": "already-inactive"}})
                else:
                    services_clean = False
                    records.append({"step": "dependent-service-cleanup-blocked", "ok": False,
                                    "readback": {"unit": unit, "owned": True, "state": state,
                                                 "rc": initial.get("rc"),
                                                 "reason": initial.get("reason", "service-state-unknown")}})
            elif state == "inactive":
                records.append({"step": "leave-inactive-service", "ok": True,
                                "readback": {"unit": unit, "owned": False, "state": state,
                                             "rc": initial.get("rc"), "reason": "inactive-not-transaction-owned"}})
            else:
                services_clean = False
                records.append({"step": "dependent-service-cleanup-blocked", "ok": False,
                                "readback": {"unit": unit, "owned": False, "state": state,
                                             "rc": initial.get("rc"),
                                             "reason": initial.get("reason", "active-service-not-transaction-owned")}})
    elif info.get("servicesStarted"):
        services_clean = False
        records.append({"step": "dependent-service-cleanup-blocked", "ok": False,
                        "readback": {"reason": "service-ownership-without-attachment-attempt", "rc": None}})

    mount_absent = not mount_state.get("mounted") and not nested
    if attachment_attempted:
        running_states = {"active", "activating", "reloading", "refreshing", "deactivating"}
        stop_ready = services_clean and not mount_conflict
        mount_stop_clean = False
        open_stop_clean = False
        if not stop_ready:
            reason = "dependent-service-not-stopped" if not services_clean else "foreign-or-nested-mount"
            records.append({"step": "stop-mount-unit", "ok": False,
                            "readback": {"unit": mount_unit, "owned": mount_unit in owned_units,
                                         "rc": None, "reason": reason}})
            records.append({"step": "stop-open-unit", "ok": False,
                            "readback": {"unit": open_unit, "owned": open_unit in owned_units,
                                         "rc": None, "reason": "mount-unit-not-stopped"}})
        else:
            mount_initial = _rollback_systemctl_state(receipt, mount_unit, "rollback-mount-unit-state")
            mount_state_name = mount_initial.get("state")
            if mount_unit in owned_units and mount_state_name in running_states | {"failed"}:
                mount_stop_clean, _final = _rollback_stop_owned_unit(
                    records, receipt, mount_unit, "stop-mount-unit", mount_initial)
            elif mount_unit in owned_units and mount_state_name == "inactive":
                mount_stop_clean = True
                records.append({"step": "stop-mount-unit", "ok": True,
                                "readback": {"unit": mount_unit, "owned": True, "state": mount_state_name,
                                             "rc": mount_initial.get("rc"), "reason": "already-inactive"}})
            elif mount_unit not in owned_units and mount_state_name == "inactive" and mount_absent:
                mount_stop_clean = True
                records.append({"step": "stop-mount-unit", "ok": True,
                                "readback": {"unit": mount_unit, "owned": False, "state": mount_state_name,
                                             "rc": mount_initial.get("rc"), "reason": "inactive-and-unmounted"}})
            else:
                records.append({"step": "stop-mount-unit", "ok": False,
                                "readback": {"unit": mount_unit, "owned": mount_unit in owned_units,
                                             "state": mount_state_name, "rc": mount_initial.get("rc"),
                                             "reason": mount_initial.get("reason", "unit-not-transaction-owned")}})

            if mount_stop_clean:
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

            if mount_stop_clean:
                open_initial = _rollback_systemctl_state(receipt, open_unit, "rollback-open-unit-state")
                open_state_name = open_initial.get("state")
                if open_unit in owned_units and open_state_name in running_states | {"failed"}:
                    open_stop_clean, _final = _rollback_stop_owned_unit(
                        records, receipt, open_unit, "stop-open-unit", open_initial)
                elif open_unit in owned_units and open_state_name == "inactive":
                    open_stop_clean = True
                    records.append({"step": "stop-open-unit", "ok": True,
                                    "readback": {"unit": open_unit, "owned": True, "state": open_state_name,
                                                 "rc": open_initial.get("rc"), "reason": "already-inactive"}})
                elif open_unit not in owned_units and open_state_name == "inactive":
                    open_stop_clean = True
                    records.append({"step": "stop-open-unit", "ok": True,
                                    "readback": {"unit": open_unit, "owned": False, "state": open_state_name,
                                                 "rc": open_initial.get("rc"), "reason": "inactive-not-transaction-owned"}})
                else:
                    records.append({"step": "stop-open-unit", "ok": False,
                                    "readback": {"unit": open_unit, "owned": open_unit in owned_units,
                                                 "state": open_state_name, "rc": open_initial.get("rc"),
                                                 "reason": open_initial.get("reason", "unit-not-transaction-owned")}})
            else:
                records.append({"step": "stop-open-unit", "ok": False,
                                "readback": {"unit": open_unit, "owned": open_unit in owned_units,
                                             "rc": None, "reason": "mount-unit-not-stopped"}})
        units_clean = mount_stop_clean and open_stop_clean

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
                  "nas-units-not-stopped" if not units_clean else "dependent-services-not-stopped")
        records.append({"step": "mapper-close-blocked", "ok": False,
                        "readback": {"mountAbsent": mount_absent, "unitsClean": units_clean,
                                     "servicesClean": services_clean, "rc": None, "reason": reason}})
    elif has_disk_mutation:
        mapper_failure = None
        try:
            mapper_state = _mapper_state(receipt, info)
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
                after_close = _mapper_state(receipt, info)
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
            dependencies.append("nas-units-not-clean")
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
                    receipt, info, whole_disk_erasure_step=whole_disk_erasure_step)
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


def _merge_attach_receipt(receipt: dict[str, Any], info: dict[str, Any], attachment: Any) -> None:
    if not isinstance(attachment, dict):
        return
    before = attachment.get("unitStatesBefore")
    if isinstance(before, dict) and before:
        snapshot = {name: dict(value) for name, value in before.items()
                    if isinstance(name, str) and isinstance(value, dict)}
        info["unitStatesBefore"] = snapshot
        receipt["unitStatesBefore"] = {name: dict(value) for name, value in snapshot.items()}
    for field in ("mapperReadback", "mountReadback"):
        observation = attachment.get(field)
        if isinstance(observation, dict):
            info[field] = dict(observation)
    raw_units = attachment.get("unitsStarted")
    if isinstance(raw_units, list):
        started = list(info.get("unitsStarted", []))
        for unit in raw_units:
            if isinstance(unit, str) and unit not in started:
                started.append(unit)
        info["unitsStarted"] = started
    raw_services = attachment.get("servicesStarted")
    if isinstance(raw_services, list):
        started_services = list(info.get("servicesStarted", []))
        for unit in raw_services:
            if isinstance(unit, str) and unit not in started_services:
                started_services.append(unit)
        info["servicesStarted"] = started_services
    services = attachment.get("services")
    if isinstance(services, list):
        known_services = {item.get("unit") for item in info.get("services", [])
                          if isinstance(item, dict) and isinstance(item.get("unit"), str)}
        merged_services = list(info.get("services", []))
        for service in services:
            if (isinstance(service, dict) and isinstance(service.get("unit"), str)
                    and service["unit"] not in known_services):
                merged_services.append(dict(service))
                known_services.add(service["unit"])
        info["services"] = merged_services
    steps = attachment.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if isinstance(step, dict) and isinstance(step.get("step"), str):
                receipt["steps"].append(dict(step))


def _execute(receipt: dict[str, Any], request: dict[str, Any], info: dict[str, Any]) -> tuple[dict[str, Any] | None, bytearray]:
    key_identity = None
    material = bytearray()
    mutations = {"diskMutationAttempted": False, "mapperOpenAttempted": False, "mountAttempted": False}
    info["device"] = request["device"]
    info["unitsStarted"] = list(info.get("unitsStarted", []))
    info["servicesStarted"] = list(info.get("servicesStarted", []))
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
    mapper_state = _mapper_state(receipt, info)
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
    closed = not _mapper_state(receipt, info).get("exists")
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
    mutations["mapperOpenAttempted"] = True
    mutations["mountAttempted"] = True

    def after_mount_verified(attachment_receipt: dict[str, Any]) -> None:
        created_partition_identity = info.get("createdPartitionIdentity")
        partition_identity = None
        partition_identity_error = None
        if isinstance(created_partition_identity, str):
            try:
                partition_identity = _device_identity(info["partition"], "portal-layout-partition-guard")
            except Refusal as failure:
                partition_identity_error = failure.signal_name

        mapper_readback = attachment_receipt.get("mapperReadback")
        mount_readback = attachment_receipt.get("mountReadback")
        started_units = attachment_receipt.get("unitsStarted")
        partition_matches = (isinstance(created_partition_identity, str)
                             and partition_identity == created_partition_identity)
        mapper_matches = (isinstance(mapper_readback, dict)
                          and mapper_readback.get("exists") is True
                          and mapper_readback.get("backingMatches") is True
                          and mapper_readback.get("backingIdentity") == created_partition_identity
                          and mapper_readback.get("expectedBackingIdentity") == created_partition_identity)
        mount_matches = (isinstance(mount_readback, dict)
                         and mount_readback.get("mounted") is True
                         and mount_readback.get("sourceMatches") is True
                         and mount_readback.get("fstype") == "xfs")
        transaction_mount = (attachment_receipt.get("alreadyMounted") is False
                             and isinstance(started_units, list)
                             and info["mountUnit"] in started_units)
        okay = partition_matches and mapper_matches and mount_matches and transaction_mount
        if not isinstance(created_partition_identity, str):
            reason = "partition-identity-unavailable"
        elif not partition_matches:
            reason = partition_identity_error or "partition-identity-mismatch"
        elif not mapper_matches:
            reason = "mapper-backing-identity-mismatch"
        elif not mount_matches:
            reason = "mount-readback-mismatch"
        elif not transaction_mount:
            reason = "mount-not-transaction-owned"
        else:
            reason = "verified"
        _record(attachment_receipt, "portal-layout-attachment-guard", okay,
                reason=reason, createdPartitionIdentity=created_partition_identity,
                partitionIdentity=partition_identity,
                mapperBackingIdentity=(mapper_readback.get("backingIdentity")
                                       if isinstance(mapper_readback, dict) else None),
                mapperExpectedBackingIdentity=(mapper_readback.get("expectedBackingIdentity")
                                               if isinstance(mapper_readback, dict) else None),
                mapperBackingMatches=(mapper_readback.get("backingMatches")
                                      if isinstance(mapper_readback, dict) else None),
                mounted=(mount_readback.get("mounted") if isinstance(mount_readback, dict) else None),
                sourceMatches=(mount_readback.get("sourceMatches")
                               if isinstance(mount_readback, dict) else None),
                filesystem=(mount_readback.get("fstype") if isinstance(mount_readback, dict) else None),
                alreadyMounted=attachment_receipt.get("alreadyMounted"),
                mountUnitStarted=(info["mountUnit"] in started_units
                                  if isinstance(started_units, list) else False))
        if not okay:
            raise Refusal("agathodaimon-nas-portal-layout-attachment-guard-failed",
                          "portal-layout-attachment-guard", receipt=attachment_receipt)
        _apply_permissions(attachment_receipt, info)
        _seed_portal_layout(attachment_receipt, info)

    try:
        attachment = attach_role(request["role"], start_services=False,
                                 after_mount_verified=after_mount_verified)
    except Refusal as failure:
        _merge_attach_receipt(receipt, info, getattr(failure, "receipt", None))
        raise
    _merge_attach_receipt(receipt, info, attachment)
    started_units = attachment.get("unitsStarted")
    if (attachment.get("alreadyMounted") is not False or not isinstance(started_units, list)
            or info["mountUnit"] not in started_units):
        raise Refusal("agathodaimon-nas-attach-not-transaction-owned", "mount-start")
    mapper_readback = attachment.get("mapperReadback")
    mount_readback = attachment.get("mountReadback")
    if not isinstance(mapper_readback, dict):
        mapper_readback = {}
    if not isinstance(mount_readback, dict):
        mount_readback = {}
    mapper_ok = mapper_readback.get("exists") is True and mapper_readback.get("backingMatches") is True
    if not mapper_ok:
        _record(receipt, "cryptsetup-open", False, rc=None, unit=info["openUnit"],
                mapper=mapper, **mapper_readback)
        raise Refusal("agathodaimon-nas-mapper-open-failed", "cryptsetup-open")
    mount_ok = bool(mount_readback.get("mounted") and mount_readback.get("sourceMatches")
                    and mount_readback.get("fstype") == "xfs")
    if not mount_ok:
        _record(receipt, "mount-readback", False, rc=None, **mount_readback)
        raise Refusal("agathodaimon-nas-mount-readback-mismatch", "mount-readback")

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
            lock_fd = os.open(runtime_path(LOCK_PATH), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600)
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
    return attach_envelope(_perform(request), envelope_request)


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

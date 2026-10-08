"""Shared fixed-NAS runtime for the open, attach, and detach staff bands.

Production identity comes from the kernel, sysfs, cryptsetup, mountinfo,
and findmnt.  An explicitly selected AGATHODAIMON_SCRATCH_ROOT projects
those same coordinates into an isolated tree.  Scratch fixtures may provide
/dev/.agathodaimon-stat.json with ``devices`` and ``paths`` mappings from
logical absolute paths to ``major:minor`` identities; the stand-in at each
mapped path must still exist.  This metadata is never consulted live.
"""
from __future__ import annotations

import json
import os
import re
import signal
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, NoReturn, Sequence, cast

from agathodaimon.lib.keyman_export.index import (
    MISSING_KEY,
    KeymanExportError,
    export_key,
)

MAX_INPUT = 65536
SYSTEMCTL = "/usr/bin/systemctl"
CRYPTSETUP = "/usr/sbin/cryptsetup"
BLKID = "/usr/sbin/blkid"
FINDMNT = "/usr/bin/findmnt"
KEYMAN_EXPORTER = "/vault/keyman/keyman"
MOUNTINFO = "/proc/self/mountinfo"
SYS_DEV_BLOCK = "/sys/dev/block"
UNIT_DIR = "/etc/systemd/system"
STAT_FIXTURE = "/dev/.agathodaimon-stat.json"
MOUNT_ESCAPE = re.compile(r"\\([0-7]{3})")
_SAFE_STEP = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_SAFE_UNIT = re.compile(r"^[A-Za-z0-9_.@-]+\.(?:service|mount)$")
_IDENTITY = re.compile(r"^(0|[1-9][0-9]*):(0|[1-9][0-9]*)$")

ROLE: dict[str, dict[str, str]] = {
    "primary": {
        "key": "nas",
        "service": "nas",
        "partlabel": "homeserver-primary-nas",
        "mapper": "homeserver-primary-nas",
        "mountpoint": "/mnt/nas",
        "mount_unit": "mnt-nas.mount",
        "open_unit": "homeserver-nas-open@primary.service",
    },
    "backup": {
        "key": "nas_backup",
        "service": "nas_backup",
        "partlabel": "homeserver-backup-nas",
        "mapper": "homeserver-backup-nas",
        "mountpoint": "/mnt/nas_backup",
        "mount_unit": "mnt-nas_backup.mount",
        "open_unit": "homeserver-nas-open@backup.service",
    },
}


class Refusal(Exception):
    """Secret-free, stable refusal compatible with the NAS setup band."""

    def __init__(self, signal_name: str, step: str, return_code: int | None = None,
                 receipt: dict[str, Any] | None = None):
        super().__init__(signal_name)
        self.signal_name = signal_name
        self.step = step
        self.return_code = return_code
        self.receipt = receipt


def _scratch_root() -> Path | None:
    if "AGATHODAIMON_SCRATCH_ROOT" not in os.environ:
        return None
    raw = os.environ["AGATHODAIMON_SCRATCH_ROOT"]
    if (not raw or not os.path.isabs(raw) or "\x00" in raw
            or any(part in {".", ".."} for part in raw.split("/") if part)):
        raise Refusal("agathodaimon-nas-scratch-root-invalid", "scratch-root")
    try:
        root = Path(raw).resolve(strict=False)
    except (OSError, RuntimeError):
        raise Refusal("agathodaimon-nas-scratch-root-invalid", "scratch-root") from None
    if root == Path("/") or not root.is_absolute():
        raise Refusal("agathodaimon-nas-scratch-root-invalid", "scratch-root")
    try:
        metadata = os.stat(root)
    except FileNotFoundError:
        return root
    except OSError:
        raise Refusal("agathodaimon-nas-scratch-root-unreadable", "scratch-root") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise Refusal("agathodaimon-nas-scratch-root-invalid", "scratch-root")
    return root


def _assert_inside_scratch(path: Path, root: Path) -> None:
    """Reject any existing symlink traversal that leaves the declared root."""
    try:
        resolved = path.resolve(strict=False)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        raise Refusal("agathodaimon-nas-scratch-path-escape", "scratch-path") from None


def runtime_path(path: str | os.PathLike[str]) -> Path:
    """Map an absolute appliance path into scratch, rejecting escaping links."""
    text = os.fspath(path)
    if (not isinstance(text, str) or not text.startswith("/") or text.startswith("//")
            or "\x00" in text or os.path.normpath(text) != text
            or any(part in {".", ".."} for part in text.split("/") if part)):
        raise Refusal("agathodaimon-nas-runtime-path-invalid", "runtime-path")
    root = _scratch_root()
    if root is None:
        return Path(text)
    mapped = root.joinpath(*Path(text).parts[1:])
    _assert_inside_scratch(mapped, root)
    return mapped


def command_argv(argv: Sequence[str]) -> list[str]:
    """Resolve every invoked program through the scratch bin with no live fallback."""
    if not argv or not isinstance(argv[0], str) or not argv[0]:
        raise Refusal("agathodaimon-nas-command-invalid", "command")
    values = list(argv)
    root = _scratch_root()
    if root is None:
        return values
    basename = os.path.basename(values[0])
    if basename in {"", ".", ".."} or "/" in basename or "\x00" in basename:
        raise Refusal("agathodaimon-nas-command-invalid", "command")
    executable = runtime_path("/bin/" + basename)
    try:
        link_metadata = os.lstat(executable)
        metadata = os.stat(executable)
    except OSError:
        raise Refusal("agathodaimon-nas-command-unavailable", "command") from None
    if (stat.S_ISLNK(link_metadata.st_mode) or not stat.S_ISREG(metadata.st_mode)
            or not os.access(executable, os.X_OK)):
        raise Refusal("agathodaimon-nas-command-unavailable", "command")
    values[0] = str(executable)
    return values


def _safe_step(value: str) -> str:
    return value if _SAFE_STEP.fullmatch(value) else "unknown"


def _record(receipt: dict[str, Any], step: str, ok: bool, **readback: Any) -> None:
    receipt.setdefault("steps", []).append({
        "step": _safe_step(step), "ok": bool(ok), "readback": readback,
    })


def _fail(receipt: dict[str, Any], signal_name: str, step: str,
          return_code: int | None = None, **readback: Any) -> NoReturn:
    _record(receipt, step, False, **readback)
    raise Refusal(signal_name, step, return_code, receipt)


def _require_root(receipt: dict[str, Any], step: str = "root-preflight") -> None:
    uid = os.geteuid()
    if uid != 0:
        _fail(receipt, "agathodaimon-nas-root-required", step, uid=uid)
    _record(receipt, step, True, uid=0)


def _stop_process_group(process: subprocess.Popen[bytes]) -> bool:
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


def _run(argv: Sequence[str], *, input_data: bytes | bytearray | None = None, timeout: int = 60,
         step: str | None = None, suppress_output: bool = False) -> subprocess.CompletedProcess[bytes]:
    """Run through the declared command lane and keep child output internal."""
    command = command_argv(argv)
    command_step = _safe_step(step or os.path.basename(command[0]))
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if suppress_output else subprocess.PIPE,
            stderr=subprocess.DEVNULL if suppress_output else subprocess.PIPE,
            start_new_session=True,
        )
        stdout, stderr = process.communicate(input=cast(bytes | None, input_data), timeout=timeout)
        return subprocess.CompletedProcess(command, process.returncode, stdout or b"", stderr or b"")
    except subprocess.TimeoutExpired:
        if process is not None and not _stop_process_group(process):
            raise Refusal("agathodaimon-nas-command-group-unreaped", command_step,
                          process.returncode) from None
        raise Refusal("agathodaimon-nas-command-timeout", command_step,
                      process.returncode if process is not None else None) from None
    except OSError:
        if process is not None and not _stop_process_group(process):
            raise Refusal("agathodaimon-nas-command-group-unreaped", command_step,
                          process.returncode) from None
        raise Refusal("agathodaimon-nas-command-unavailable", command_step) from None


def _decode_output(result: subprocess.CompletedProcess[bytes], step: str) -> str:
    try:
        return result.stdout.decode("utf-8").strip()
    except UnicodeError:
        raise Refusal("agathodaimon-nas-readback-invalid", step, result.returncode) from None


def _role_info(role: str) -> dict[str, str]:
    if not isinstance(role, str) or role not in ROLE:
        raise Refusal("agathodaimon-nas-role-invalid", "request")
    return ROLE[role]


def _fixture_identity(path: str, section: str) -> str | None:
    """Read a projected identity only from explicit scratch fixture metadata."""
    root = _scratch_root()
    if root is None:
        return None
    fixture = runtime_path(STAT_FIXTURE)
    try:
        before = os.lstat(fixture)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise OSError("fixture-not-regular")
        fd = os.open(fixture, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_size > 65536:
                raise OSError("fixture-raced-or-large")
            chunks: list[bytes] = []
            remaining = 65537
            while remaining:
                chunk = os.read(fd, min(16384, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > 65536:
                raise OSError("fixture-large")
        finally:
            os.close(fd)
        data = json.loads(raw.decode("utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError):
        raise Refusal("agathodaimon-nas-scratch-stat-fixture-invalid", "scratch-stat-fixture") from None
    if not isinstance(data, dict):
        raise Refusal("agathodaimon-nas-scratch-stat-fixture-invalid", "scratch-stat-fixture")
    table = data.get(section)
    if not isinstance(table, dict) or path not in table:
        return None
    item = table[path]
    if isinstance(item, str):
        identity = item
    elif isinstance(item, dict):
        major, minor = item.get("major"), item.get("minor")
        if (isinstance(major, bool) or not isinstance(major, int) or major < 0
                or isinstance(minor, bool) or not isinstance(minor, int) or minor < 0):
            raise Refusal("agathodaimon-nas-scratch-stat-fixture-invalid", "scratch-stat-fixture")
        identity = f"{major}:{minor}"
    else:
        raise Refusal("agathodaimon-nas-scratch-stat-fixture-invalid", "scratch-stat-fixture")
    if not _IDENTITY.fullmatch(identity):
        raise Refusal("agathodaimon-nas-scratch-stat-fixture-invalid", "scratch-stat-fixture")
    return identity


def _stat_block(path: str, step: str) -> tuple[int, int, os.stat_result]:
    mapped = runtime_path(path)
    try:
        metadata = os.stat(mapped)
    except OSError:
        raise Refusal("agathodaimon-nas-device-unobservable", step) from None
    if stat.S_ISBLK(metadata.st_mode):
        return os.major(metadata.st_rdev), os.minor(metadata.st_rdev), metadata
    projected = _fixture_identity(path, "devices")
    if projected is None:
        raise Refusal("agathodaimon-nas-block-device-required", step)
    major, minor = (int(value) for value in projected.split(":"))
    return major, minor, metadata


def _device_identity(path: str, step: str) -> str:
    major, minor, _ = _stat_block(path, step)
    return f"{major}:{minor}"


def _stat_path_identity(path: str, step: str) -> str:
    mapped = runtime_path(path)
    try:
        metadata = os.stat(mapped, follow_symlinks=False)
    except OSError:
        raise Refusal("agathodaimon-nas-path-unobservable", step) from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise Refusal("agathodaimon-nas-mountpoint-not-directory", step)
    projected = _fixture_identity(path, "paths")
    if projected is not None:
        return projected
    return f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"


def _mountinfo() -> list[dict[str, str]]:
    try:
        raw = runtime_path(MOUNTINFO).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise Refusal("agathodaimon-nas-mount-census-unavailable", "mount-census") from None
    entries: list[dict[str, str]] = []
    for line in raw.splitlines():
        before, separator, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not separator or len(fields) < 6 or len(tail) < 2 or not re.fullmatch(r"\d+:\d+", fields[2]):
            raise Refusal("agathodaimon-nas-mount-census-invalid", "mount-census")
        unescape = lambda value: MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)
        entries.append({
            "dev": fields[2], "root": unescape(fields[3]), "target": unescape(fields[4]),
            "source": unescape(tail[1]), "fstype": tail[0],
        })
    if not entries:
        raise Refusal("agathodaimon-nas-mount-census-empty", "mount-census")
    return entries


def _mount_for_target(entries: list[dict[str, str]], target: str) -> dict[str, str] | None:
    found = [entry for entry in entries if entry.get("target") == target]
    if len(found) > 1:
        raise Refusal("agathodaimon-nas-mount-ambiguous", "mount-census")
    return found[0] if found else None


def _safe_resolve(path: Path, step: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise Refusal("agathodaimon-nas-block-graph-incomplete", step) from None
    root = _scratch_root()
    if root is not None:
        _assert_inside_scratch(resolved, root)
    return resolved


def _sysfs_dev(path: Path) -> str:
    root = _scratch_root()
    if root is not None:
        _assert_inside_scratch(path / "dev", root)
    try:
        value = (path / "dev").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph") from None
    if not _IDENTITY.fullmatch(value):
        raise Refusal("agathodaimon-nas-block-graph-invalid", "block-graph")
    return value


def _block_graph() -> tuple[dict[str, set[str]], dict[str, str]]:
    """Build the undirected partition/slave identity component graph."""
    root_path = runtime_path(SYS_DEV_BLOCK)
    try:
        names = sorted(os.listdir(root_path))
    except OSError:
        raise Refusal("agathodaimon-nas-block-graph-unavailable", "block-graph") from None
    if not names:
        raise Refusal("agathodaimon-nas-block-graph-empty", "block-graph")
    edges: dict[str, set[str]] = {}
    paths: dict[str, str] = {}
    for name in names:
        if not _IDENTITY.fullmatch(name):
            raise Refusal("agathodaimon-nas-block-graph-invalid", "block-graph")
        resolved = _safe_resolve(root_path / name, "block-graph")
        identity = _sysfs_dev(resolved)
        if identity != name:
            raise Refusal("agathodaimon-nas-block-graph-identity-mismatch", "block-graph")
        edges.setdefault(identity, set())
        paths[identity] = "/dev/" + resolved.name
        partition_file = resolved / "partition"
        root = _scratch_root()
        if root is not None:
            _assert_inside_scratch(partition_file, root)
        try:
            is_partition = partition_file.exists()
        except OSError:
            raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph") from None
        if is_partition:
            parent = _sysfs_dev(_safe_resolve(resolved.parent, "block-graph"))
            edges.setdefault(parent, set()).add(identity)
            edges[identity].add(parent)
        slaves = resolved / "slaves"
        try:
            if root is not None:
                _assert_inside_scratch(slaves, root)
            slave_names = sorted(os.listdir(slaves)) if slaves.is_dir() else []
        except OSError:
            raise Refusal("agathodaimon-nas-block-graph-incomplete", "block-graph") from None
        for slave_name in slave_names:
            if not slave_name or "/" in slave_name or slave_name in {".", ".."}:
                raise Refusal("agathodaimon-nas-block-graph-invalid", "block-graph")
            slave_resolved = _safe_resolve(slaves / slave_name, "block-graph")
            child = _sysfs_dev(slave_resolved)
            edges.setdefault(child, set()).add(identity)
            edges[identity].add(child)
    return edges, paths


def _component(edges: dict[str, set[str]], start: str) -> set[str]:
    if start not in edges:
        raise Refusal("agathodaimon-nas-block-identity-unobserved", "block-graph")
    seen, stack = {start}, [start]
    while stack:
        current = stack.pop()
        for other in edges.get(current, set()):
            if other not in seen:
                seen.add(other)
                stack.append(other)
    return seen


def _direct_slaves(identity: str) -> set[str]:
    root_path = runtime_path(SYS_DEV_BLOCK)
    device = _safe_resolve(root_path / identity, "mapper-backing-readback")
    slaves = device / "slaves"
    try:
        root = _scratch_root()
        if root is not None:
            _assert_inside_scratch(slaves, root)
        names = sorted(os.listdir(slaves))
    except OSError:
        raise Refusal("agathodaimon-nas-mapper-backing-unobservable", "mapper-backing-readback") from None
    result = set()
    for name in names:
        if not name or "/" in name or name in {".", ".."}:
            raise Refusal("agathodaimon-nas-block-graph-invalid", "mapper-backing-readback")
        result.add(_sysfs_dev(_safe_resolve(slaves / name, "mapper-backing-readback")))
    return result


def _list_holders(identity: str) -> list[str]:
    root_path = runtime_path(SYS_DEV_BLOCK)
    device = _safe_resolve(root_path / identity, "block-holders-readback")
    holders = device / "holders"
    try:
        root = _scratch_root()
        if root is not None:
            _assert_inside_scratch(holders, root)
        names = sorted(os.listdir(holders))
    except OSError:
        raise Refusal("agathodaimon-nas-block-holders-unreadable", "block-holders-readback") from None
    if any(not name or "/" in name or name in {".", ".."} for name in names):
        raise Refusal("agathodaimon-nas-block-holders-invalid", "block-holders-readback")
    return names


def _sysfs_block_name(identity: str) -> str:
    root_path = runtime_path(SYS_DEV_BLOCK)
    return _safe_resolve(root_path / identity, "block-holder-readback").name


def role_partition(role: str) -> str:
    """Resolve and verify the fixed role PARTLABEL, or refuse by name."""
    if os.geteuid() != 0:
        raise Refusal("agathodaimon-nas-root-required", "root-preflight")
    info = _role_info(role)
    label_path = f"/dev/disk/by-partlabel/{info['partlabel']}"
    try:
        os.lstat(runtime_path(label_path))
    except FileNotFoundError:
        raise Refusal("agathodaimon-nas-partlabel-absent", "partlabel-readback") from None
    except OSError:
        raise Refusal("agathodaimon-nas-partition-unavailable", "partlabel-readback") from None
    try:
        _device_identity(label_path, "partlabel-device-readback")
    except Refusal as failure:
        if failure.signal_name in {"agathodaimon-nas-block-device-required", "agathodaimon-nas-device-unobservable"}:
            raise Refusal("agathodaimon-nas-partition-unavailable", "partlabel-readback",
                          failure.return_code) from None
        raise
    try:
        result = _run([BLKID, "-s", "PARTLABEL", "-o", "value", "--", label_path],
                      step="partlabel-readback")
    except Refusal as failure:
        raise Refusal("agathodaimon-nas-partlabel-unobservable", "partlabel-readback",
                      failure.return_code) from None
    observed = _decode_output(result, "partlabel-readback") if result.returncode == 0 else ""
    if result.returncode != 0 or observed != info["partlabel"]:
        raise Refusal("agathodaimon-nas-partlabel-missing-or-mismatch", "partlabel-readback",
                      result.returncode)
    return label_path


def _unit_file_readback(receipt: dict[str, Any], unit: str, template_path: str) -> None:
    path = runtime_path(template_path)
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_uid != 0:
            _fail(receipt, "agathodaimon-nas-fixed-unit-file-invalid", "fixed-unit-file-readback",
                  unit=unit, exists=True, regular=stat.S_ISREG(before.st_mode), owner=before.st_uid)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0))
        try:
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                    or not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0):
                _fail(receipt, "agathodaimon-nas-fixed-unit-file-raced", "fixed-unit-file-readback",
                      unit=unit, exists=True)
        finally:
            os.close(fd)
    except FileNotFoundError:
        _fail(receipt, "agathodaimon-nas-fixed-unit-file-missing", "fixed-unit-file-readback",
              unit=unit, exists=False)
    except Refusal:
        raise
    except OSError:
        _fail(receipt, "agathodaimon-nas-fixed-unit-file-unreadable", "fixed-unit-file-readback",
              unit=unit, exists=None)
    _record(receipt, "fixed-unit-file-readback", True, unit=unit, exists=True, regular=True)


def _systemctl_load_state(receipt: dict[str, Any], unit: str) -> str:
    result = _run([SYSTEMCTL, "show", unit, "--property=LoadState", "--value"],
                  step="systemd-load-state")
    if result.returncode != 0:
        _fail(receipt, "agathodaimon-nas-unit-state-unreadable", "systemd-load-state",
              result.returncode, unit=unit)
    state = _decode_output(result, "systemd-load-state")
    _record(receipt, "systemd-load-state", state == "loaded", unit=unit, loadState=state,
            rc=result.returncode)
    if state != "loaded":
        raise Refusal("agathodaimon-nas-fixed-unit-not-loaded", "systemd-load-state",
                      result.returncode, receipt)
    return state


def _systemctl_state(receipt: dict[str, Any], action: str, unit: str,
                     allowed: set[int] = {0}) -> tuple[int, str]:
    if not _SAFE_UNIT.fullmatch(unit) or action not in {"is-active", "start", "stop"}:
        _fail(receipt, "agathodaimon-nas-systemd-request-invalid", "systemd-request", unit=unit)
    try:
        result = _run([SYSTEMCTL, action, unit], step="systemd-" + action,
                      timeout=180 if action in {"start", "stop"} else 30)
    except Refusal as failure:
        raise Refusal(failure.signal_name, failure.step, failure.return_code, receipt) from None
    state = result.stdout.decode("utf-8", "ignore").strip()[:64]
    safe_state = state if state in {"active", "inactive", "failed", "activating", "deactivating",
                                    "enabled", "disabled", "static", "masked"} else "other"
    _record(receipt, "systemd-" + action, result.returncode in allowed, unit=unit,
            state=safe_state, rc=result.returncode)
    if result.returncode not in allowed:
        raise Refusal("agathodaimon-nas-systemd-command-failed", "systemd-" + action,
                      result.returncode, receipt)
    return result.returncode, state


def require_fixed_units(role: str, receipt: dict[str, Any],
                        require_mount_inactive: bool = False) -> dict[str, dict[str, Any]]:
    """Require both fixed unit files and loaded manager units; return pre-state."""
    info = _role_info(role)
    _require_root(receipt)
    template = "homeserver-nas-open@.service"
    selected = {
        "opener": (info["open_unit"], f"{UNIT_DIR}/{template}"),
        "mount": (info["mount_unit"], f"{UNIT_DIR}/{info['mount_unit']}"),
    }
    snapshots: dict[str, dict[str, Any]] = {}
    for name, (unit, path) in selected.items():
        _unit_file_readback(receipt, unit, path)
        _systemctl_load_state(receipt, unit)
        try:
            rc, state = _systemctl_state(receipt, "is-active", unit, {0, 3})
        except Refusal as failure:
            raise
        if (rc == 0 and state != "active") or (rc == 3 and state != "inactive"):
            _fail(receipt, "agathodaimon-nas-unit-state-unreadable", "systemd-state-readback",
                  unit=unit, state=state[:64])
        snapshots[name] = {"unit": unit, "state": state, "active": state == "active", "rc": rc}
    receipt["unitStatesBefore"] = {name: dict(value) for name, value in snapshots.items()}
    if require_mount_inactive and snapshots["mount"]["active"]:
        _fail(receipt, "agathodaimon-nas-mount-unit-active", "fixed-unit-inactive-preflight",
              unit=snapshots["mount"]["unit"], active=True)
    return snapshots


def _parse_status_backing(output: bytes) -> str | None:
    try:
        text = output.decode("utf-8")
    except UnicodeError:
        return None
    values = re.findall(r"(?m)^\s*device:\s*(\S+)\s*$", text)
    return values[0] if len(values) == 1 else None


def _mapper_state(receipt: dict[str, Any], info: dict[str, Any]) -> dict[str, Any]:
    """Observe canonical mapper and prove its direct LUKS backing identity."""
    mapper = info.get("mapper")
    partition = info.get("partition")
    if not isinstance(mapper, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", mapper):
        _fail(receipt, "agathodaimon-nas-mapper-invalid", "mapper-readback")
    path = f"/dev/mapper/{mapper}"
    try:
        mapped_path = runtime_path(path)
        os.lstat(mapped_path)
    except FileNotFoundError:
        observed = {"exists": False, "backingMatches": False}
        _record(receipt, "mapper-readback", True, **observed)
        return observed
    except OSError:
        _fail(receipt, "agathodaimon-nas-mapper-readback-failed", "mapper-readback")
    try:
        os.stat(mapped_path)
    except OSError:
        _fail(receipt, "agathodaimon-nas-mapper-readback-failed", "mapper-readback",
              exists=True, observed="mapper-target-unreadable")
    try:
        mapper_identity = _device_identity(path, "mapper-readback")
    except Refusal as failure:
        _fail(receipt, "agathodaimon-nas-mapper-not-block", "mapper-readback",
              observed=failure.signal_name)
    try:
        result = _run([CRYPTSETUP, "status", mapper], step="mapper-readback")
    except Refusal as failure:
        raise Refusal("agathodaimon-nas-mapper-readback-failed", "mapper-readback",
                      failure.return_code, receipt) from None
    if result.returncode != 0:
        _fail(receipt, "agathodaimon-nas-mapper-readback-failed", "mapper-readback",
              result.returncode, exists=True, identity=mapper_identity)
    status_backing = _parse_status_backing(result.stdout)
    if not isinstance(partition, str):
        _fail(receipt, "agathodaimon-nas-mapper-backing-unobservable", "mapper-backing-readback",
              exists=True, identity=mapper_identity)
    try:
        expected_identity = _device_identity(partition, "mapper-backing-readback")
        status_identity = _device_identity(status_backing, "mapper-backing-readback") if status_backing else None
        direct_slaves = _direct_slaves(mapper_identity)
    except Refusal as failure:
        raise Refusal("agathodaimon-nas-mapper-backing-unobservable", "mapper-backing-readback",
                      failure.return_code, receipt) from None
    backing_matches = (status_identity == expected_identity and direct_slaves == {expected_identity})
    observed = {
        "exists": True, "block": True, "identity": mapper_identity,
        "statusRc": result.returncode, "backingMatches": backing_matches,
        "backingIdentity": status_identity, "expectedBackingIdentity": expected_identity,
        "directSlaveCount": len(direct_slaves),
    }
    _record(receipt, "mapper-readback", backing_matches, **observed)
    if not backing_matches:
        raise Refusal("agathodaimon-nas-mapper-backing-mismatch", "mapper-readback",
                      result.returncode, receipt)
    return observed


def _mount_readback(info: dict[str, Any]) -> dict[str, Any]:
    """Read back exact target, XFS type and mapper identity from independent views."""
    mountpoint = info["mountpoint"]
    entries = _mountinfo()
    matches = [entry for entry in entries if entry["target"] == mountpoint]
    try:
        findmnt = _run([FINDMNT, "--json", "--mountpoint", mountpoint,
                        "--output", "SOURCE,FSTYPE,MAJ:MIN,TARGET"],
                       step="findmnt-mount-readback")
    except Refusal as failure:
        return {"mounted": True, "sourceMatches": False,
                "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": failure.return_code, "reason": failure.signal_name}
    if findmnt.returncode == 1:
        if not findmnt.stdout.strip():
            if not matches:
                return {"mounted": False, "sourceMatches": False, "fstype": None,
                        "findmntRc": findmnt.returncode, "findmntAbsent": True}
            return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"],
                    "findmntRc": findmnt.returncode, "reason": "findmnt-command-failed"}
        try:
            absent = json.loads(findmnt.stdout.decode("utf-8"))["filesystems"]
            if not isinstance(absent, list):
                raise ValueError("filesystems")
        except (UnicodeError, json.JSONDecodeError, ValueError, KeyError, TypeError):
            return {"mounted": True, "sourceMatches": False,
                    "fstype": matches[0]["fstype"] if matches else None,
                    "findmntRc": findmnt.returncode, "reason": "findmnt-readback-invalid"}
        if not absent:
            if not matches:
                return {"mounted": False, "sourceMatches": False, "fstype": None,
                        "findmntRc": findmnt.returncode, "findmntAbsent": True}
            return {"mounted": True, "sourceMatches": False, "fstype": matches[0]["fstype"],
                    "findmntRc": findmnt.returncode, "reason": "mountinfo-findmnt-disagree"}
        return {"mounted": True, "sourceMatches": False,
                "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": findmnt.returncode, "reason": "findmnt-command-failed"}
    if findmnt.returncode != 0:
        return {"mounted": True, "sourceMatches": False,
                "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": findmnt.returncode, "reason": "findmnt-command-failed"}
    try:
        decoded = json.loads(findmnt.stdout.decode("utf-8"))
        filesystems = decoded["filesystems"]
        if not isinstance(filesystems, list):
            raise ValueError("filesystems")
        if not filesystems and not matches:
            return {"mounted": False, "sourceMatches": False, "fstype": None,
                    "findmntRc": findmnt.returncode, "findmntAbsent": True}
        if len(filesystems) != 1 or not isinstance(filesystems[0], dict):
            raise ValueError("findmnt-row-count")
        row = filesystems[0]
        source, fstype, findmnt_identity, target = (row[key] for key in ("source", "fstype", "maj:min", "target"))
        if not all(isinstance(value, str) for value in (source, fstype, findmnt_identity, target)):
            raise ValueError("findmnt-field-type")
        if not _IDENTITY.fullmatch(findmnt_identity):
            raise ValueError("findmnt-identity")
    except (UnicodeError, json.JSONDecodeError, ValueError, KeyError, TypeError):
        return {"mounted": True, "sourceMatches": False,
                "fstype": matches[0]["fstype"] if matches else None,
                "findmntRc": findmnt.returncode, "reason": "findmnt-readback-invalid"}
    if len(matches) != 1:
        return {"mounted": True, "sourceMatches": False, "fstype": fstype,
                "target": target, "findmntSource": source, "findmntIdentity": findmnt_identity,
                "findmntRc": findmnt.returncode, "reason": "mountinfo-findmnt-disagree"}
    try:
        mapper_identity = _device_identity(f"/dev/mapper/{info['mapper']}", "mount-readback")
        source_identity = _device_identity(source, "mount-readback")
        mount_source_identity = _device_identity(matches[0]["source"], "mount-readback")
        stat_identity = _stat_path_identity(mountpoint, "mount-readback")
    except Refusal as failure:
        return {"mounted": True, "sourceMatches": False, "fstype": fstype,
                "findmntSource": source, "findmntIdentity": findmnt_identity,
                "findmntRc": findmnt.returncode, "reason": failure.signal_name,
                "readbackRc": failure.return_code}
    identity_matches = (matches[0]["dev"] == mapper_identity == stat_identity
                        and source_identity == mapper_identity
                        and mount_source_identity == mapper_identity
                        and findmnt_identity == mapper_identity)
    target_matches = target == mountpoint and matches[0]["target"] == mountpoint
    filesystem_matches = fstype == "xfs" and matches[0]["fstype"] == "xfs"
    source_matches = identity_matches and target_matches and filesystem_matches
    return {
        "mounted": True, "sourceMatches": source_matches,
        "mountinfoIdentity": matches[0]["dev"], "statIdentity": stat_identity,
        "findmntIdentity": findmnt_identity, "findmntSource": source,
        "mountinfoSourceIdentity": mount_source_identity,
        "findmntRc": findmnt.returncode, "findmntMatches": source_matches,
        "fstype": fstype, "target": target, "mountinfoFstype": matches[0]["fstype"],
    }


def _vault_is_mounted(receipt: dict[str, Any]) -> None:
    entries = _mountinfo()
    entry = _mount_for_target(entries, "/vault")
    if entry is None:
        _fail(receipt, "agathodaimon-nas-vault-not-mounted", "vault-mount-preflight",
              mounted=False)
    _record(receipt, "vault-mount-preflight", True, mounted=True,
            filesystem=entry["fstype"])


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


def _read_regular_nofollow(path: str, maximum: int = 1024 * 1024) -> tuple[bytes, os.stat_result]:
    path = str(runtime_path(path))
    parts = Path(path).parts
    if not Path(path).is_absolute() or any(part in {".", ".."} for part in parts):
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


def _list_enabled_nas_services(receipt: dict[str, Any], mountpoint: str) -> list[dict[str, Any]]:
    """Census readable concrete NAS dependents, skipping unrelated unreadable rows."""
    result = _run([SYSTEMCTL, "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
                  step="service-census")
    if result.returncode != 0:
        _fail(receipt, "agathodaimon-nas-service-census-failed", "service-census",
              result.returncode)
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeError:
        _fail(receipt, "agathodaimon-nas-service-census-invalid", "service-census",
              observed="invalid")
    services: list[dict[str, Any]] = []
    skipped_units: list[str] = []
    for line in lines:
        fields = line.split()
        if len(fields) < 2 or not fields[0].endswith(".service"):
            continue
        unit, enabled_state = fields[0], fields[1]
        if (unit.endswith("@.service")
                or enabled_state in {"alias", "bad", "masked", "masked-runtime", "not-found"}):
            continue
        enabled = enabled_state in {"enabled", "enabled-runtime"}
        fragment: subprocess.CompletedProcess[bytes] | None = None
        fragment_failure: Refusal | None = None
        try:
            fragment = _run([SYSTEMCTL, "show", unit, "--property=FragmentPath", "--value"],
                            step="service-fragment-readback")
        except Refusal as failure:
            fragment_failure = failure
        cat: subprocess.CompletedProcess[bytes] | None = None
        cat_failure: Refusal | None = None
        try:
            cat = _run([SYSTEMCTL, "cat", unit, "--no-pager"], step="service-unit-readback")
        except Refusal as failure:
            cat_failure = failure
        failed: subprocess.CompletedProcess[bytes] | Refusal | None = None
        if cat is not None and cat.returncode != 0:
            failed = cat
        elif cat_failure is not None:
            failed = cat_failure
        elif fragment is not None and fragment.returncode != 0:
            failed = fragment
        elif fragment_failure is not None:
            failed = fragment_failure

        fragment_path: str | None = None
        fragment_path_unreadable = fragment is None
        if fragment is not None:
            try:
                candidate = fragment.stdout.decode("utf-8").strip()
                if candidate and candidate != "/dev/null":
                    fragment_path = candidate
                else:
                    fragment_path_unreadable = True
            except UnicodeError:
                fragment_path_unreadable = True

        text: str | None = None
        cat_unreadable = cat is None
        if cat is not None:
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
        if (text is None or cat_unreadable or (cat is not None and cat.returncode != 0)) and fragment_path is not None:
            try:
                raw, _metadata = _read_regular_nofollow(fragment_path, maximum=1024 * 1024)
            except (OSError, Refusal):
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
            if isinstance(failed, subprocess.CompletedProcess):
                failed_rc = failed.returncode
            elif isinstance(failed, Refusal):
                failed_rc = failed.return_code
            else:
                failed_rc = None
            if matches:
                _fail(receipt, "agathodaimon-nas-service-unit-unreadable", "service-condition-readback",
                      failed_rc, unit=unit, mountpoint=mountpoint, observed="nas-dependent")
            skipped_units.append(unit)
            _record(receipt, "service-unit-skipped", True, unit=unit, rc=failed_rc,
                    reason="unit-readback-failed" if failed is not None else "declaration-unreadable",
                    observed="unreadable")
            continue
        if not matches:
            continue
        try:
            active_result = _run([SYSTEMCTL, "is-active", unit], step="service-active-preflight")
        except Refusal as failure:
            raise Refusal(failure.signal_name, failure.step, failure.return_code, receipt) from None
        if active_result.returncode not in {0, 3}:
            _fail(receipt, "agathodaimon-nas-service-state-unreadable", "service-active-preflight",
                  active_result.returncode, unit=unit)
        if active_result.returncode == 0 and active_result.stdout.strip() == b"active":
            active = True
        elif active_result.returncode == 3 and active_result.stdout.strip() == b"inactive":
            active = False
        else:
            _fail(receipt, "agathodaimon-nas-service-state-unreadable", "service-active-preflight",
                  active_result.returncode,
                  unit=unit, state=active_result.stdout.decode("utf-8", "ignore").strip()[:64])
        services.append({
            "unit": unit,
            "enabled": enabled,
            "activeBefore": active,
            "condition": mountpoint,
            "fragment": fragment_path,
        })
    receipt["services"] = [dict(service) for service in services]
    receipt["excludedServices"] = []
    _record(receipt, "service-census", True, nasDependentCount=len(services),
            units=[service["unit"] for service in services],
            skippedUnits=skipped_units, skippedUnitCount=len(skipped_units))
    return services


def _service_active(unit: str) -> bool:
    if not _SAFE_UNIT.fullmatch(unit):
        raise Refusal("agathodaimon-nas-service-state-unreadable", "service-state-readback")
    result = _run([SYSTEMCTL, "is-active", unit], step="service-state-readback")
    if result.returncode == 0 and result.stdout.strip() == b"active":
        return True
    if result.returncode == 3 and result.stdout.strip() == b"inactive":
        return False
    raise Refusal("agathodaimon-nas-service-state-unreadable", "service-state-readback",
                  result.returncode)


def _start_nas_services(receipt: dict[str, Any], info: dict[str, Any]) -> None:
    started = info.setdefault("servicesStarted", [])
    for service in info.get("services", []):
        unit = service["unit"]
        active = _service_active(unit)
        if service["activeBefore"]:
            if not active:
                _fail(receipt, "agathodaimon-nas-preactive-service-stopped", "service-state-readback",
                      unit=unit)
            continue
        if active:
            _record(receipt, "service-start-readback", True, unit=unit, active=True,
                    enabled=service["enabled"], startAttempted=False)
            continue
        if not service["enabled"]:
            continue
        command = None
        command_failure: Refusal | None = None
        try:
            command = _run([SYSTEMCTL, "start", unit], step="service-start", timeout=180)
        except Refusal as failure:
            command_failure = failure
        try:
            after = _service_active(unit)
        except Refusal as failure:
            if command_failure is not None:
                raise Refusal(command_failure.signal_name, command_failure.step,
                              command_failure.return_code, receipt) from None
            raise Refusal(failure.signal_name, failure.step, failure.return_code, receipt) from None
        if after:
            if unit not in started:
                started.append(unit)
        if command is None:
            rc = command_failure.return_code if command_failure is not None else None
        else:
            rc = command.returncode
        okay = command is not None and rc == 0 and after
        _record(receipt, "service-start", okay, unit=unit, enabled=True, active=after, rc=rc)
        if not okay:
            raise Refusal("agathodaimon-nas-service-start-failed", "service-start", rc, receipt)


def _observe_nas_services(receipt: dict[str, Any], info: dict[str, Any], *,
                          track_started: bool = True) -> None:
    """Read dependent units, optionally owning only transitions from a start."""
    started = info.setdefault("servicesStarted", [])
    for service in info.get("services", []):
        unit = service["unit"]
        active = _service_active(unit)
        if service["activeBefore"] and not active:
            _fail(receipt, "agathodaimon-nas-preactive-service-stopped", "service-state-readback",
                  unit=unit)
        if track_started and not service["activeBefore"] and active and unit not in started:
            started.append(unit)
        _record(receipt, "service-state-readback", True, unit=unit, active=active,
                enabled=service["enabled"], activeBefore=service["activeBefore"],
                startAttempted=track_started)


def _snapshot_after_start(receipt: dict[str, Any], info: dict[str, str],
                          before: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    after: dict[str, dict[str, Any]] = {}
    unreadable: list[Refusal] = []
    for name, unit in (("opener", info["open_unit"]), ("mount", info["mount_unit"])):
        try:
            rc, state = _systemctl_state(receipt, "is-active", unit, {0, 3})
        except Refusal as failure:
            unreadable.append(failure)
            after[name] = {"unit": unit, "state": "unknown", "active": None,
                           "rc": failure.return_code}
            continue
        valid = (rc == 0 and state == "active") or (rc == 3 and state == "inactive")
        if not valid:
            _record(receipt, "systemd-state-readback", False, unit=unit,
                    state=state[:64], rc=rc)
            unreadable.append(Refusal("agathodaimon-nas-unit-state-unreadable",
                                      "systemd-state-readback", rc, receipt))
            after[name] = {"unit": unit, "state": state[:64], "active": None, "rc": rc}
            continue
        after[name] = {"unit": unit, "state": state, "active": state == "active", "rc": rc}
        if not before[name]["active"] and state == "active":
            if unit not in receipt["unitsStarted"]:
                receipt["unitsStarted"].append(unit)
    receipt["unitStatesAfter"] = {name: dict(value) for name, value in after.items()}
    if unreadable:
        first = unreadable[0]
        raise Refusal(first.signal_name, first.step, first.return_code, receipt)
    return after


def _attach_failure(receipt: dict[str, Any], failure: Refusal) -> Refusal:
    if not receipt.get("steps") or receipt["steps"][-1].get("step") != failure.step:
        _record(receipt, failure.step, False, rc=failure.return_code)
    receipt["ok"] = False
    receipt["firstMissingSignal"] = failure.signal_name
    receipt["failedStep"] = _safe_step(failure.step)
    if failure.return_code is not None:
        receipt["returnCode"] = failure.return_code
    failure.receipt = receipt
    return failure


def _receipt(schema: str, role: str | None) -> dict[str, Any]:
    return {
        "schema": schema, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete",
        "role": role, "partlabel": None, "partition": None, "mapper": None,
        "mountpoint": None, "steps": [], "unitsStarted": [], "unitStatesBefore": {},
        "services": [], "servicesStarted": [], "mapperReadback": None, "mountReadback": None,
        "alreadyOpen": False, "alreadyMounted": False, "servicesStopped": [], "unitsStopped": [],
    }


def _info_for(role: str, partition: str) -> dict[str, str]:
    info = dict(_role_info(role))
    info["partition"] = partition
    return info


def _observe_mount_and_mapper(receipt: dict[str, Any], info: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    mapper = _mapper_state(receipt, info)
    mount = _mount_readback(info)
    receipt["mapperReadback"] = dict(mapper)
    receipt["mountReadback"] = dict(mount)
    _record(receipt, "mount-readback", bool(mount.get("mounted") and mount.get("sourceMatches")
            and mount.get("fstype") == "xfs"), **mount)
    return mapper, mount


def attach_role(role: str, *, start_services: bool = True,
                after_mount_verified: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Attach one fixed role; a correct existing mount is a strict no-op."""
    receipt = _receipt("caduceus.nas.attach.v1", role if isinstance(role, str) else None)
    try:
        _require_root(receipt)
        info = _role_info(role)
        receipt.update(partlabel=info["partlabel"], mapper=info["mapper"], mountpoint=info["mountpoint"])
        _vault_is_mounted(receipt)
        partition = role_partition(role)
        receipt["partition"] = partition
        runtime_info = _info_for(role, partition)
        before = require_fixed_units(role, receipt)
        receipt["unitStatesBefore"] = {name: dict(value) for name, value in before.items()}

        current_mount = _mount_for_target(_mountinfo(), info["mountpoint"])
        nested_mounts = [entry["target"] for entry in _mountinfo()
                         if entry["target"].startswith(info["mountpoint"].rstrip("/") + "/")]
        if nested_mounts:
            _fail(receipt, "agathodaimon-nas-mountpoint-busy", "mount-preflight",
                  nestedMounts=nested_mounts)
        if current_mount is not None:
            mapper, mount = _observe_mount_and_mapper(receipt, runtime_info)
            if (mapper.get("exists") is not True or mapper.get("backingMatches") is not True
                    or mount.get("mounted") is not True or mount.get("sourceMatches") is not True
                    or mount.get("fstype") != "xfs"):
                raise Refusal("agathodaimon-nas-mounted-state-mismatch", "mount-readback", receipt=receipt)
            services = _list_enabled_nas_services(receipt, info["mountpoint"])
            receipt["services"] = [dict(service) for service in services]
            receipt["servicesStarted"] = []
            runtime_info = {**runtime_info, "services": services, "servicesStarted": receipt["servicesStarted"]}
            _observe_nas_services(receipt, runtime_info, track_started=False)
            receipt["alreadyMounted"] = True
            receipt["ok"] = True
            receipt["firstMissingSignal"] = "none"
            _record(receipt, "attach-noop", True, alreadyMounted=True,
                    startStopAttempted=False, mapperMatches=True, xfs=True)
            return receipt
        if before["mount"]["active"]:
            raise Refusal("agathodaimon-nas-mount-unit-active-without-mount", "mount-preflight",
                          receipt=receipt)

        target_identity = _device_identity(partition, "partition-readback")
        runtime_info = _info_for(role, partition)
        mapper_before = _mapper_state(receipt, runtime_info)
        expected_holders = {_sysfs_block_name(mapper_before["identity"])} if mapper_before.get("exists") else set()
        holders = _list_holders(target_identity)
        foreign_holders = [name for name in holders if name not in expected_holders]
        if foreign_holders:
            _fail(receipt, "agathodaimon-nas-partition-held-by-foreign-device", "partition-holder-preflight",
                  partitionIdentity=target_identity, holders=foreign_holders)
        services = _list_enabled_nas_services(receipt, info["mountpoint"])
        receipt["unitsStarted"] = []
        receipt["servicesStarted"] = []
        runtime_info = {**runtime_info, "services": services, "servicesStarted": receipt["servicesStarted"]}

        if mapper_before.get("exists"):
            receipt["mapperReadback"] = dict(mapper_before)

        try:
            start_result = _run([SYSTEMCTL, "start", info["mount_unit"]],
                                step="mount-start", timeout=180)
            start_rc = start_result.returncode
        except Refusal as failure:
            start_rc = failure.return_code
            start_failure = failure
        else:
            start_failure = None
        after = _snapshot_after_start(receipt, info, before)
        _record(receipt, "mount-start", start_failure is None and start_rc == 0,
                unit=info["mount_unit"], rc=start_rc,
                openerActive=after["opener"]["active"], mountActive=after["mount"]["active"])
        if start_failure is not None:
            raise Refusal(start_failure.signal_name, "mount-start", start_failure.return_code, receipt)
        if start_rc != 0:
            raise Refusal("agathodaimon-nas-mount-start-failed", "mount-start", start_rc, receipt)
        mapper, mount = _observe_mount_and_mapper(receipt, runtime_info)
        if (mapper.get("exists") is not True or mapper.get("backingMatches") is not True
                or mount.get("mounted") is not True or mount.get("sourceMatches") is not True
                or mount.get("fstype") != "xfs"):
            raise Refusal("agathodaimon-nas-mount-readback-mismatch", "mount-readback", receipt=receipt)
        receipt["alreadyMounted"] = False
        if after_mount_verified is not None:
            after_mount_verified(receipt)
        if start_services:
            _start_nas_services(receipt, runtime_info)
        else:
            _observe_nas_services(receipt, runtime_info)
        receipt["servicesStarted"] = list(runtime_info.get("servicesStarted", []))
        receipt["ok"] = True
        receipt["firstMissingSignal"] = "none"
        _record(receipt, "attach-complete", True, servicesStarted=list(receipt["servicesStarted"]),
                unitsStarted=list(receipt["unitsStarted"]))
        return receipt
    except Refusal as failure:
        raise _attach_failure(receipt, failure) from None
    except Exception:
        failure = Refusal("agathodaimon-nas-attach-aborted", "attach")
        raise _attach_failure(receipt, failure) from None


def _export_for_role(role: str, scratch: Path | None) -> bytearray:
    key_name = ROLE[role]["key"]
    exporter = (None if scratch is None else
                str(runtime_path("/bin/" + os.path.basename(KEYMAN_EXPORTER))))
    try:
        if exporter is None:
            return export_key(key_name)
        return export_key(key_name, scratch_root=str(scratch), exporter=exporter)
    except KeymanExportError as failure:
        if role != "backup" or failure.signal != MISSING_KEY:
            raise
        if exporter is None:
            return export_key("nas")
        return export_key("nas", scratch_root=str(scratch), exporter=exporter)


def open_role(role: str) -> dict[str, Any]:
    """Open only the canonical mapper; never attach, mount, or start dependents."""
    receipt = _receipt("caduceus.nas.open.v1", role if isinstance(role, str) else None)
    material: bytearray | None = None
    try:
        _require_root(receipt)
        info = _role_info(role)
        receipt.update(partlabel=info["partlabel"], mapper=info["mapper"])
        _vault_is_mounted(receipt)
        partition = role_partition(role)
        receipt["partition"] = partition
        runtime_info = _info_for(role, partition)
        partition_identity = _device_identity(partition, "partition-readback")
        result = _run([CRYPTSETUP, "isLuks", "--", partition],
                      step="luks-readback", suppress_output=True)
        if result.returncode != 0:
            _fail(receipt, "agathodaimon-nas-luks-required", "luks-readback", result.returncode,
                  isLuks=False)
        _record(receipt, "luks-readback", True, isLuks=True)
        try:
            current = _mapper_state(receipt, runtime_info)
        except Refusal:
            for observation in reversed(receipt.get("steps", [])):
                if isinstance(observation, dict) and observation.get("step") == "mapper-readback":
                    readback = observation.get("readback")
                    if isinstance(readback, dict):
                        receipt["mapperReadback"] = dict(readback)
                    break
            raise
        if current.get("exists") is True:
            receipt["mapperReadback"] = dict(current)
            if current.get("backingMatches") is not True:
                raise Refusal("agathodaimon-nas-mapper-backing-mismatch", "mapper-readback",
                              receipt=receipt)
        expected_holders = {_sysfs_block_name(current["identity"])} if current.get("exists") else set()
        holders = _list_holders(partition_identity)
        foreign_holders = [name for name in holders if name not in expected_holders]
        if foreign_holders:
            _fail(receipt, "agathodaimon-nas-partition-held-by-foreign-device", "partition-holder-preflight",
                  partitionIdentity=partition_identity, holders=foreign_holders)
        if current.get("exists") is True:
            receipt["alreadyOpen"] = True
            receipt["ok"] = True
            receipt["firstMissingSignal"] = "none"
            _record(receipt, "open-noop", True, **current, alreadyOpen=True,
                    mountAttempted=False, servicesAttempted=False)
            return receipt

        scratch = _scratch_root()
        try:
            material = _export_for_role(role, scratch)
        except KeymanExportError as failure:
            signal_name = ("agathodaimon-nas-key-export-missing"
                           if failure.signal == MISSING_KEY
                           else "agathodaimon-nas-key-export-failed")
            _fail(receipt, signal_name, "key-export", failure.return_code,
                  observed=failure.signal)
        _record(receipt, "key-export", True, present=True, bytes=len(material))
        command = _run([CRYPTSETUP, "open", "--key-file", "-", "--", partition, info["mapper"]],
                       input_data=material, timeout=120, step="cryptsetup-open",
                       suppress_output=True)
        mapper_state = _mapper_state(receipt, runtime_info)
        receipt["mapperReadback"] = dict(mapper_state)
        _record(receipt, "cryptsetup-open", command.returncode == 0
                and mapper_state.get("exists") is True and mapper_state.get("backingMatches") is True,
                rc=command.returncode, mapper=info["mapper"], **mapper_state)
        if (command.returncode != 0 or mapper_state.get("exists") is not True
                or mapper_state.get("backingMatches") is not True):
            raise Refusal("agathodaimon-nas-mapper-open-failed", "cryptsetup-open",
                          command.returncode, receipt)
        receipt["alreadyOpen"] = False
        receipt["ok"] = True
        receipt["firstMissingSignal"] = "none"
        return receipt
    except Refusal as failure:
        raise _attach_failure(receipt, failure) from None
    except Exception:
        failure = Refusal("agathodaimon-nas-open-aborted", "open")
        raise _attach_failure(receipt, failure) from None
    finally:
        if material is not None:
            for index in range(len(material)):
                material[index] = 0


def _stop_service(receipt: dict[str, Any], unit: str) -> None:
    try:
        active = _service_active(unit)
    except Refusal as failure:
        raise Refusal(failure.signal_name, failure.step, failure.return_code, receipt) from None
    if not active:
        return
    try:
        result = _run([SYSTEMCTL, "stop", unit], step="service-stop", timeout=180)
    except Refusal as failure:
        raise Refusal(failure.signal_name, "service-stop", failure.return_code, receipt) from None
    try:
        after = _service_active(unit)
    except Refusal as failure:
        raise Refusal(failure.signal_name, failure.step, failure.return_code, receipt) from None
    okay = result.returncode == 0 and not after
    _record(receipt, "service-stop", okay, unit=unit, rc=result.returncode, inactive=not after)
    if not okay:
        signal_name = "agathodaimon-nas-service-stop-failed"
        if result.returncode != 0 and after:
            signal_name = "agathodaimon-nas-service-stop-busy"
        raise Refusal(signal_name, "service-stop", result.returncode, receipt)
    if unit not in receipt["servicesStopped"]:
        receipt["servicesStopped"].append(unit)


def _stop_fixed_unit(receipt: dict[str, Any], unit: str, step: str,
                     *, attempt_if_inactive: bool = False) -> None:
    rc, state = _systemctl_state(receipt, "is-active", unit, {0, 3})
    if (rc == 0 and state != "active") or (rc == 3 and state != "inactive"):
        _fail(receipt, "agathodaimon-nas-unit-state-unreadable", step + "-preflight", unit=unit)
    was_active = state == "active"
    if not was_active and not attempt_if_inactive:
        return
    try:
        result = _run([SYSTEMCTL, "stop", unit], step=step, timeout=180)
    except Refusal as failure:
        raise Refusal(failure.signal_name, step, failure.return_code, receipt) from None
    rc_after, after = _systemctl_state(receipt, "is-active", unit, {0, 3})
    inactive = rc_after == 3 and after == "inactive"
    okay = result.returncode == 0 and inactive
    _record(receipt, step, okay, unit=unit, rc=result.returncode,
            stateAfter=after[:64], inactive=inactive)
    if not okay:
        raise Refusal("agathodaimon-nas-systemd-stop-failed", step,
                      result.returncode, receipt)
    if was_active and unit not in receipt["unitsStopped"]:
        receipt["unitsStopped"].append(unit)


def detach_role(role: str) -> dict[str, Any]:
    """Stop dependent services, then mount and opener; never force a busy close."""
    receipt = _receipt("caduceus.nas.detach.v1", role if isinstance(role, str) else None)
    receipt["servicesStopped"] = []
    receipt["unitsStopped"] = []
    try:
        _require_root(receipt)
        info = _role_info(role)
        receipt.update(partlabel=info["partlabel"], mapper=info["mapper"], mountpoint=info["mountpoint"])
        before = require_fixed_units(role, receipt)
        receipt["unitStatesBefore"] = {name: dict(value) for name, value in before.items()}

        # If a mapper exists, establish that it is the role's partition before stopping it.
        mapper_path = runtime_path(f"/dev/mapper/{info['mapper']}")
        try:
            os.lstat(mapper_path)
            mapper_exists = True
        except FileNotFoundError:
            mapper_exists = False
        except OSError:
            _fail(receipt, "agathodaimon-nas-mapper-readback-failed", "mapper-readback")
        partition: str | None = None
        runtime_info: dict[str, str] = dict(info)
        if mapper_exists:
            partition = role_partition(role)
            receipt["partition"] = partition
            runtime_info["partition"] = partition
            mapper_state = _mapper_state(receipt, runtime_info)
            receipt["mapperReadback"] = dict(mapper_state)
            receipt["mapperReadbackBefore"] = dict(mapper_state)
        else:
            receipt["mapperReadback"] = {"exists": False, "backingMatches": False}

        current_mount = _mount_for_target(_mountinfo(), info["mountpoint"])
        mount = _mount_readback(runtime_info)
        receipt["mountReadback"] = dict(mount)
        if current_mount is not None:
            receipt["mountReadbackBefore"] = dict(mount)
            if (not mount.get("mounted") or not mount.get("sourceMatches")
                    or mount.get("fstype") != "xfs"):
                _fail(receipt, "agathodaimon-nas-mounted-state-mismatch", "mount-preflight",
                      mounted=True, sourceMatches=mount.get("sourceMatches"),
                      filesystem=mount.get("fstype"))
        elif mount.get("mounted") is not False or mount.get("findmntAbsent") is not True:
            _fail(receipt, "agathodaimon-nas-mounted-state-mismatch", "mount-preflight",
                  mounted=mount.get("mounted"), findmntAbsent=mount.get("findmntAbsent"))
        services = _list_enabled_nas_services(receipt, info["mountpoint"])
        receipt["services"] = [dict(service) for service in services]
        for service in services:
            _stop_service(receipt, service["unit"])

        try:
            _stop_fixed_unit(receipt, info["mount_unit"], "mount-stop",
                             attempt_if_inactive=current_mount is not None)
        except Refusal as failure:
            observed_mount = _mount_for_target(_mountinfo(), info["mountpoint"])
            nested = [entry["target"] for entry in _mountinfo()
                      if entry["target"].startswith(info["mountpoint"].rstrip("/") + "/")]
            if observed_mount is not None or nested:
                _record(receipt, "mount-busy-readback", False,
                        mounted=observed_mount is not None, nestedMounts=nested)
                raise Refusal("agathodaimon-nas-mount-busy", "mount-stop",
                              failure.return_code, receipt) from None
            raise
        after_mount = _mount_for_target(_mountinfo(), info["mountpoint"])
        nested = [entry["target"] for entry in _mountinfo()
                  if entry["target"].startswith(info["mountpoint"].rstrip("/") + "/")]
        final_mount = _mount_readback(runtime_info)
        receipt["mountReadback"] = dict(final_mount)
        if (after_mount is not None or nested or final_mount.get("mounted") is not False
                or final_mount.get("findmntAbsent") is not True):
            _fail(receipt, "agathodaimon-nas-mount-busy", "mount-absent-readback",
                  mounted=after_mount is not None or final_mount.get("mounted") is True,
                  nestedMounts=nested, findmntAbsent=final_mount.get("findmntAbsent"))
        _record(receipt, "mount-absent-readback", True, mounted=False, nestedMountCount=0,
                findmntAbsent=True)

        try:
            _stop_fixed_unit(receipt, info["open_unit"], "opener-stop",
                             attempt_if_inactive=mapper_exists)
        except Refusal as failure:
            try:
                os.lstat(runtime_path(f"/dev/mapper/{info['mapper']}"))
            except FileNotFoundError:
                still_open = False
            except OSError:
                still_open = None
            else:
                still_open = True
            if still_open is True:
                _record(receipt, "mapper-busy-readback", False,
                        mapper=info["mapper"], absent=False)
                raise Refusal("agathodaimon-nas-mapper-busy", "opener-stop",
                              failure.return_code, receipt) from None
            if still_open is None:
                raise Refusal("agathodaimon-nas-mapper-readback-failed", "mapper-absent-readback",
                              failure.return_code, receipt) from None
            raise
        try:
            os.lstat(runtime_path(f"/dev/mapper/{info['mapper']}"))
        except FileNotFoundError:
            mapper_absent = True
        except OSError:
            _fail(receipt, "agathodaimon-nas-mapper-readback-failed", "mapper-absent-readback")
        else:
            mapper_absent = False
        _record(receipt, "mapper-absent-readback", mapper_absent,
                mapper=info["mapper"], absent=mapper_absent)
        if not mapper_absent:
            raise Refusal("agathodaimon-nas-mapper-busy", "mapper-absent-readback", receipt=receipt)
        receipt["mapperReadback"] = {"exists": False, "backingMatches": False}
        receipt["ok"] = True
        receipt["firstMissingSignal"] = "none"
        _record(receipt, "detach-complete", True,
                servicesStopped=list(receipt["servicesStopped"]),
                unitsStopped=list(receipt["unitsStopped"]))
        return receipt
    except Refusal as failure:
        raise _attach_failure(receipt, failure) from None
    except Exception:
        failure = Refusal("agathodaimon-nas-detach-aborted", "detach")
        raise _attach_failure(receipt, failure) from None

"""Bounded direct-file Unbound local A-record actuator; no daemon control."""
from __future__ import annotations

import argparse
import errno
import fcntl
import glob
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from agathodaimon import _load_trace
from agathodaimon.reload.index import reload_services

SCHEMA = "caduceus.network.dns.receipt.v2"
DEFAULT_CONFIG = Path("/etc/unbound/unbound.conf")
CHECKCONF = Path("/usr/sbin/unbound-checkconf")
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_INPUT_BYTES = 8192
MAX_NAME_BYTES = 253
MAX_LABEL_BYTES = 63
_RECORD = re.compile(rb'^(?P<prefix>[ \t]*local-data:[ \t]*)"(?P<body>[^"\r\n]+)"(?P<suffix>[ \t]*(?:#.*)?)$')
_LOCAL_ZONE = re.compile(rb'^(?P<prefix>[ \t]*)local-zone:[ \t]*')
_TOP_LEVEL = re.compile(rb'^[A-Za-z][A-Za-z0-9-]*:[ \t]*(?:#.*)?$')


class DnsRefused(ValueError):
    pass


@dataclass(frozen=True)
class FileSnapshot:
    identity: tuple[int, int]
    posture: tuple[int, int, int, int]
    digest: str
    xattrs: tuple[tuple[str, bytes], ...]


class InstalledFailure(DnsRefused):
    def __init__(self, error: str, snapshot: FileSnapshot):
        super().__init__(error)
        self.snapshot = snapshot


def _receipt(action: str, *, ok: bool, changed: bool, name: str | None = None,
             address: str | None = None, error: str = "none", **extra: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": ok, "action": action, "changed": changed,
            "record": ({"name": name, **({"address": address} if address else {})} if name else None),
            "serviceAction": "not-owned", "error": error, **extra}


def normalize_name(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8", "ignore")) > MAX_NAME_BYTES:
        raise DnsRefused("dns-name-invalid")
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or any(char in value for char in '\"\\/;:*'):
        raise DnsRefused("dns-name-invalid")
    name = value.lower().rstrip(".")
    if name != "home.arpa" and not name.endswith(".home.arpa"):
        raise DnsRefused("dns-name-outside-home-arpa")
    labels = name.split(".")
    if any(not label or len(label.encode("ascii", "ignore")) > MAX_LABEL_BYTES or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise DnsRefused("dns-name-invalid")
    return name + "."


def admit_private_ipv4(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 15:
        raise DnsRefused("dns-address-invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DnsRefused("dns-address-invalid") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private or address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or int(address) == 0xffffffff:
        raise DnsRefused("dns-address-not-admitted")
    return str(address)


def _stat_identity(st: os.stat_result) -> tuple[int, int]:
    return st.st_dev, st.st_ino


def _stat_posture(st: os.stat_result) -> tuple[int, int, int, int]:
    return st.st_mode, st.st_uid, st.st_gid, st.st_size


def _open_locked_parent(path: Path) -> int:
    try:
        before = os.lstat(path.parent)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise DnsRefused("dns-config-parent-refused")
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except DnsRefused:
        raise
    except OSError as exc:
        raise DnsRefused("dns-config-parent-open-refused") from exc
    try:
        after = os.fstat(fd)
        if not stat.S_ISDIR(after.st_mode) or _stat_identity(before) != _stat_identity(after):
            raise DnsRefused("dns-config-parent-identity-refused")
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_config(path: Path) -> tuple[bytes, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise DnsRefused("dns-config-open-refused") from exc
    try:
        file_stat, path_stat = os.fstat(fd), os.lstat(path)
        if not stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode) or _stat_identity(file_stat) != _stat_identity(path_stat):
            raise DnsRefused("dns-config-identity-refused")
        if file_stat.st_size > MAX_CONFIG_BYTES:
            raise DnsRefused("dns-config-too-large")
        parts: list[bytes] = []
        total = 0
        while True:
            part = os.read(fd, 65536)
            if not part:
                break
            total += len(part)
            if total > MAX_CONFIG_BYTES:
                raise DnsRefused("dns-config-too-large")
            parts.append(part)
        return b"".join(parts), file_stat
    finally:
        os.close(fd)


def _capture_xattrs(path: Path) -> tuple[tuple[str, bytes], ...]:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return ()
        raise DnsRefused("dns-config-metadata-capture-failed") from exc
    try:
        return tuple(sorted((name, os.getxattr(path, name, follow_symlinks=False)) for name in names))
    except OSError as exc:
        raise DnsRefused("dns-config-metadata-capture-failed") from exc


def _snapshot(path: Path) -> tuple[bytes, os.stat_result, FileSnapshot]:
    data, metadata = _read_config(path)
    xattrs = _capture_xattrs(path)
    try:
        final = os.lstat(path)
    except OSError as exc:
        raise DnsRefused("dns-config-snapshot-failed") from exc
    if not stat.S_ISREG(final.st_mode) or stat.S_ISLNK(final.st_mode) or _stat_identity(metadata) != _stat_identity(final):
        raise DnsRefused("dns-config-snapshot-failed")
    return data, final, FileSnapshot(
        identity=_stat_identity(final),
        posture=_stat_posture(final),
        digest=hashlib.sha256(data).hexdigest(),
        xattrs=xattrs,
    )


def _snapshot_is_current(path: Path, expected: FileSnapshot) -> bool:
    """Strict CAS proof used before replacing a currently installed file."""
    try:
        _data, _metadata, observed = _snapshot(path)
    except (DnsRefused, OSError):
        return False
    return observed == expected


def _snapshot_semantics_are_current(path: Path, expected: FileSnapshot) -> bool:
    """Prove restored pathname content and posture without requiring inode reuse."""
    try:
        _data, _metadata, observed = _snapshot(path)
    except (DnsRefused, OSError):
        return False
    return (
        observed.posture == expected.posture
        and observed.digest == expected.digest
        and observed.xattrs == expected.xattrs
    )


def _apply_metadata(fd: int, metadata: os.stat_result, xattrs: tuple[tuple[str, bytes], ...]) -> None:
    try:
        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
        os.fchown(fd, metadata.st_uid, metadata.st_gid)
        for name, value in xattrs:
            os.setxattr(fd, name, value)
    except OSError as exc:
        raise DnsRefused("dns-config-metadata-apply-failed") from exc


def _newline_style(data: bytes) -> bytes:
    has_crlf = b"\r\n" in data
    if has_crlf and b"\n" in data.replace(b"\r\n", b""):
        raise DnsRefused("dns-config-mixed-newlines")
    return b"\r\n" if has_crlf else b"\n"


def _segments(data: bytes):
    offset = 0
    for line in data.splitlines(keepends=True):
        yield offset, offset + len(line), line
        offset += len(line)


def _server_bounds(data: bytes) -> tuple[int, int]:
    sections = [(start, end, raw.split(b":", 1)[0]) for start, end, raw in _segments(data) if _TOP_LEVEL.fullmatch(raw.rstrip(b"\r\n"))]
    servers = [(start, end) for start, end, name in sections if name == b"server"]
    if len(servers) != 1:
        raise DnsRefused("dns-server-section-ambiguous")
    start = servers[0][1]
    later = [section_start for section_start, _, _ in sections if section_start >= start]
    return start, min(later) if later else len(data)


def _parse_record(record: re.Match[bytes]) -> tuple[str, str, tuple[bytes, ...]] | None:
    fields = record.group("body").split()
    if len(fields) == 3:
        name_b, kind, address_b = fields
        style = (kind,)
    elif len(fields) == 4:
        name_b, dns_class, kind, address_b = fields
        style = (dns_class, kind)
    else:
        return None
    if style[-1].lower() != b"a" or (len(style) == 2 and style[0].lower() != b"in"):
        return None
    try:
        return normalize_name(name_b.decode("ascii")), admit_private_ipv4(address_b.decode("ascii")), style
    except (UnicodeDecodeError, DnsRefused):
        return None


def _server_records(data: bytes, target: str | None = None):
    section_start, section_end = _server_bounds(data)
    matches, records = [], []
    last_local_data = last_local_zone = None
    for start, end, raw in _segments(data):
        if start < section_start or end > section_end:
            continue
        body = raw.rstrip(b"\r\n")
        record = _RECORD.fullmatch(body)
        if record:
            last_local_data = (start, end, raw, record)
            parsed = _parse_record(record)
            if parsed:
                name, address, _style = parsed
                records.append({"name": name, "address": address})
                if target and name == target:
                    matches.append((start, end, raw, record, parsed))
            elif target and target.encode("ascii").rstrip(b".") in record.group("body").lower():
                raise DnsRefused("dns-target-record-ambiguous")
        elif _LOCAL_ZONE.match(body):
            last_local_zone = (start, end, raw)
        elif target and body.lstrip().startswith(b"local-data:") and target.encode("ascii").rstrip(b".") in body.lower():
            raise DnsRefused("dns-target-record-ambiguous")
    if len(matches) > 1:
        raise DnsRefused("dns-target-record-ambiguous")
    insertion = last_local_data[1] if last_local_data else (last_local_zone[1] if last_local_zone else section_end)
    return matches, records, insertion


def _candidate(data: bytes, action: str, name: str | None, address: str | None) -> tuple[bytes, list[dict[str, str]]]:
    newline = _newline_style(data)
    entries, records, insertion = _server_records(data, name if action != "status" else None)
    if action == "status":
        return data, records
    assert name is not None
    if action == "remove":
        return (data if not entries else data[:entries[0][0]] + data[entries[0][1]:]), records
    assert address is not None
    if entries:
        start, end, _raw, match, (_old_name, _old_address, style) = entries[0]
        rendered = match.group("prefix") + b'"' + name.encode("ascii") + b" " + b" ".join(style) + b" " + address.encode("ascii") + b'"' + match.group("suffix") + newline
        return data[:start] + rendered + data[end:], records
    if data and not data.endswith((b"\n", b"\r")):
        raise DnsRefused("dns-config-final-newline-required")
    anchor = data[:insertion].splitlines(keepends=True)[-1] if insertion else b""
    match, zone = _RECORD.fullmatch(anchor.rstrip(b"\r\n")), _LOCAL_ZONE.match(anchor.rstrip(b"\r\n"))
    indent = match.group("prefix").split(b"local-data:", 1)[0] if match else (zone.group("prefix") if zone else b"")
    rendered = indent + b'local-data: "' + name.encode("ascii") + b" IN A " + address.encode("ascii") + b'"' + newline
    return data[:insertion] + rendered + data[insertion:], records


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("dns-config-short-write")
        view = view[written:]


def _checkconf(path: Path) -> tuple[bool, str]:
    try:
        result = subprocess.run([str(CHECKCONF), str(path)], text=True, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, "dns-checkconf-unavailable"
    return result.returncode == 0, "" if result.returncode == 0 else "dns-checkconf-refused"


def _write_staged(path: Path, prefix: str, payload: bytes, metadata: os.stat_result, xattrs: tuple[tuple[str, bytes], ...]) -> Path:
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    staged = Path(temporary)
    try:
        _apply_metadata(fd, metadata, xattrs)
        _write_all(fd, payload)
        os.fsync(fd)
    except Exception:
        staged.unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)
    return staged


def _stage_validate(path: Path, candidate: bytes, metadata: os.stat_result, xattrs: tuple[tuple[str, bytes], ...], checkconf: Callable[[Path], tuple[bool, str]]) -> tuple[bool, str]:
    staged = _write_staged(path, ".agathodaimon-unbound-", candidate, metadata, xattrs)
    try:
        return checkconf(staged)
    finally:
        staged.unlink(missing_ok=True)


def _fsync_parent(path: Path) -> None:
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _install(path: Path, payload: bytes, metadata: os.stat_result, xattrs: tuple[tuple[str, bytes], ...], source: FileSnapshot) -> FileSnapshot:
    if not _snapshot_is_current(path, source):
        raise DnsRefused("dns-config-identity-content-metadata-changed")
    staged = _write_staged(path, ".agathodaimon-unbound-", payload, metadata, xattrs)
    try:
        _staged_data, _staged_metadata, fallback = _snapshot(staged)
        if not _snapshot_is_current(path, source):
            raise DnsRefused("dns-config-identity-content-metadata-changed")
        os.replace(staged, path)
        try:
            _installed_data, _installed_metadata, installed = _snapshot(path)
            if installed.identity != fallback.identity or installed.digest != fallback.digest or installed.xattrs != fallback.xattrs:
                raise DnsRefused("dns-config-identity-content-metadata-changed")
            _fsync_parent(path)
        except Exception as exc:
            raise InstalledFailure("dns-install-failed", fallback) from exc
        return installed
    finally:
        staged.unlink(missing_ok=True)


def _restore(path: Path, original: bytes, metadata: os.stat_result, xattrs: tuple[tuple[str, bytes], ...], installed: FileSnapshot, source: FileSnapshot) -> None:
    if not _snapshot_is_current(path, installed):
        raise DnsRefused("dns-config-identity-content-metadata-changed")
    staged = _write_staged(path, ".agathodaimon-unbound-rollback-", original, metadata, xattrs)
    try:
        if not _snapshot_is_current(path, installed):
            raise DnsRefused("dns-config-identity-content-metadata-changed")
        os.replace(staged, path)
        _fsync_parent(path)
        if not _snapshot_semantics_are_current(path, source):
            raise DnsRefused("dns-config-restore-validation-failed")
    finally:
        staged.unlink(missing_ok=True)


def _rollback(path: Path, original: bytes, metadata: os.stat_result, xattrs: tuple[tuple[str, bytes], ...], installed: FileSnapshot, source: FileSnapshot, checkconf: Callable[[Path], tuple[bool, str]]) -> tuple[str, str]:
    try:
        _restore(path, original, metadata, xattrs, installed, source)
        valid, error = checkconf(path)
        return ("restored" if valid else "restore-validation-failed", error or "none")
    except DnsRefused as exc:
        if str(exc) == "dns-config-identity-content-metadata-changed":
            return "refused-identity-content-metadata-changed", str(exc)
        return "failed", str(exc)
    except Exception as exc:
        return "failed", str(exc)


def dispatch(intent: Any, *, config_path: Path = DEFAULT_CONFIG, checkconf: Callable[[Path], tuple[bool, str]] = _checkconf) -> dict[str, Any]:
    action = intent.get("action") if isinstance(intent, dict) else "invalid"
    name = address = None
    parent_fd: int | None = None
    try:
        if not isinstance(intent, dict) or not isinstance(action, str) or set(intent) - {"action", "name", "address"}:
            raise DnsRefused("dns-intent-invalid")
        if action not in {"status", "ensure-local-data", "remove"}:
            raise DnsRefused("dns-intent-action-invalid")
        if action == "status":
            if set(intent) != {"action"}:
                raise DnsRefused("dns-intent-invalid")
        else:
            name = normalize_name(intent.get("name"))
            if name == "home.arpa.":
                raise DnsRefused("dns-gateway-apex-base-owned")
            if action == "ensure-local-data":
                address = admit_private_ipv4(intent.get("address"))
            elif set(intent) != {"action", "name"}:
                raise DnsRefused("dns-intent-invalid")
        path = Path(config_path)
        parent_fd = _open_locked_parent(path)
        original, metadata, source = _snapshot(path)
        candidate, records = _candidate(original, action, name, address)
        before = source.digest
        after = hashlib.sha256(candidate).hexdigest()
        if action == "status":
            valid, error = checkconf(path)
            return _receipt(action, ok=valid, changed=False, records=records, beforeSha256=before, afterSha256=after, error=error or "none", validation="installed-validated" if valid else "installed-refused", rollback="not-needed")
        if candidate == original:
            valid, error = _stage_validate(path, candidate, metadata, source.xattrs, checkconf)
            return _receipt(action, ok=valid, changed=False, name=name, address=address, error=error or "none", beforeSha256=before, afterSha256=after, validation="validated-noop", rollback="not-needed")
        valid, error = _stage_validate(path, candidate, metadata, source.xattrs, checkconf)
        if not valid:
            return _receipt(action, ok=False, changed=False, name=name, address=address, error=error, beforeSha256=before, afterSha256=before, validation="candidate-refused", rollback="not-needed")
        try:
            installed = _install(path, candidate, metadata, source.xattrs, source)
        except InstalledFailure as exc:
            rollback, rollback_error = _rollback(path, original, metadata, source.xattrs, exc.snapshot, source, checkconf)
            return _receipt(action, ok=False, changed=False, name=name, address=address, error=str(exc), beforeSha256=before, afterSha256=after if rollback != "restored" else before, validation="install-failed", rollback=rollback, rollbackError=rollback_error)
        try:
            valid, error = checkconf(path)
        except Exception as exc:
            rollback, rollback_error = _rollback(path, original, metadata, source.xattrs, installed, source, checkconf)
            return _receipt(action, ok=False, changed=False, name=name, address=address, error="dns-installed-validator-exception", beforeSha256=before, afterSha256=after if rollback != "restored" else before, validation="installed-exception", rollback=rollback, rollbackError=rollback_error or str(exc))
        if valid:
            return _receipt(action, ok=True, changed=True, name=name, address=address, beforeSha256=before, afterSha256=after, validation="installed-validated", rollback="not-needed")
        rollback, rollback_error = _rollback(path, original, metadata, source.xattrs, installed, source, checkconf)
        return _receipt(action, ok=False, changed=False, name=name, address=address, error=error, beforeSha256=before, afterSha256=after if rollback != "restored" else before, validation="installed-refused", rollback=rollback, rollbackError=rollback_error)
    except (DnsRefused, OSError) as exc:
        return _receipt(action if isinstance(action, str) else "invalid", ok=False, changed=False, name=name, address=address, error=str(exc), validation="not-run", rollback="not-needed")
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def legacy_main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-network-dns")
    parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        value = _receipt("invalid", ok=False, changed=False, error="dns-input-too-large", validation="not-run", rollback="not-needed")
    else:
        try:
            intent = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            value = _receipt("invalid", ok=False, changed=False, error="dns-input-invalid", validation="not-run", rollback="not-needed")
        else:
            value = dispatch(intent)
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


from agathodaimon.network.dns._manager import CommandRunner, DnsError, DnsManager, create_alias
from agathodaimon.network.dns._resolver import ResolverControl, resolver_control


def _failure(action: str, reason: str) -> dict[str, Any]:
    return {
        "schema": "caduceus.network.dns.v1",
        "action": action,
        "ok": False,
        "mutationPerformed": False,
        "firstMissingSignal": reason,
    }



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agathodaimon-network-dns")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("read")
    resolver = commands.add_parser("resolver")
    resolver.add_argument("action", choices=("status", "adblock", "blocklist-update", "upstream"))
    resolver.add_argument("--metadata-json")
    device = commands.add_parser("device-name")
    device.add_argument("action", choices=("create", "remove"))
    device.add_argument("--hostname", required=True)
    device.add_argument("--ip", required=True)
    alias = commands.add_parser("alias")
    alias.add_argument("action", choices=("create", "remove"))
    alias.add_argument("--label", required=True)
    alias.add_argument("--hostname", required=True)
    intent = commands.add_parser("intent")
    intent.add_argument("method")
    intent.add_argument("target")
    intent.add_argument("--metadata-json", required=True)
    return parser



def staff_main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manager = DnsManager()
    try:
        if args.command == "status":
            receipt = manager.read_status()
        elif args.command == "read":
            receipt = {"schema": "caduceus.network.dns.v1", "actuator": "network.dns.read", "action": "read", "ok": True, "result": manager.read(), "mutationPerformed": False, "firstMissingSignal": "none"}
        elif args.command == "resolver":
            metadata = None
            if args.metadata_json is not None:
                try:
                    metadata = json.loads(args.metadata_json)
                except json.JSONDecodeError as exc:
                    raise DnsError("resolver-metadata-invalid") from exc
            receipt = resolver_control(args.action, metadata)
        elif args.command == "device-name":
            receipt = manager.create_device_name(args.hostname, args.ip) if args.action == "create" else manager.remove_device_name(args.hostname, args.ip)
            receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.device_name.{args.action}", "ok": True, "firstMissingSignal": "none"}
        elif args.command == "alias":
            receipt = manager.create_alias(args.label, args.hostname) if args.action == "create" else manager.remove_alias(args.label, args.hostname)
            receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.alias.{args.action}", "ok": True, "firstMissingSignal": "none"}
        else:
            if args.method != "POST" or args.target != DnsManager.INTENT_TARGET:
                raise DnsError("dns-intent-not-admitted")
            try:
                metadata = json.loads(args.metadata_json)
            except json.JSONDecodeError as exc:
                raise DnsError("dns-metadata-invalid") from exc
            receipt = manager.apply(metadata)
    except DnsError as exc:
        receipt = _failure(args.command, str(exc))
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    return staff_main(arguments) if arguments and arguments[0] in {"status", "read", "resolver", "device-name", "alias", "intent"} else legacy_main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())

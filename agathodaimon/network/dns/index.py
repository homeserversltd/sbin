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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

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
    if not name.endswith(".home.arpa") or name == "home.arpa":
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


# Managed drop-in lineage carried from sbin 0851389; direct-file lineage remains above.
class DnsError(RuntimeError):
    """A bounded, operator-readable Unbound managed-drop-in failure."""


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class DnsManager:
    """Install exactly one bounded, managed Unbound local-data drop-in."""

    ROOT_CONFIG = Path("/etc/unbound/unbound.conf")
    DROPIN_DIR = Path("/etc/unbound/unbound.conf.d")
    TARGET_NAME = "laptop-home-arpa.conf"
    CHECKCONF = "unbound-checkconf"
    SERVICE = "unbound"
    MAX_PAYLOAD_BYTES = 8192
    ACTION = "network dns"
    INTENT_TARGET = "/api/dns/unbound/drop-in"
    READ_INCLUDE_PATH = Path("/etc/unbound/unbound.conf.d/agathodaimon-local-names.conf")
    BEGIN = "# BEGIN CADUCEUS OWNED DEVICE RECORDS"
    END = "# END CADUCEUS OWNED DEVICE RECORDS"

    def __init__(
        self,
        root_config: str | Path | None = None,
        dropin_dir: str | Path | None = None,
        include_path: str | Path | None = None,
        *,
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.root_config = Path(root_config or os.environ.get("CADUCEUS_UNBOUND_CONFIG", self.ROOT_CONFIG))
        self.dropin_dir = Path(dropin_dir or os.environ.get("CADUCEUS_UNBOUND_DROPIN_DIR", self.DROPIN_DIR))
        self.target = self.dropin_dir / self.TARGET_NAME
        self.read_include = Path(include_path or os.environ.get("CADUCEUS_UNBOUND_INCLUDE", self.READ_INCLUDE_PATH))
        self._command_runner = command_runner or self._run

    @staticmethod
    def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)

    def _command(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self._command_runner(command)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError(f"command failed: {' '.join(command)}: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or f"exit {result.returncode}"
            raise DnsError(f"command failed: {' '.join(command)}: {detail}")
        return result

    def _reload_service(self) -> dict[str, Any]:
        receipt = reload_services([self.SERVICE], command_runner=self._command_runner)
        step = receipt["services"][0]
        if not receipt["ok"]:
            raise DnsError(receipt["firstMissingSignal"])
        return step

    @staticmethod
    def _digest(payload: bytes | None) -> str | None:
        return hashlib.sha256(payload).hexdigest() if payload is not None else None

    def _safe_target(self, target: str | None) -> Path:
        if target not in (None, self.TARGET_NAME):
            raise DnsError("dns-target-not-admitted")
        if self.target.name != self.TARGET_NAME or self.target.parent != self.dropin_dir:
            raise DnsError("dns-target-not-admitted")
        if self.dropin_dir.is_symlink() or self.target.is_symlink():
            raise DnsError("dns-target-symlink-refused")
        return self.target

    @staticmethod
    def _validate_payload(payload: Any) -> bytes:
        if not isinstance(payload, str):
            raise DnsError("dns-payload-missing")
        encoded = payload.encode("utf-8")
        if not encoded or len(encoded) > DnsManager.MAX_PAYLOAD_BYTES or "\x00" in payload:
            raise DnsError("dns-payload-invalid")
        lines = payload.splitlines()
        if not lines or lines[0].strip() != "server:":
            raise DnsError("dns-payload-not-unbound")
        records: set[str] = set()
        pattern = re.compile(
            r'^\s+local-data:\s+"laptop\.home\.arpa\. IN A 192\.168\.123\.(19|20)"\s*$'
        )
        for line in lines[1:]:
            match = pattern.fullmatch(line)
            if not match or match.group(1) in records:
                raise DnsError("dns-payload-not-admitted")
            records.add(match.group(1))
        if records != {"19", "20"}:
            raise DnsError("dns-payload-not-admitted")
        return (payload.rstrip() + "\n").encode("utf-8")

    def _root_text(self) -> str:
        try:
            return self.root_config.read_text(encoding="utf-8")
        except OSError as exc:
            raise DnsError(f"dns-root-config-unreadable: {exc}") from exc

    def _stage_full_config(self, candidate: bytes) -> Path:
        root_text = self._root_text()
        expected_include = f'include-toplevel: "{self.dropin_dir}/*.conf"'
        if expected_include not in root_text:
            raise DnsError("dns-managed-include-missing")
        stage: Path | None = None
        try:
            stage = Path(tempfile.mkdtemp(prefix="agathodaimon-unbound-stage-"))
            stage_dropins = stage / "unbound.conf.d"
            stage_dropins.mkdir(mode=0o700)
            if self.dropin_dir.exists():
                for sibling in self.dropin_dir.iterdir():
                    if sibling.name == self.TARGET_NAME:
                        continue
                    if sibling.is_symlink() or not sibling.is_file():
                        raise DnsError("dns-neighbor-not-regular")
                    shutil.copy2(sibling, stage_dropins / sibling.name)
            (stage_dropins / self.TARGET_NAME).write_bytes(candidate)
            stage_root = stage / "unbound.conf"
            stage_root.write_text(root_text.replace(expected_include, f'include-toplevel: "{stage_dropins}/*.conf"'), encoding="utf-8")
            return stage
        except Exception:
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)
            raise

    def _validate_staged(self, candidate: bytes) -> None:
        stage = self._stage_full_config(candidate)
        try:
            self._command([self.CHECKCONF, str(stage / "unbound.conf")])
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def _validate_owned_staged(self, candidate: bytes) -> None:
        root_text = self._root_text()
        expected_include = f'include-toplevel: "{self.dropin_dir}/*.conf"'
        if expected_include not in root_text:
            raise DnsError("dns-managed-include-missing")
        stage = Path(tempfile.mkdtemp(prefix="agathodaimon-unbound-owned-stage-"))
        try:
            stage_dropins = stage / "unbound.conf.d"
            stage_dropins.mkdir(mode=0o700)
            if self.dropin_dir.exists():
                for sibling in self.dropin_dir.iterdir():
                    if sibling.is_symlink() or not sibling.is_file():
                        raise DnsError("dns-neighbor-not-regular")
                    if sibling != self.read_include:
                        shutil.copy2(sibling, stage_dropins / sibling.name)
            (stage_dropins / self.read_include.name).write_bytes(candidate)
            stage_root = stage / "unbound.conf"
            stage_root.write_text(root_text.replace(expected_include, f'include-toplevel: "{stage_dropins}/*.conf"'), encoding="utf-8")
            self._command([self.CHECKCONF, str(stage_root)])
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def _validate_live(self) -> None:
        self._command([self.CHECKCONF, str(self.root_config)])

    def _replace_bytes(self, target: Path, payload: bytes, mode: int = 0o644) -> None:
        self.dropin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        if self.dropin_dir.is_symlink():
            raise DnsError("dns-target-symlink-refused")
        with tempfile.NamedTemporaryFile(dir=self.dropin_dir, prefix=f".{target.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
        try:
            temporary.chmod(mode)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def _restore(self, previous: bytes | None, mode: int) -> None:
        if previous is None:
            self.target.unlink(missing_ok=True)
        else:
            self._replace_bytes(self.target, previous, mode)
        self._validate_live()
        self._reload_service()

    def status(self) -> dict[str, Any]:
        return {
            "schema": "caduceus.network.dns.v1",
            "action": "status",
            "target": str(self.target),
            "rootConfig": str(self.root_config),
            "targetExists": self.target.is_file() and not self.target.is_symlink(),
            "firstMissingSignal": "none",
            "ok": True,
        }

    def read_status(self) -> dict[str, Any]:
        """Additive read-actuator view without changing the mutation membrane's status."""
        result = self.status()
        result["actuator"] = "network.dns.status"
        result["read"] = self.read()
        result["mutationPerformed"] = False
        return result

    def _owned_lines(self) -> list[str]:
        try:
            text = self.read_include.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise DnsError(f"failed to read owned include {self.read_include}: {exc}") from exc
        if self.BEGIN not in text or self.END not in text:
            return []
        return text.split(self.BEGIN, 1)[1].split(self.END, 1)[0].splitlines()

    _INCLUDE = re.compile(r'^\s*(?:include|include-toplevel)\s*:\s*"([^"\r\n]+)"', re.I)
    _LOCAL_DATA = re.compile(r'\blocal-data\s*:\s*"([^\s"]+)\.?\s+(?:IN\s+)?(A|PTR|CNAME)\s+([^\s"]+)', re.I)

    def _config_paths(self) -> list[Path]:
        """Return the root and every recursively referenced Unbound fragment."""
        paths: list[Path] = []
        seen: set[Path] = set()

        def visit(path: Path, required: bool) -> None:
            resolved = path.resolve(strict=False)
            if resolved in seen:
                return
            try:
                text = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                if required:
                    raise DnsError(f"dns-root-config-unreadable: {path}")
                return
            except OSError as exc:
                raise DnsError(f"dns-config-unreadable: {path}: {exc}") from exc
            seen.add(resolved)
            paths.append(path)
            for line in text.splitlines():
                match = self._INCLUDE.match(line)
                if not match:
                    continue
                candidate = Path(match.group(1))
                if not candidate.is_absolute():
                    candidate = path.parent / candidate
                matches = sorted(Path(value) for value in glob.glob(str(candidate)))
                if matches:
                    for included in matches:
                        visit(included, required=False)
                elif not any(character in str(candidate) for character in "*?["):
                    visit(candidate, required=False)

        visit(self.root_config, required=True)
        return paths

    def _all_local_records(self) -> list[dict[str, str]]:
        records: list[dict[str, str]] = []
        for path in self._config_paths():
            text = path.read_text(encoding="utf-8")
            owned = False
            for line in text.splitlines():
                if self.BEGIN in line:
                    owned = True
                    continue
                if self.END in line:
                    owned = False
                    continue
                match = self._LOCAL_DATA.search(line)
                if not match:
                    continue
                records.append({
                    "name": match.group(1).rstrip(".").lower(),
                    "type": match.group(2).upper(),
                    "target": match.group(3).rstrip(".").lower(),
                    "provenance": "owned" if owned else "legacy",
                })
        return records

    def read(self) -> dict[str, Any]:
        """Read every configured local-data identity; ownership only governs writes."""
        devices: dict[str, dict[str, Any]] = {}
        aliases: list[dict[str, str]] = []
        for record in self._all_local_records():
            name, record_type, target, provenance = record["name"], record["type"], record["target"], record["provenance"]
            if record_type == "CNAME":
                aliases.append({"name": name, "target": target, "provenance": provenance})
                continue
            if record_type == "A":
                device = devices.setdefault(name, {"name": name, "a": [], "ptr": [], "a_records": [], "ptr_records": [], "provenance": []})
                if target not in device["a"]:
                    device["a"].append(target)
                device["a_records"].append({"address": target, "provenance": provenance})
            else:
                device = devices.setdefault(target, {"name": target, "a": [], "ptr": [], "a_records": [], "ptr_records": [], "provenance": []})
                if name not in device["ptr"]:
                    device["ptr"].append(name)
                device["ptr_records"].append({"name": name, "provenance": provenance})
        for device in devices.values():
            device["a"].sort()
            device["ptr"].sort()
            device["a_records"].sort(key=lambda item: (item["address"], item["provenance"]))
            device["ptr_records"].sort(key=lambda item: (item["name"], item["provenance"]))
            records_with_provenance = device["a_records"] + device["ptr_records"]
            device["provenance"] = sorted({item["provenance"] for item in records_with_provenance})
        return {"include": str(self.read_include), "exists": self.read_include.is_file(), "devices": [devices[key] for key in sorted(devices)], "aliases": sorted(aliases, key=lambda item: (item["name"], item["target"], item["provenance"])), "mutationPerformed": False, "firstMissingSignal": "none"}

    @staticmethod
    def canonical_name(hostname: str) -> str:
        label = hostname.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise DnsError("dns-hostname-malformed")
        return f"{label}.home.arpa."

    @staticmethod
    def _reverse_name(address: str) -> str:
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise DnsError("dns-ipv4-malformed") from exc
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa."

    @staticmethod
    def _alias_name(label: str) -> str:
        value = label.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
            raise DnsError("dns-alias-label-malformed")
        return f"{value}.home.arpa."

    def _include_text(self) -> str:
        try:
            return self.read_include.read_text(encoding="utf-8")
        except FileNotFoundError:
            return f"server:\n{self.BEGIN}\n{self.END}\n"
        except OSError as exc:
            raise DnsError(f"failed to read owned include {self.read_include}: {exc}") from exc

    def _split_owned_include(self, text: str) -> tuple[str, str, str]:
        if text.count(self.BEGIN) != 1 or text.count(self.END) != 1:
            raise DnsError("dns-ownership-markers-invalid")
        before, rest = text.split(self.BEGIN, 1)
        owned, after = rest.split(self.END, 1)
        return before, owned, after

    def _render_owned(self, lines: list[str]) -> bytes:
        text = self._include_text()
        before, _owned, after = self._split_owned_include(text)
        payload = before + self.BEGIN + "\n"
        payload += "".join(f'    local-data: "{line}"\n' for line in sorted(lines))
        payload += self.END + after
        return payload.encode("utf-8")

    def _owned_records(self) -> list[str]:
        records: list[str] = []
        for line in self._owned_lines():
            match = re.fullmatch(r'\s*local-data:\s+"(.+)"\s*', line, re.I)
            if match:
                records.append(match.group(1))
        return records

    def _observed_owner_names(self) -> set[str]:
        names: set[str] = set()
        for record in self._all_local_records():
            names.add(record["name"])
        return names

    def _validate_candidate(self, lines: list[str], new_owners: set[str]) -> None:
        owned_names: set[str] = set()
        cname_names: set[str] = set()
        for line in lines:
            match = re.fullmatch(r"([^\s]+)\s+IN\s+(A|PTR|CNAME)\s+([^\s]+)", line, re.I)
            if not match:
                raise DnsError("dns-owned-record-malformed")
            owner, record_type = match.group(1).rstrip(".").lower(), match.group(2).upper()
            if record_type == "CNAME":
                cname_names.add(owner)
            else:
                owned_names.add(owner)
        if cname_names & owned_names:
            raise DnsError("dns-cname-a-owner-conflict")
        observed = self._observed_owner_names()
        existing_owned = {line.split()[0].rstrip(".").lower() for line in self._owned_records()}
        if any(owner in observed - existing_owned for owner in new_owners):
            raise DnsError("dns-observed-record-collision")

    def _candidate_apply(self, lines: list[str], expected: list[tuple[str, str]]) -> dict[str, Any]:
        query_tool = shutil.which("dig")
        if query_tool is None:
            raise DnsError("dns-live-query-tool-missing")
        candidate = self._render_owned(lines)
        previous = self.read_include.read_bytes() if self.read_include.exists() else None
        mode = self.read_include.stat().st_mode & 0o777 if self.read_include.exists() else 0o644
        receipt: dict[str, Any] = {"config_valid": False, "reload_outcome": "not-run", "live_query_readback": [], "mutationPerformed": False}
        try:
            self._validate_owned_staged(candidate)
            receipt["config_valid"] = True
            self._replace_bytes(self.read_include, candidate, mode)
            self._reload_service()
            receipt["reload_outcome"] = "reloaded"
            for record_type, owner in expected:
                result = self._command([query_tool, "@127.0.0.1", owner, record_type, "+short"])
                output = result.stdout.strip()
                if not output:
                    raise DnsError(f"dns-live-query-empty: {record_type} {owner}")
                receipt["live_query_readback"].append({"type": record_type, "owner": owner, "output": output})
            receipt["mutationPerformed"] = True
            return receipt
        except DnsError as exc:
            receipt["first_failing_boundary"] = str(exc)
            try:
                if previous is None:
                    self.read_include.unlink(missing_ok=True)
                else:
                    self._replace_bytes(self.read_include, previous, mode)
                self._reload_service()
                receipt["candidate"] = "restored"
            except DnsError as rollback:
                receipt["candidate"] = "restore-failed"
                receipt["rollback_error"] = str(rollback)
            raise DnsError(json.dumps(receipt, sort_keys=True)) from exc

    def owned_preimage(self) -> bytes | None:
        return self.read_include.read_bytes() if self.read_include.exists() else None

    def restore_owned_preimage(self, previous: bytes | None) -> dict[str, Any]:
        mode = self.read_include.stat().st_mode & 0o777 if self.read_include.exists() else 0o644
        if previous is None:
            self.read_include.unlink(missing_ok=True)
        else:
            self._replace_bytes(self.read_include, previous, mode)
        self._validate_live()
        self._reload_service()
        restored = self.read_include.read_bytes() if self.read_include.exists() else None
        if restored != previous:
            raise DnsError("dns-preimage-restoration-mismatch")
        return {"config_valid": True, "reload_outcome": "reloaded", "restoration_verified": True}

    def create_device_name(self, hostname: str, address: str) -> dict[str, Any]:
        canonical = self.canonical_name(hostname)
        reverse = self._reverse_name(address)
        lines = self._owned_records()
        additions = [f"{canonical} IN A {address}", f"{reverse} IN PTR {canonical}"]
        if any(value in lines for value in additions):
            if all(value in lines for value in additions):
                return {"action": "device-name-create", "state": "noop", "canonical_name": canonical, "mutationPerformed": False, "verification": []}
            raise DnsError("dns-device-projection-incomplete")
        self._validate_candidate(lines + additions, {canonical.rstrip(".").lower(), reverse.rstrip(".").lower()})
        return {"action": "device-name-create", "state": "applied", "canonical_name": canonical, "verification": self._candidate_apply(lines + additions, [("A", canonical), ("PTR", reverse)])}

    def remove_device_name(self, hostname: str, address: str) -> dict[str, Any]:
        canonical, reverse = self.canonical_name(hostname), self._reverse_name(address)
        removals = {f"{canonical} IN A {address}", f"{reverse} IN PTR {canonical}"}
        lines = self._owned_records()
        present = removals & set(lines)
        if not present:
            return {"action": "device-name-remove", "state": "noop", "canonical_name": canonical, "mutationPerformed": False, "verification": []}
        if present != removals:
            raise DnsError("dns-device-projection-incomplete")
        return {"action": "device-name-remove", "state": "applied", "canonical_name": canonical, "verification": self._candidate_apply([line for line in lines if line not in removals], [("A", canonical), ("PTR", reverse)])}

    def create_alias(self, alias_label: str, hostname: str) -> dict[str, Any]:
        alias, canonical = self._alias_name(alias_label), self.canonical_name(hostname)
        lines = self._owned_records()
        record = f"{alias} IN CNAME {canonical}"
        if record in lines:
            return {"action": "alias-create", "state": "noop", "alias": alias, "mutationPerformed": False, "verification": []}
        self._validate_candidate(lines + [record], {alias.rstrip(".").lower()})
        return {"action": "alias-create", "state": "applied", "alias": alias, "verification": self._candidate_apply(lines + [record], [("CNAME", alias)])}

    def remove_alias(self, alias_label: str, hostname: str) -> dict[str, Any]:
        alias, canonical = self._alias_name(alias_label), self.canonical_name(hostname)
        record = f"{alias} IN CNAME {canonical}"
        lines = self._owned_records()
        if record not in lines:
            return {"action": "alias-remove", "state": "noop", "alias": alias, "mutationPerformed": False, "verification": []}
        return {"action": "alias-remove", "state": "applied", "alias": alias, "verification": self._candidate_apply([line for line in lines if line != record], [("CNAME", alias)])}

    def apply(self, metadata: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(metadata, dict):
            raise DnsError("dns-metadata-invalid")
        target = self._safe_target(metadata.get("target"))
        candidate = self._validate_payload(metadata.get("dropIn"))
        dry_run = metadata.get("dryRun", False)
        if not isinstance(dry_run, bool):
            raise DnsError("dns-dry-run-invalid")
        previous = target.read_bytes() if target.exists() else None
        before_hash, after_hash = self._digest(previous), self._digest(candidate)
        receipt: dict[str, Any] = {
            "schema": "caduceus.network.dns.v1",
            "action": "apply-managed-drop-in",
            "target": str(target),
            "beforeHash": before_hash,
            "afterHash": after_hash,
            "stagedValidation": False,
            "liveValidation": False,
            "reload": "not-run",
            "rollback": "not-needed",
            "mutationPerformed": False,
            "ok": True,
            "firstMissingSignal": "none",
        }
        self._validate_staged(candidate)
        receipt["stagedValidation"] = True
        if dry_run:
            receipt["action"] = "plan-managed-drop-in"
            return receipt
        if previous == candidate:
            self._validate_live()
            receipt["liveValidation"] = True
            receipt["reload"] = "not-needed-idempotent"
            return receipt
        mode = target.stat().st_mode & 0o777 if target.exists() else 0o644
        try:
            self._replace_bytes(target, candidate, mode)
            self._validate_live()
            receipt["liveValidation"] = True
            self._reload_service()
            receipt["reload"] = "reloaded"
            receipt["mutationPerformed"] = True
            return receipt
        except DnsError as exc:
            try:
                self._restore(previous, mode)
                receipt["rollback"] = "restored-and-revalidated"
            except DnsError as rollback:
                receipt["rollback"] = "failed"
                receipt["ok"] = False
                receipt["firstMissingSignal"] = f"{exc}; dns-rollback-failed: {rollback}"
                return receipt
            receipt["ok"] = False
            receipt["firstMissingSignal"] = str(exc)
            return receipt




class ResolverControl:
    """Bounded owner for the resolver-control portion of Unbound configuration."""

    CONFIG = Path("/etc/unbound/unbound.conf")
    BLOCKLIST = Path("/etc/unbound/blocklist.conf")
    CHECKCONF = "/usr/sbin/unbound-checkconf"
    SYSTEMCTL = "/usr/bin/systemctl"
    UPDATE = "/usr/local/lib/updates/modules/adblock/index.py"
    PRESETS = {
        "quad9": ["9.9.9.9", "149.112.112.112"],
        "cloudflare": ["1.1.1.1", "1.0.0.1"],
        "google": ["8.8.8.8", "8.8.4.4"],
    }
    _BLOCKLIST = re.compile(r'^(?P<indent>[ \t]*)(?P<comment>#\s*)?include:\s*["\']?/etc/unbound/blocklist\.conf["\']?(?P<tail>\s*(?:#.*)?)$', re.M)
    _TOP = re.compile(r'^[A-Za-z][A-Za-z0-9-]*:\s*(?:#.*)?$', re.M)

    def __init__(self, config: Path | None = None, *, runner: CommandRunner | None = None) -> None:
        self.config = config or Path(os.environ.get("CADUCEUS_UNBOUND_CONFIG", self.CONFIG))
        self.runner = runner or DnsManager._run

    def _run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self.runner(argv)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError("resolver-command-unavailable") from exc
        if result.returncode:
            raise DnsError("resolver-command-failed")
        return result

    def _read(self) -> str:
        try:
            return self.config.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DnsError("resolver-config-unreadable") from exc

    def _install(self, before: str, after: str) -> None:
        if before == after:
            self._run([self.CHECKCONF, str(self.config)])
            return
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.config.parent, prefix=".agathodaimon-resolver-", delete=False) as handle:
            staged = Path(handle.name)
            handle.write(after)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(staged, self.config.stat().st_mode & 0o777)
            self._run([self.CHECKCONF, str(staged)])
            os.replace(staged, self.config)
            try:
                self._run([self.CHECKCONF, str(self.config)])
                self._run([self.SYSTEMCTL, "reload", "unbound"])
            except DnsError:
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.config.parent, prefix=".agathodaimon-resolver-rollback-", delete=False) as rollback:
                    restored = Path(rollback.name)
                    rollback.write(before)
                    rollback.flush()
                    os.fsync(rollback.fileno())
                try:
                    os.chmod(restored, self.config.stat().st_mode & 0o777)
                    os.replace(restored, self.config)
                    self._run([self.CHECKCONF, str(self.config)])
                    self._run([self.SYSTEMCTL, "reload", "unbound"])
                finally:
                    restored.unlink(missing_ok=True)
                raise
        finally:
            staged.unlink(missing_ok=True)

    @staticmethod
    def _forward_section(text: str) -> tuple[int, int]:
        matches = list(re.finditer(r'^forward-zone:\s*(?:#.*)?$', text, re.M))
        if len(matches) != 1:
            raise DnsError("resolver-forward-zone-ambiguous")
        start = matches[0].start()
        subsequent = ResolverControl._TOP.search(text, matches[0].end())
        return start, subsequent.start() if subsequent else len(text)

    @staticmethod
    def _forward_values(text: str) -> tuple[list[str], bool]:
        start, end = ResolverControl._forward_section(text)
        section = text[start:end]
        addresses = re.findall(r'^\s*forward-addr:\s+([^\s#]+)', section, re.M)
        dot = bool(re.search(r'^\s*forward-tls-upstream:\s+yes\s*(?:#.*)?$', section, re.M | re.I))
        return addresses, dot

    def status(self) -> dict[str, Any]:
        text = self._read()
        matches = list(self._BLOCKLIST.finditer(text))
        if len(matches) != 1:
            raise DnsError("resolver-blocklist-include-ambiguous")
        addresses, dot = self._forward_values(text)
        count = 0
        updated = None
        try:
            stat_result = self.BLOCKLIST.stat()
            updated = int(stat_result.st_mtime)
            with self.BLOCKLIST.open(encoding="utf-8", errors="replace") as handle:
                count = sum(1 for line in handle if line.lstrip().startswith("local-zone:"))
        except FileNotFoundError:
            pass
        try:
            active = self.runner([self.SYSTEMCTL, "is-active", "--quiet", "unbound"]).returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError("resolver-service-status-unavailable") from exc
        return {"schema": "caduceus.network.dns.resolver.v1", "ok": True, "action": "status", "adblockEnabled": matches[0].group("comment") is None, "upstreams": addresses, "dnsOverTls": dot, "blocklistDomainCount": count, "blocklistLastUpdate": updated, "unboundActive": active, "mutationPerformed": False, "firstMissingSignal": "none"}

    def adblock(self, enabled: Any) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise DnsError("resolver-adblock-enabled-invalid")
        before = self._read()
        matches = list(self._BLOCKLIST.finditer(before))
        if len(matches) != 1:
            raise DnsError("resolver-blocklist-include-ambiguous")
        match = matches[0]
        line = f'{match.group("indent")}{"" if enabled else "# "}include: "/etc/unbound/blocklist.conf"{match.group("tail")}'
        after = before[:match.start()] + line + before[match.end():]
        self._install(before, after)
        return {"schema": "caduceus.network.dns.resolver.v1", "ok": True, "action": "adblock", "enabled": enabled, "mutationPerformed": before != after, "reload": "reloaded", "firstMissingSignal": "none"}

    def update_blocklist(self) -> dict[str, Any]:
        self._run([sys.executable, self.UPDATE])
        self._run([self.SYSTEMCTL, "reload", "unbound"])
        status = self.status()
        return {"schema": "caduceus.network.dns.resolver.v1", "ok": True, "action": "blocklist-update", "domainCount": status["blocklistDomainCount"], "mutationPerformed": True, "reload": "reloaded", "firstMissingSignal": "none"}

    def upstream(self, metadata: Any) -> dict[str, Any]:
        if not isinstance(metadata, dict) or set(metadata) - {"preset", "custom", "dot"}:
            raise DnsError("resolver-upstream-input-invalid")
        dot = metadata.get("dot")
        if not isinstance(dot, bool):
            raise DnsError("resolver-dot-invalid")
        preset, custom = metadata.get("preset"), metadata.get("custom")
        if isinstance(preset, str) and custom is None:
            if preset not in self.PRESETS:
                raise DnsError("resolver-upstream-preset-invalid")
            addresses = self.PRESETS[preset]
        elif preset is None and isinstance(custom, list) and custom:
            addresses = custom
        else:
            raise DnsError("resolver-upstream-input-invalid")
        if len(addresses) > 8 or any(not isinstance(value, str) for value in addresses):
            raise DnsError("resolver-upstream-address-invalid")
        canonical: list[str] = []
        for value in addresses:
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError as exc:
                raise DnsError("resolver-upstream-address-invalid") from exc
            if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_link_local:
                raise DnsError("resolver-upstream-address-refused")
            canonical.append(str(parsed))
        before = self._read()
        start, end = self._forward_section(before)
        lines = ["forward-zone:", '    name: "."', f'    forward-tls-upstream: {"yes" if dot else "no"}']
        lines.extend(f'    forward-addr: {address}{"@853" if dot else ""}' for address in canonical)
        after = before[:start] + "\n".join(lines) + "\n" + before[end:]
        self._install(before, after)
        return {"schema": "caduceus.network.dns.resolver.v1", "ok": True, "action": "upstream", "upstreams": canonical, "dnsOverTls": dot, "mutationPerformed": before != after, "reload": "reloaded", "firstMissingSignal": "none"}


def resolver_control(action: str, metadata: Any = None) -> dict[str, Any]:
    try:
        resolver = ResolverControl()
        if action == "status" and metadata is None:
            return resolver.status()
        if action == "adblock" and isinstance(metadata, dict):
            return resolver.adblock(metadata.get("enabled"))
        if action == "blocklist-update" and metadata is None:
            return resolver.update_blocklist()
        if action == "upstream":
            return resolver.upstream(metadata)
        raise DnsError("resolver-action-invalid")
    except DnsError as exc:
        return {"schema": "caduceus.network.dns.resolver.v1", "ok": False, "action": action, "mutationPerformed": False, "firstMissingSignal": str(exc)}

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

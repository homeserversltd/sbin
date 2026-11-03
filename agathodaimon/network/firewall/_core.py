"""Caduceus firewall staff actuator backed only by its owned drop-ins."""
from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from agathodaimon._envelope import EnvelopeError, attach, read_fields
from agathodaimon.network.dhcp.index import DhcpError, DhcpManager

SCHEMA = "caduceus.network.firewall.v1"
DEFAULT_POLICY = Path("/etc/unbound/unbound.conf.d/agathodaimon-child-policy.conf")
DEFAULT_NFT = Path("/etc/nftables.d/caduceus-child-filter.nft")
CHECKCONF = Path("/usr/sbin/unbound-checkconf")
NFT = Path("/usr/sbin/nft")
UNBOUND_CONTROL = Path("/usr/sbin/unbound-control")
SYSTEMCTL = Path("/bin/systemctl")
MAX_INPUT_BYTES = 8192
MAX_FILE_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 131072
MAX_FQDNS = 64
NEW_FILE_MODE = 0o644
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
FQDN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.$")
ACCESS_LINE = re.compile(r'^    access-control-view: ([0-9.]+)/32 "([a-z0-9-]+)"$')
VIEW_NAME = re.compile(r'^    name: "([a-z0-9-]+)"$')
ZONE = re.compile(r'^    local-zone: "([a-z0-9.-]+)" (refuse|transparent)$')
NFT_RULE = re.compile(r"^        ether saddr ([0-9a-f:]{17}) ip saddr ([0-9.]+) (udp|tcp) dport 53 ip daddr != ([0-9.]+) drop$")
LIVE_RULE = re.compile(r"^ether saddr ([0-9a-f:]{17}) ip saddr ([0-9.]+) (udp|tcp) dport 53 ip daddr != ([0-9.]+) drop$")


class FirewallRefused(ValueError):
    pass


class FileInstallFailure(FirewallRefused):
    def __init__(self, signal: str, installed: "FileImage"):
        super().__init__(signal)
        self.installed = installed


@dataclass(frozen=True)
class FileImage:
    exists: bool
    data: bytes
    metadata: os.stat_result | None
    identity: tuple[int, int] | None
    posture: tuple[int, int, int, int, int] | None
    digest: str | None
    xattrs: tuple[tuple[str, bytes], ...]


def _receipt(action: str, ok: bool, changed: bool, message: str,
             revision: str | None, first_missing_signal: str = "none", **extra: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "action": action,
        "ok": ok,
        "changed": changed,
        "message": message,
        "firstMissingSignal": first_missing_signal,
        "revision": revision,
        **extra,
    }


def canonical_mac(value: Any) -> str:
    if not isinstance(value, str):
        raise FirewallRefused("firewall-mac-invalid")
    compact = value.strip().lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", compact):
        compact = ":".join(compact[index:index + 2] for index in range(0, 12, 2))
    if not MAC.fullmatch(compact) or compact in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        raise FirewallRefused("firewall-mac-invalid")
    return compact


def canonical_fqdns(value: Any) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_FQDNS:
        raise FirewallRefused("firewall-hostnames-invalid")
    names: set[str] = set()
    for raw in value:
        if not isinstance(raw, str) or len(raw.encode("utf-8", "ignore")) > 253:
            raise FirewallRefused("firewall-hostname-invalid")
        name = raw.lower().rstrip(".") + "."
        bare = name[:-1]
        if not FQDN.fullmatch(name) or bare == "home.arpa" or bare.endswith(".home.arpa"):
            raise FirewallRefused("firewall-hostname-invalid")
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            pass
        else:
            raise FirewallRefused("firewall-hostname-invalid")
        names.add(name)
    if len(names) > MAX_FQDNS:
        raise FirewallRefused("firewall-hostnames-invalid")
    return sorted(names)


def _admit_private(value: Any, signal: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError) as exc:
        raise FirewallRefused(signal) from exc
    if (not address.is_private or address.is_unspecified or address.is_loopback
            or address.is_link_local or address.is_multicast or int(address) == 0xFFFFFFFF):
        raise FirewallRefused(signal)
    return str(address)


def view_name(mac: str) -> str:
    return "agathodaimon-child-" + mac.replace(":", "")


def _render_unbound(policies: dict[str, dict[str, Any]]) -> bytes:
    if not policies:
        return b""
    lines = ["server:"]
    for mac, policy in sorted(policies.items()):
        lines.append(f'    access-control-view: {policy["ip"]}/32 "{view_name(mac)}"')
    for mac, policy in sorted(policies.items()):
        lines.extend(("view:", f'    name: "{view_name(mac)}"', '    local-zone: "." refuse'))
        lines.extend(f'    local-zone: "{name}" transparent' for name in policy["hostnames"])
    return ("\n".join(lines) + "\n").encode("ascii")


def _parse_unbound(data: bytes) -> dict[str, dict[str, Any]]:
    if not data:
        return {}
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirewallRefused("firewall-unbound-owned-file-invalid") from exc
    if not text.endswith("\n"):
        raise FirewallRefused("firewall-unbound-owned-file-invalid")
    lines = text.splitlines()
    if not lines or lines[0] != "server:":
        raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
    access: dict[str, str] = {}
    cursor = 1
    while cursor < len(lines) and lines[cursor].startswith("    access-control-view:"):
        match = ACCESS_LINE.fullmatch(lines[cursor])
        if not match:
            raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
        ip = _admit_private(match.group(1), "firewall-unbound-owned-file-invalid")
        name = match.group(2)
        prefix = "agathodaimon-child-"
        if not name.startswith(prefix) or len(name) != len(prefix) + 12:
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        mac = canonical_mac(name[len(prefix):])
        if mac in access or name != view_name(mac):
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        access[mac] = ip
        cursor += 1
    parsed: dict[str, dict[str, Any]] = {}
    while cursor < len(lines):
        if lines[cursor] != "view:" or cursor + 2 >= len(lines):
            raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
        name_match = VIEW_NAME.fullmatch(lines[cursor + 1])
        root_match = ZONE.fullmatch(lines[cursor + 2])
        if (name_match is None or root_match is None or root_match.groups() != (".", "refuse")):
            raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
        name = name_match.group(1)
        prefix = "agathodaimon-child-"
        if not name.startswith(prefix) or len(name) != len(prefix) + 12:
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        mac = canonical_mac(name[len(prefix):])
        if mac in parsed or access.get(mac) is None or name != view_name(mac):
            raise FirewallRefused("firewall-unbound-policy-mismatch")
        cursor += 3
        names: list[str] = []
        while cursor < len(lines) and lines[cursor] != "view:":
            zone = ZONE.fullmatch(lines[cursor])
            if zone is None or zone.group(2) != "transparent":
                raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
            hostname = zone.group(1)
            normalized = canonical_fqdns([hostname])
            if normalized[0] != hostname or hostname in names:
                raise FirewallRefused("firewall-unbound-owned-file-invalid")
            names.append(hostname)
            cursor += 1
        if len(names) > MAX_FQDNS:
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        parsed[mac] = {"mac": mac, "ip": access[mac], "hostnames": names}
    if set(parsed) != set(access):
        raise FirewallRefused("firewall-unbound-policy-mismatch")
    for policy in parsed.values():
        policy["hostnames"] = sorted(policy["hostnames"])
    if _render_unbound(parsed) != data:
        raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
    return parsed


def _nft_bytes(policies: dict[str, dict[str, Any]]) -> bytes:
    lines = [
        "table inet caduceus_child_filter {",
        "    chain forward {",
        "        type filter hook forward priority -5; policy accept;",
    ]
    for mac, policy in sorted(policies.items()):
        ip, router = policy["ip"], policy["router"]
        lines.append(f"        ether saddr {mac} ip saddr {ip} udp dport 53 ip daddr != {router} drop")
        lines.append(f"        ether saddr {mac} ip saddr {ip} tcp dport 53 ip daddr != {router} drop")
    lines.extend(("    }", "}"))
    return ("\n".join(lines) + "\n").encode("ascii")


def _nft_inert_bytes(data: bytes) -> bool:
    return all(not line.strip() or line.lstrip().startswith(b"#") for line in data.splitlines())


def _parse_nft(data: bytes) -> dict[str, dict[str, Any]]:
    if _nft_inert_bytes(data):
        return {}
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirewallRefused("firewall-nft-owned-file-invalid") from exc
    if not text.endswith("\n"):
        raise FirewallRefused("firewall-nft-owned-file-invalid")
    lines = text.splitlines()
    if (len(lines) < 5 or lines[:3] != [
            "table inet caduceus_child_filter {", "    chain forward {",
            "        type filter hook forward priority -5; policy accept;",
        ] or lines[-2:] != ["    }", "}"]):
        raise FirewallRefused("firewall-nft-owned-file-foreign-content")
    rules: dict[tuple[str, str], dict[str, Any]] = {}
    protocols: dict[tuple[str, str], set[str]] = {}
    for line in lines[3:-2]:
        match = NFT_RULE.fullmatch(line)
        if match is None:
            raise FirewallRefused("firewall-nft-owned-file-foreign-content")
        mac = canonical_mac(match.group(1))
        ip = _admit_private(match.group(2), "firewall-nft-owned-file-invalid")
        protocol = match.group(3)
        router = _admit_private(match.group(4), "firewall-nft-owned-file-invalid")
        identity = (mac, ip)
        prior = rules.get(identity)
        if prior is not None and prior["router"] != router:
            raise FirewallRefused("firewall-nft-owned-file-invalid")
        rules[identity] = {"mac": mac, "ip": ip, "router": router, "hostnames": []}
        protocols.setdefault(identity, set()).add(protocol)
    if any(values != {"udp", "tcp"} for values in protocols.values()):
        raise FirewallRefused("firewall-nft-owned-file-invalid")
    policies = {mac: value for (mac, _ip), value in rules.items()}
    if len(policies) != len(rules) or _nft_bytes(policies) != data:
        raise FirewallRefused("firewall-nft-owned-file-foreign-content")
    return policies


def _parse_live_nft(text: str) -> dict[str, dict[str, Any]]:
    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise FirewallRefused("firewall-nft-live-readback-invalid")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if (len(lines) < 5 or lines[:3] != [
            "table inet caduceus_child_filter {", "chain forward {",
            "type filter hook forward priority -5; policy accept;",
        ] or lines[-2:] != ["}", "}"]):
        # nft renders priority in its normalized long form on supported versions.
        if (len(lines) < 5 or lines[:2] != ["table inet caduceus_child_filter {", "chain forward {"]
                or lines[2] not in {"type filter hook forward priority -5; policy accept;",
                                    "type filter hook forward priority filter - 5; policy accept;"}
                or lines[-2:] != ["}", "}"]):
            raise FirewallRefused("firewall-nft-live-table-mismatch")
    if lines[2] not in {"type filter hook forward priority -5; policy accept;",
                        "type filter hook forward priority filter - 5; policy accept;"}:
        raise FirewallRefused("firewall-nft-live-hook-mismatch")
    rules: dict[tuple[str, str], dict[str, Any]] = {}
    protocols: dict[tuple[str, str], set[str]] = {}
    seen_rules: set[tuple[str, str, str, str]] = set()
    for line in lines[3:-2]:
        match = LIVE_RULE.fullmatch(line)
        if match is None:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        mac = canonical_mac(match.group(1))
        ip = _admit_private(match.group(2), "firewall-nft-live-rule-mismatch")
        protocol = match.group(3)
        router = _admit_private(match.group(4), "firewall-nft-live-rule-mismatch")
        full_rule = (mac, ip, protocol, router)
        if full_rule in seen_rules:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        seen_rules.add(full_rule)
        identity = (mac, ip)
        prior = rules.get(identity)
        if prior is not None and prior["router"] != router:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        rules[identity] = {"mac": mac, "ip": ip, "router": router, "hostnames": []}
        protocols.setdefault(identity, set()).add(protocol)
    if any(values != {"udp", "tcp"} for values in protocols.values()):
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    result = {mac: value for (mac, _ip), value in rules.items()}
    if len(result) != len(rules):
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    return result


def _expected_nft(policies: dict[str, dict[str, Any]]) -> set[tuple[str, str, str, str]]:
    return {(mac, policy["ip"], proto, policy["router"])
            for mac, policy in policies.items() for proto in ("udp", "tcp")}


def _expected_live_table(image: FileImage) -> bool:
    return image.exists and not _nft_inert_bytes(image.data)


def _unbound_view_missing(output: Any, view: str) -> bool:
    message = f"no view with name: {view}"
    return isinstance(output, str) and output in {message, message + "\n"}


def _run(argv: list[str]) -> tuple[bool, str, str]:
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, "", "firewall-command-unavailable"
    is_view_query = len(argv) == 3 and argv[:2] == [str(UNBOUND_CONTROL), "view_list_local_zones"]
    if is_view_query and _unbound_view_missing(result.stdout, argv[2]):
        return False, result.stdout, "firewall-unbound-live-view-missing"
    if result.returncode == 0:
        return True, result.stdout, "none"
    detail = result.stderr.lower()
    if argv[:4] == [str(NFT), "list", "table", "inet"] and "no such file or directory" in detail:
        return False, result.stdout, "not-found"
    missing_view = re.search(
        r"(?:\b(?:unknown|missing|absent)\s+view\b|\bview\b[^\n]*(?:not\s+found|does\s+not\s+exist|unknown|missing|absent)|\b(?:no\s+such|not\s+found)\b[^\n]*\bview\b)",
        detail,
    )
    if is_view_query and missing_view:
        return False, result.stdout, "firewall-unbound-live-view-missing"
    return False, result.stdout, "firewall-command-refused"


def _validate_unbound(path: Path, runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[bool, str]:
    ok, _output, error = runner([str(CHECKCONF), str(path)])
    return ok, error


def _validate_nft(path: Path, runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[bool, str]:
    ok, _output, error = runner([str(NFT), "-c", "-f", str(path)])
    return ok, error


def _open_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise FirewallRefused("firewall-path-invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for component in path.parts[1:]:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def _lock_parents(paths: Sequence[Path]) -> dict[str, int]:
    result: dict[str, int] = {}
    try:
        for parent in sorted({str(path.parent) for path in paths}):
            fd = _open_directory(Path(parent))
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
            except Exception:
                os.close(fd)
                raise
            result[parent] = fd
        return result
    except Exception:
        for fd in result.values():
            os.close(fd)
        raise


def _file_xattrs(fd: int) -> tuple[tuple[str, bytes], ...]:
    try:
        names = os.listxattr(fd)
        return tuple(sorted((name, os.getxattr(fd, name)) for name in names))
    except OSError as exc:
        if exc.errno in (errno.ENOTSUP, errno.EOPNOTSUPP):
            return ()
        raise FirewallRefused("firewall-file-metadata-readback-failed") from exc


def _snapshot(path: Path, parent_fd: int) -> FileImage:
    name = path.name
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return FileImage(False, b"", None, None, None, None, ())
    except OSError as exc:
        raise FirewallRefused("firewall-file-readback-failed") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise FirewallRefused("firewall-file-not-regular")
    try:
        fd = os.open(name, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    except OSError as exc:
        raise FirewallRefused("firewall-file-open-refused") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or (metadata.st_dev, metadata.st_ino) != (before.st_dev, before.st_ino):
            raise FirewallRefused("firewall-file-identity-changed")
        if metadata.st_size > MAX_FILE_BYTES:
            raise FirewallRefused("firewall-file-too-large")
        blocks: list[bytes] = []
        total = 0
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            total += len(block)
            if total > MAX_FILE_BYTES:
                raise FirewallRefused("firewall-file-too-large")
            blocks.append(block)
        data = b"".join(blocks)
        xattrs = _file_xattrs(fd)
        final_fd = os.fstat(fd)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        before_posture = (metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_size, metadata.st_mtime_ns)
        after_posture = (final_fd.st_mode, final_fd.st_uid, final_fd.st_gid, final_fd.st_size, final_fd.st_mtime_ns)
        if ((after.st_dev, after.st_ino) != (metadata.st_dev, metadata.st_ino)
                or (final_fd.st_dev, final_fd.st_ino) != (metadata.st_dev, metadata.st_ino)
                or stat.S_ISLNK(after.st_mode) or before_posture != after_posture
                or len(data) != final_fd.st_size):
            raise FirewallRefused("firewall-file-identity-changed")
        posture = before_posture
        return FileImage(True, data, metadata, (metadata.st_dev, metadata.st_ino), posture,
                         hashlib.sha256(data).hexdigest(), xattrs)
    finally:
        os.close(fd)


def _same_snapshot(left: FileImage, right: FileImage, *, semantic: bool = False) -> bool:
    if left.exists != right.exists:
        return False
    if not left.exists:
        return True
    if left.digest != right.digest or left.posture != right.posture or left.xattrs != right.xattrs:
        return False
    return semantic or left.identity == right.identity


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("firewall-file-short-write")
        view = view[count:]


def _create_temp(path: Path, parent_fd: int, payload: bytes, metadata: os.stat_result | None,
                 xattrs: tuple[tuple[str, bytes], ...]) -> str:
    if len(payload) > MAX_FILE_BYTES:
        raise FirewallRefused("firewall-file-too-large")
    for _attempt in range(10):
        name = f".{path.name}.firewall-{secrets.token_hex(8)}"
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                         NEW_FILE_MODE, dir_fd=parent_fd)
            break
        except FileExistsError:
            continue
    else:
        raise FirewallRefused("firewall-temp-create-refused")
    try:
        if metadata is not None:
            current = os.fstat(fd)
            if (current.st_uid, current.st_gid) != (metadata.st_uid, metadata.st_gid):
                os.fchown(fd, metadata.st_uid, metadata.st_gid)
            os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
            for key, value in xattrs:
                os.setxattr(fd, key, value)
        else:
            os.fchmod(fd, NEW_FILE_MODE)
        _write_all(fd, payload)
        if metadata is not None:
            os.utime(fd, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
        os.fsync(fd)
    except Exception:
        os.close(fd)
        os.unlink(name, dir_fd=parent_fd)
        raise
    os.close(fd)
    return name


def _temp_path(path: Path, temp_name: str) -> Path:
    return path.parent / temp_name


def _stage_validate(path: Path, parent_fd: int, payload: bytes, source: FileImage,
                    validator: Callable[[Path], tuple[bool, str]]) -> tuple[bool, str]:
    temporary = _create_temp(path, parent_fd, payload, source.metadata, source.xattrs)
    staged_path = _temp_path(path, temporary)
    try:
        return validator(staged_path)
    finally:
        os.unlink(temporary, dir_fd=parent_fd)


def _fsync_parent(parent_fd: int) -> None:
    os.fsync(parent_fd)


def _install(path: Path, parent_fd: int, payload: bytes | None, source: FileImage) -> FileImage:
    current = _snapshot(path, parent_fd)
    if not _same_snapshot(current, source):
        raise FirewallRefused("firewall-file-cas-conflict")
    if payload is None:
        if not source.exists:
            return source
        if not _same_snapshot(_snapshot(path, parent_fd), source):
            raise FirewallRefused("firewall-file-cas-conflict")
        absent = FileImage(False, b"", None, None, None, None, ())
        os.unlink(path.name, dir_fd=parent_fd)
        try:
            _fsync_parent(parent_fd)
        except OSError as exc:
            raise FileInstallFailure("firewall-file-delete-fsync-failed", absent) from exc
        if _snapshot(path, parent_fd).exists:
            raise FileInstallFailure("firewall-file-delete-readback-failed", absent)
        return absent
    temporary = _create_temp(path, parent_fd, payload, source.metadata, source.xattrs)
    staged_image: FileImage | None = None
    renamed = False
    try:
        staged_image = _snapshot(Path(temporary), parent_fd)
        if not _same_snapshot(_snapshot(path, parent_fd), source):
            raise FirewallRefused("firewall-file-cas-conflict")
        if source.exists:
            os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            renamed = True
        else:
            os.link(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            renamed = True
            os.unlink(temporary, dir_fd=parent_fd)
        _fsync_parent(parent_fd)
        installed = _snapshot(path, parent_fd)
        if (not installed.exists or installed.digest != hashlib.sha256(payload).hexdigest()
                or installed.xattrs != staged_image.xattrs or installed.identity != staged_image.identity):
            raise FileInstallFailure("firewall-file-install-readback-failed", staged_image)
        return installed
    except FileInstallFailure:
        raise
    except Exception as exc:
        if renamed and staged_image is not None:
            raise FileInstallFailure("firewall-file-install-readback-failed", staged_image) from exc
        raise
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def _restore(path: Path, parent_fd: int, source: FileImage, installed: FileImage) -> str:
    current = _snapshot(path, parent_fd)
    if not _same_snapshot(current, installed):
        return "refused-identity-content-metadata-changed"
    if not source.exists:
        try:
            os.unlink(path.name, dir_fd=parent_fd)
            _fsync_parent(parent_fd)
        except OSError:
            return "failed"
        return "restored" if not _snapshot(path, parent_fd).exists else "restore-readback-failed"
    assert source.metadata is not None
    temporary = _create_temp(path, parent_fd, source.data, source.metadata, source.xattrs)
    try:
        if not _same_snapshot(_snapshot(path, parent_fd), installed):
            return "refused-identity-content-metadata-changed"
        if current.exists:
            os.replace(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        else:
            os.link(temporary, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
            os.unlink(temporary, dir_fd=parent_fd)
        _fsync_parent(parent_fd)
        restored = _snapshot(path, parent_fd)
        if not _same_snapshot(restored, source, semantic=True):
            return "restore-readback-failed"
        return "restored"
    except Exception:
        return "failed"
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass


def _live_table(runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[bool, str]:
    ok, output, error = runner([str(NFT), "list", "table", "inet", "caduceus_child_filter"])
    if ok:
        if not isinstance(output, str):
            raise FirewallRefused("firewall-nft-live-readback-invalid")
        return True, output
    if error == "not-found":
        return False, ""
    raise FirewallRefused(error if error != "none" else "firewall-nft-live-readback-unavailable")


def _prove_live_nft(policies: dict[str, dict[str, Any]], expected_exists: bool,
                    runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    exists, output = _live_table(runner)
    if exists != expected_exists:
        raise FirewallRefused("firewall-nft-live-table-presence-mismatch")
    if not exists:
        return
    actual = _parse_live_nft(output)
    expected = {(mac, policy["ip"], policy["router"]) for mac, policy in policies.items()}
    observed = {(mac, policy["ip"], policy["router"]) for mac, policy in actual.items()}
    if observed != expected:
        raise FirewallRefused("firewall-nft-live-policy-mismatch")


def _valid_unbound_zone_name(name: str) -> bool:
    if name == ".":
        return True
    bare = name[:-1] if name.endswith(".") else name
    if not bare or len(bare) > 253:
        return False
    return all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) is not None
        for label in bare.split(".")
    )


def _prove_live_dns(mac: str, hostnames: list[str], runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    requested_view = view_name(mac)
    ok, output, error = runner([str(UNBOUND_CONTROL), "view_list_local_zones", requested_view])
    if _unbound_view_missing(output, requested_view):
        raise FirewallRefused("firewall-unbound-live-view-missing")
    if not ok:
        raise FirewallRefused(error if error != "none" else "firewall-unbound-live-readback-unavailable")
    if not isinstance(output, str) or len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise FirewallRefused("firewall-unbound-live-readback-invalid")
    zones: set[tuple[str, str]] = set()
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'^\s*(?:local-zone:\s*)?(?:"([^"\s]+)"|([^\s"]+))\s+([a-z][a-z0-9_-]*)\s*$', line)
        if match is None:
            raise FirewallRefused("firewall-unbound-live-readback-invalid")
        name = match.group(1) or match.group(2)
        kind = match.group(3)
        if not _valid_unbound_zone_name(name):
            raise FirewallRefused("firewall-unbound-live-readback-invalid")
        name = name.lower()
        if kind not in {"refuse", "transparent"}:
            continue
        pair = (name, kind)
        if pair in zones:
            raise FirewallRefused("firewall-unbound-live-readback-invalid")
        zones.add(pair)
    expected = {(".", "refuse"), *((name, "transparent") for name in hostnames)}
    if zones != expected:
        raise FirewallRefused("firewall-unbound-live-zone-mismatch")


def _prove_live_dns_absent(mac: str, runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    requested_view = view_name(mac)
    ok, output, error = runner([str(UNBOUND_CONTROL), "view_list_local_zones", requested_view])
    if _unbound_view_missing(output, requested_view):
        return
    if ok:
        raise FirewallRefused("firewall-unbound-live-view-extra")
    if error != "firewall-unbound-live-view-missing":
        raise FirewallRefused("firewall-unbound-live-view-absence-unproven")


def _revision(policy: FileImage, nft: FileImage) -> str:
    digest = hashlib.sha256()
    for image in (policy, nft):
        digest.update(b"present\0" if image.exists else b"absent\0")
        payload = image.data if image.exists else b""
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _dhcp_manager(factory: Any) -> Any:
    if not isinstance(factory, type) and hasattr(factory, "get_leases"):
        return factory
    if not callable(factory):
        raise FirewallRefused("firewall-dhcp-manager-unavailable")
    try:
        return factory()
    except Exception as exc:
        raise FirewallRefused("firewall-dhcp-manager-unavailable") from exc


def _get_reservations(manager: Any) -> list[dict[str, Any]]:
    try:
        values = manager.get_reservations()
    except (DhcpError, OSError, ValueError, TypeError) as exc:
        raise FirewallRefused("firewall-dhcp-reservation-readback-unavailable") from exc
    if not isinstance(values, list) or any(not isinstance(row, dict) for row in values):
        raise FirewallRefused("firewall-dhcp-reservation-readback-invalid")
    return values


def _reservation_rows(manager: Any) -> dict[str, list[dict[str, str]]]:
    rows: dict[str, list[dict[str, str]]] = {}
    for item in _get_reservations(manager):
        try:
            mac = canonical_mac(item.get("hw-address"))
        except FirewallRefused:
            continue
        ip = _admit_private(item.get("ip-address"), "firewall-dhcp-reservation-invalid")
        rows.setdefault(mac, []).append({"ip": ip, "hostname": str(item.get("hostname", ""))})
    return rows


def _router_for_ip(manager: Any, ip: str) -> str:
    try:
        config = manager.get_config()
    except (DhcpError, OSError, ValueError, TypeError) as exc:
        raise FirewallRefused("firewall-dhcp-config-readback-unavailable") from exc
    dhcp = config.get("Dhcp4", config) if isinstance(config, dict) else None
    subnets = dhcp.get("subnet4") if isinstance(dhcp, dict) else None
    if not isinstance(subnets, list):
        raise FirewallRefused("firewall-dhcp-subnets-invalid")
    address = ipaddress.IPv4Address(ip)
    matches: list[str] = []
    for subnet in subnets:
        if not isinstance(subnet, dict) or not isinstance(subnet.get("subnet"), str):
            raise FirewallRefused("firewall-dhcp-subnets-invalid")
        try:
            network = ipaddress.IPv4Network(subnet["subnet"], strict=False)
        except ValueError as exc:
            raise FirewallRefused("firewall-dhcp-subnets-invalid") from exc
        if address not in network:
            continue
        options = subnet.get("option-data", [])
        if not isinstance(options, list):
            raise FirewallRefused("firewall-dhcp-router-invalid")
        found = [value.get("data") for value in options
                 if isinstance(value, dict) and value.get("name") == "routers"]
        if len(found) != 1 or not isinstance(found[0], str):
            raise FirewallRefused("firewall-dhcp-router-ambiguous")
        routers = [part.strip() for part in found[0].split(",") if part.strip()]
        if len(routers) != 1:
            raise FirewallRefused("firewall-dhcp-router-ambiguous")
        router = _admit_private(routers[0], "firewall-dhcp-router-invalid")
        if ipaddress.IPv4Address(router) not in network:
            raise FirewallRefused("firewall-dhcp-router-invalid")
        matches.append(router)
    if len(matches) != 1:
        raise FirewallRefused("firewall-dhcp-router-ambiguous")
    return matches[0]


def _bind_policies(policies: dict[str, dict[str, Any]], manager: Any) -> dict[str, dict[str, Any]]:
    reservations = _reservation_rows(manager)
    bound: dict[str, dict[str, Any]] = {}
    for mac, policy in policies.items():
        rows = reservations.get(mac, [])
        if len(rows) != 1 or rows[0]["ip"] != policy["ip"]:
            raise FirewallRefused("firewall-dhcp-binding-mismatch")
        bound[mac] = {**policy, "router": _router_for_ip(manager, policy["ip"])}
    return bound


def _lease_rows(manager: Any) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    try:
        values = manager.get_leases()
    except (DhcpError, OSError, ValueError, TypeError) as exc:
        raise FirewallRefused("firewall-dhcp-leases-unavailable") from exc
    if not isinstance(values, list):
        raise FirewallRefused("firewall-dhcp-leases-invalid")
    observed: list[dict[str, Any]] = []
    leases: dict[str, dict[str, str]] = {}
    for item in values:
        if not isinstance(item, dict):
            continue
        lease_ip = item.get("ip-address")
        if not isinstance(lease_ip, str) or not lease_ip.strip():
            continue
        try:
            mac = canonical_mac(item.get("hw-address"))
            address = str(ipaddress.ip_address(lease_ip))
        except (FirewallRefused, ValueError, TypeError):
            continue
        hostname = item.get("hostname")
        hostname = hostname if isinstance(hostname, str) and hostname else None
        observed.append({"mac": mac, "ip": address, "hostname": hostname})
        prior = leases.get(mac)
        if prior is not None and prior["ip"] != address:
            raise FirewallRefused("firewall-dhcp-lease-ambiguous")
        leases[mac] = {"ip": address, "hostname": hostname or ""}
    return observed, leases


def _neighbor_rows(runner: Callable[[list[str]], tuple[bool, str, str]]) -> list[dict[str, str]]:
    ok, output, error = runner(["ip", "-j", "neigh", "show"])
    if not ok:
        raise FirewallRefused(error if error != "none" else "firewall-neighbor-readback-unavailable")
    if not isinstance(output, str) or len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise FirewallRefused("firewall-neighbor-readback-invalid")
    try:
        values = json.loads(output)
    except (json.JSONDecodeError, TypeError) as exc:
        raise FirewallRefused("firewall-neighbor-readback-invalid") from exc
    if not isinstance(values, list):
        raise FirewallRefused("firewall-neighbor-readback-invalid")
    result: list[dict[str, str]] = []
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("lladdr"), str) or not isinstance(item.get("dst"), str):
            continue
        try:
            result.append({"mac": canonical_mac(item["lladdr"]), "ip": str(ipaddress.ip_address(item["dst"]))})
        except (FirewallRefused, ValueError):
            continue
    return result


def _observed_projection(manager: Any, policies: dict[str, dict[str, Any]],
                         runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    lease_observed, leases = _lease_rows(manager)
    merged: dict[str, dict[str, Any]] = {}
    for item in lease_observed + _neighbor_rows(runner):
        prior = merged.setdefault(item["mac"], {"mac": item["mac"], "ip": None, "hostname": None})
        for field in ("ip", "hostname"):
            if item.get(field):
                prior[field] = item[field]
    rows = [{**value, "registered": mac in policies} for mac, value in sorted(merged.items())]
    return rows, leases


def _enforcement(mac: str, policy: dict[str, Any], leases: dict[str, dict[str, str]]) -> str:
    lease = leases.get(mac)
    return "pending-renewal" if lease is not None and lease["ip"] != policy["ip"] else "applied"


def _validate_intent(intent: Any) -> tuple[str, str | None, list[str] | None, str | None]:
    if not isinstance(intent, dict):
        raise FirewallRefused("firewall-intent-invalid")
    action = intent.get("action")
    if not isinstance(action, str) or action not in {
            "observed", "list", "register", "unregister", "whitelist-get", "whitelist-set"}:
        raise FirewallRefused("firewall-action-invalid")
    keys = set(intent)
    if action in {"observed", "list"}:
        if keys & {"mac", "hostnames", "revision"}:
            raise FirewallRefused("firewall-intent-shape-invalid")
        return action, None, None, None
    if action == "whitelist-get":
        if "hostnames" in keys or "revision" in keys:
            raise FirewallRefused("firewall-intent-shape-invalid")
    elif action in {"register", "unregister"}:
        if "hostnames" in keys:
            raise FirewallRefused("firewall-intent-shape-invalid")
    elif action == "whitelist-set":
        if "revision" not in keys or "hostnames" not in keys:
            raise FirewallRefused("firewall-intent-shape-invalid")
    mac = canonical_mac(intent.get("mac"))
    names = canonical_fqdns(intent["hostnames"]) if action == "whitelist-set" else None
    revision = intent.get("revision") if "revision" in keys else None
    if "revision" in keys and (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision)):
        raise FirewallRefused("firewall-revision-invalid")
    if action == "whitelist-set" and revision is None:
        raise FirewallRefused("firewall-revision-invalid")
    return action, mac, names, revision


def _live_state(policies: dict[str, dict[str, Any]], expected_table: bool,
                runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    _prove_live_nft(policies, expected_table, runner)
    for mac, policy in policies.items():
        _prove_live_dns(mac, policy["hostnames"], runner)


def _read_images(policy_path: Path, nft_path: Path, parents: dict[str, int]) -> tuple[FileImage, FileImage, dict[str, dict[str, Any]], str]:
    policy_image = _snapshot(policy_path, parents[str(policy_path.parent)])
    nft_image = _snapshot(nft_path, parents[str(nft_path.parent)])
    policies = _parse_unbound(policy_image.data if policy_image.exists else b"")
    nft_policies = _parse_nft(nft_image.data) if nft_image.exists else {}
    expected = {(mac, item["ip"]) for mac, item in policies.items()}
    actual = {(mac, item["ip"]) for mac, item in nft_policies.items()}
    if expected != actual:
        raise FirewallRefused("firewall-owned-policy-mismatch")
    return policy_image, nft_image, policies, _revision(policy_image, nft_image)


def _stage_and_check(policy_path: Path, nft_path: Path, policy_parent: int, nft_parent: int,
                     policy_source: FileImage, nft_source: FileImage, policy_candidate: bytes | None,
                     nft_candidate: bytes, runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    candidate_unbound = policy_candidate if policy_candidate is not None else b""
    valid, error = _stage_validate(
        policy_path, policy_parent, candidate_unbound, policy_source,
        lambda staged: _validate_unbound(staged, runner),
    )
    if not valid:
        raise FirewallRefused(error if error != "none" else "firewall-unbound-validator-refused")
    valid, error = _stage_validate(
        nft_path, nft_parent, nft_candidate, nft_source,
        lambda staged: _validate_nft(staged, runner),
    )
    if not valid:
        raise FirewallRefused(error if error != "none" else "firewall-nft-validator-refused")


def _apply_transaction(action: str, policy_path: Path, nft_path: Path, parents: dict[str, int],
                       policy_source: FileImage, nft_source: FileImage,
                       old_policies: dict[str, dict[str, Any]], policy_candidate: bytes | None,
                       nft_candidate: bytes, new_policies: dict[str, dict[str, Any]],
                       runner: Callable[[list[str]], tuple[bool, str, str]],
                       removed_mac: str | None = None) -> dict[str, Any]:
    policy_parent, nft_parent = parents[str(policy_path.parent)], parents[str(nft_path.parent)]
    expected_table = _expected_live_table(nft_source)
    _stage_and_check(policy_path, nft_path, policy_parent, nft_parent, policy_source, nft_source,
                     policy_candidate, nft_candidate, runner)
    want_policy = policy_candidate is not None
    policy_same = policy_source.exists == want_policy and (not want_policy or policy_source.data == policy_candidate)
    nft_same = nft_source.exists and nft_source.data == nft_candidate
    if policy_same and nft_same:
        _live_state(new_policies, expected_table, runner)
        return {"ok": True, "changed": False, "revision": _revision(policy_source, nft_source),
                "rollback": "not-needed", "rollbackFiles": []}

    initial_live_exists, initial_live_text = _live_table(runner)
    if initial_live_exists != expected_table:
        raise FirewallRefused("firewall-nft-live-table-presence-mismatch")
    if initial_live_exists:
        _prove_live_nft(old_policies, True, runner)
    old_live_policies = _parse_nft(nft_source.data) if nft_source.exists else {}
    installed: list[tuple[Path, int, FileImage, FileImage]] = []
    policy_installed = False
    nft_installed = False
    live_changed = False
    reload_attempted = False
    try:
        if not policy_same:
            try:
                image = _install(policy_path, policy_parent, policy_candidate, policy_source)
            except FileInstallFailure as exc:
                installed.append((policy_path, policy_parent, policy_source, exc.installed))
                policy_installed = True
                raise
            installed.append((policy_path, policy_parent, policy_source, image))
            policy_installed = True
        if not nft_same:
            try:
                image = _install(nft_path, nft_parent, nft_candidate, nft_source)
            except FileInstallFailure as exc:
                installed.append((nft_path, nft_parent, nft_source, exc.installed))
                nft_installed = True
                raise
            installed.append((nft_path, nft_parent, nft_source, image))
            nft_installed = True
        batch = ((b"delete table inet caduceus_child_filter\n" if initial_live_exists else b"")
                 + nft_candidate)
        staged_name = _create_temp(nft_path, nft_parent, batch, nft_source.metadata, nft_source.xattrs)
        try:
            ok, _output, error = runner([str(NFT), "-f", str(_temp_path(nft_path, staged_name))])
        finally:
            os.unlink(staged_name, dir_fd=nft_parent)
        if not ok:
            raise FirewallRefused(error if error != "none" else "firewall-nft-apply-refused")
        live_changed = True
        if policy_installed:
            ok, _output, error = runner([str(SYSTEMCTL), "reload", "unbound"])
            reload_attempted = True
            if not ok:
                raise FirewallRefused(error if error != "none" else "firewall-unbound-reload-refused")

        final_policy = _snapshot(policy_path, policy_parent)
        final_nft = _snapshot(nft_path, nft_parent)
        if (not final_nft.exists or final_nft.data != nft_candidate
                or (policy_candidate is None and final_policy.exists)
                or (policy_candidate is not None and (not final_policy.exists or final_policy.data != policy_candidate))):
            raise FirewallRefused("firewall-installed-readback-mismatch")
        if final_policy.exists:
            valid, error = _validate_unbound(policy_path, runner)
            if not valid:
                raise FirewallRefused(error if error != "none" else "firewall-unbound-installed-validator-refused")
        valid, error = _validate_nft(nft_path, runner)
        if not valid:
            raise FirewallRefused(error if error != "none" else "firewall-nft-installed-validator-refused")
        _live_state(new_policies, True, runner)
        if removed_mac is not None:
            _prove_live_dns_absent(removed_mac, runner)
        new_revision = _revision(final_policy, final_nft)
        return {"ok": True, "changed": True, "revision": new_revision,
                "rollback": "not-needed", "rollbackFiles": []}
    except Exception as exc:
        file_results: list[dict[str, str]] = []
        for path, parent, source, installed_image in reversed(installed):
            file_results.append({"path": str(path), "state": _restore(path, parent, source, installed_image)})
        live_ok = not live_changed
        try:
            current_exists, current_text = _live_table(runner)
            current_is_candidate = False
            if current_exists:
                current = _parse_live_nft(current_text)
                current_keys = {(mac, item["ip"], item["router"]) for mac, item in current.items()}
                candidate_keys = {(mac, item["ip"], item["router"]) for mac, item in new_policies.items()}
                old_keys = {(mac, item["ip"], item["router"]) for mac, item in old_live_policies.items()}
                current_is_candidate = current_keys == candidate_keys
                current_is_old = current_keys == old_keys
            else:
                current_is_old = not initial_live_exists
            if current_is_old:
                live_ok = True
            elif current_is_candidate:
                if initial_live_exists:
                    rollback_batch = b"delete table inet caduceus_child_filter\n" + nft_source.data
                    staged_name = _create_temp(nft_path, nft_parent, rollback_batch, nft_source.metadata, nft_source.xattrs)
                    try:
                        live_ok, _output, _error = runner([str(NFT), "-f", str(_temp_path(nft_path, staged_name))])
                    finally:
                        os.unlink(staged_name, dir_fd=nft_parent)
                    if live_ok:
                        _prove_live_nft(old_live_policies, True, runner)
                else:
                    staged_name = _create_temp(nft_path, nft_parent, b"delete table inet caduceus_child_filter\n",
                                               nft_source.metadata, nft_source.xattrs)
                    try:
                        live_ok, _output, error = runner([str(NFT), "-f", str(_temp_path(nft_path, staged_name))])
                        if not live_ok and error == "not-found":
                            live_ok = True
                    finally:
                        os.unlink(staged_name, dir_fd=nft_parent)
                    if live_ok:
                        exists_after, _ = _live_table(runner)
                        live_ok = not exists_after
            else:
                live_ok = False
        except Exception:
            live_ok = False
        if policy_installed or reload_attempted:
            try:
                reload_ok, _output, _error = runner([str(SYSTEMCTL), "reload", "unbound"])
                rollback_reload = bool(reload_ok)
            except Exception:
                rollback_reload = False
        else:
            rollback_reload = True
        rollback_dns = bool(rollback_reload)
        if rollback_dns:
            try:
                for old_mac, old_policy in old_policies.items():
                    _prove_live_dns(old_mac, old_policy["hostnames"], runner)
                for added_mac in sorted(set(new_policies) - set(old_policies)):
                    _prove_live_dns_absent(added_mac, runner)
            except Exception:
                rollback_dns = False
        rollback_complete = (all(value["state"] == "restored" for value in file_results)
                             and live_ok and rollback_reload and rollback_dns)
        try:
            final_policy = _snapshot(policy_path, policy_parent)
            final_nft = _snapshot(nft_path, nft_parent)
            final_revision = _revision(final_policy, final_nft)
        except Exception:
            rollback_complete = False
            final_revision = None
        return {
            "ok": False,
            "changed": not rollback_complete,
            "revision": final_revision,
            "rollback": "restored" if rollback_complete else "failed",
            "rollbackFiles": file_results,
            "rollbackLiveNft": live_ok,
            "rollbackUnboundReload": rollback_reload,
            "rollbackDnsReadback": rollback_dns,
            "firstMissingSignal": str(exc) if isinstance(exc, FirewallRefused) else "firewall-transaction-failed",
        }


def _enforce_readback(policy_path: Path, nft_path: Path, policy_image: FileImage, nft_image: FileImage,
                      policies: dict[str, dict[str, Any]], revision: str, manager_factory: Any,
                      runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[Any | None, dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    expected_table = _expected_live_table(nft_image)
    if not policies:
        _live_state({}, expected_table, runner)
        return None, {}, {}
    manager = _dhcp_manager(manager_factory)
    bound = _bind_policies(policies, manager)
    disk_nft = _parse_nft(nft_image.data) if nft_image.exists else {}
    if any(disk_nft[mac]["router"] != policy["router"] for mac, policy in bound.items()):
        raise FirewallRefused("firewall-dhcp-router-binding-mismatch")
    _live_state(bound, expected_table, runner)
    _observed, leases = _lease_rows(manager)
    return manager, bound, leases


def _reservation_for(manager: Any, mac: str) -> tuple[str | None, bool, str | None]:
    rows = _reservation_rows(manager).get(mac, [])
    if len(rows) > 1:
        raise FirewallRefused("firewall-dhcp-reservation-ambiguous")
    if rows:
        return rows[0]["ip"], False, None
    created = False
    returned_ip: str | None = None
    try:
        result = manager.add_reservation(mac)
        created = True
        if isinstance(result, dict) and result.get("ip-address") is not None:
            returned_ip = _admit_private(result.get("ip-address"), "firewall-dhcp-reservation-invalid")
    except (DhcpError, OSError, ValueError, TypeError) as exc:
        # update_config can complete its atomic updater before a later readback
        # fails, so inspect the native reservation door before reporting state.
        try:
            after = _reservation_rows(manager).get(mac, [])
        except FirewallRefused:
            after = []
        if len(after) == 1:
            return after[0]["ip"], True, "firewall-dhcp-reservation-update-readback-failed"
        return None, False, "firewall-dhcp-reservation-update-failed"
    try:
        after = _reservation_rows(manager).get(mac, [])
    except FirewallRefused:
        return returned_ip, created, "firewall-dhcp-reservation-readback-unavailable"
    if len(after) != 1:
        return returned_ip, created, "firewall-dhcp-reservation-readback-mismatch"
    if returned_ip is not None and after[0]["ip"] != returned_ip:
        return after[0]["ip"], created, "firewall-dhcp-reservation-readback-mismatch"
    return after[0]["ip"], created, None


def dispatch(intent: Any, *, policy_path: Path = DEFAULT_POLICY, nft_path: Path = DEFAULT_NFT,
             runner: Callable[[list[str]], tuple[bool, str, str]] = _run,
             dhcp_manager_factory: Any = DhcpManager) -> dict[str, Any]:
    action = intent.get("action") if isinstance(intent, dict) else "invalid"
    mac: str | None = None
    bound: dict[str, dict[str, Any]] = {}
    leases: dict[str, dict[str, str]] | None = None
    created = False
    pinned_ip: str | None = None
    revision: str | None = None
    try:
        action, mac, hostnames, supplied_revision = _validate_intent(intent)
        policy_path, nft_path = Path(policy_path), Path(nft_path)
        if policy_path.name != "agathodaimon-child-policy.conf" or nft_path.name != "caduceus-child-filter.nft":
            # Scratch paths may change parents, but the owned basenames remain exact.
            raise FirewallRefused("firewall-owned-path-invalid")
        parents = _lock_parents([policy_path, nft_path])
        try:
            policy_image, nft_image, policies, revision = _read_images(policy_path, nft_path, parents)
            manager, bound, leases = _enforce_readback(
                policy_path, nft_path, policy_image, nft_image, policies,
                revision, dhcp_manager_factory, runner,
            )
            if action == "register" and mac in bound:
                pinned_ip = bound[mac]["ip"]
            if action in {"observed", "list"}:
                manager = manager or _dhcp_manager(dhcp_manager_factory)
                if action == "observed":
                    rows, observed_leases = _observed_projection(manager, policies, runner)
                    for row in rows:
                        item_mac = row["mac"]
                        if item_mac in bound:
                            row["enforcement"] = _enforcement(item_mac, bound[item_mac], observed_leases)
                    return _receipt(action, True, False, "Observed current leases and neighbors.", revision,
                                    observed=rows, count=len(rows))
                rows = [{
                    "mac": item_mac,
                    "ip": bound[item_mac]["ip"],
                    "hostnames": list(bound[item_mac]["hostnames"]),
                    "revision": revision,
                    "enforcement": _enforcement(item_mac, bound[item_mac], leases),
                } for item_mac in sorted(bound)]
                return _receipt(action, True, False, "Registered firewall children.", revision, children=rows)

            assert mac is not None
            if supplied_revision is not None and supplied_revision != revision:
                raise FirewallRefused("firewall-revision-conflict")
            if action == "whitelist-set" and supplied_revision != revision:
                raise FirewallRefused("firewall-revision-conflict")
            if action == "whitelist-get":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                policy = bound[mac]
                return _receipt(action, True, False, "Read the registered child whitelist.", revision,
                                mac=mac, hostnames=list(policy["hostnames"]),
                                enforcement=_enforcement(mac, policy, leases))

            if action == "register":
                manager = manager or _dhcp_manager(dhcp_manager_factory)
                observed, leases = _observed_projection(manager, policies, runner)
                if mac not in {row["mac"] for row in observed}:
                    raise FirewallRefused("firewall-mac-not-observed")
                if mac in bound:
                    pinned_ip = bound[mac]["ip"]
                    candidate = {key: dict(value) for key, value in bound.items()}
                    selected = candidate[mac]
                else:
                    pinned_ip, created, reservation_error = _reservation_for(manager, mac)
                    if reservation_error:
                        extra = {"pinned": {"ip": pinned_ip, "created": created}, "mac": mac}
                        if pinned_ip is not None:
                            extra["enforcement"] = _enforcement(mac, {"ip": pinned_ip}, leases)
                        receipt = _receipt(action, False, created, "Reservation readback failed.", revision,
                                           reservation_error, **extra)
                        return receipt
                    if pinned_ip is None:
                        raise FirewallRefused("firewall-dhcp-reservation-readback-mismatch")
                    candidate = {key: dict(value) for key, value in bound.items()}
                    candidate[mac] = {"mac": mac, "ip": pinned_ip, "router": _router_for_ip(manager, pinned_ip),
                                      "hostnames": []}
                    selected = candidate[mac]
                candidate_unbound = _render_unbound(candidate) if candidate else None
                candidate_nft = _nft_bytes(candidate)
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, candidate_nft, candidate, runner)
                if not transaction["ok"]:
                    enforcement = (_enforcement(mac, bound[mac], leases) if mac in bound else
                                   ("pending-renewal" if mac in leases and mac in candidate
                                    and leases[mac]["ip"] != candidate[mac]["ip"] else "applied"))
                    return _receipt(action, False, bool(transaction["changed"] or created),
                                    "Firewall registration did not converge.",
                                    transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                    pinned={"ip": pinned_ip, "created": created}, mac=mac, enforcement=enforcement,
                                    rollback=transaction.get("rollback", "failed"),
                                    **{key: value for key, value in transaction.items()
                                       if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})
                try:
                    _final_leases_observed, final_leases = _lease_rows(manager)
                except FirewallRefused as exc:
                    return _receipt(action, False, bool(transaction["changed"] or created),
                                    "Firewall installed; lease enforcement readback is unavailable.",
                                    transaction.get("revision", revision), str(exc),
                                    pinned={"ip": pinned_ip, "created": created}, mac=mac,
                                    rollback=transaction.get("rollback", "not-needed"))
                enforcement = _enforcement(mac, candidate[mac], final_leases)
                signal = transaction.get("firstMissingSignal", "none")
                ok = bool(transaction["ok"])
                pending_message = enforcement == "pending-renewal"
                message = ("Firewall filter takes-hold-on-renewal when the device renews its lease."
                           if pending_message else "Child firewall registration is applied.")
                return _receipt(action, ok, bool(transaction["changed"] or created), message,
                                transaction.get("revision", revision), signal,
                                pinned={"ip": pinned_ip, "created": created}, mac=mac, enforcement=enforcement,
                                rollback=transaction.get("rollback", "not-needed"),
                                **{key: value for key, value in transaction.items()
                                   if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})

            if action == "unregister":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                enforcement = _enforcement(mac, bound[mac], leases)
                candidate = {key: dict(value) for key, value in bound.items() if key != mac}
                candidate_unbound = _render_unbound(candidate) if candidate else None
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, _nft_bytes(candidate), candidate, runner,
                                                 removed_mac=mac)
                return _receipt(action, bool(transaction["ok"]), bool(transaction["changed"]),
                                "Child firewall registration removed; DHCP reservation retained.",
                                transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                mac=mac, enforcement=enforcement, rollback=transaction.get("rollback", "not-needed"),
                                **{key: value for key, value in transaction.items()
                                   if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})

            if action == "whitelist-set":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                candidate = {key: dict(value) for key, value in bound.items()}
                candidate[mac]["hostnames"] = list(hostnames or [])
                candidate_unbound = _render_unbound(candidate) if candidate else None
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, _nft_bytes(candidate), candidate, runner)
                if not transaction["ok"]:
                    rollback_state = transaction.get("rollback", "failed")
                    fields = ({"hostnames": list(bound[mac]["hostnames"])} if rollback_state == "restored"
                              else {"attemptedHostnames": list(candidate[mac]["hostnames"])})
                    return _receipt(action, False, bool(transaction["changed"]), "Child whitelist update did not converge.",
                                    transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                    mac=mac, **fields,
                                    enforcement=_enforcement(mac, candidate[mac], leases),
                                    rollback=transaction.get("rollback", "failed"),
                                    **{key: value for key, value in transaction.items()
                                       if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})
                try:
                    _observed_leases, final_leases = _lease_rows(manager)
                except FirewallRefused as exc:
                    return _receipt(action, False, bool(transaction["changed"]),
                                    "Whitelist installed; lease enforcement readback is unavailable.",
                                    transaction.get("revision", revision), str(exc), mac=mac,
                                    hostnames=list(candidate[mac]["hostnames"]),
                                    rollback=transaction.get("rollback", "not-needed"))
                enforcement = _enforcement(mac, candidate[mac], final_leases)
                return _receipt(action, bool(transaction["ok"]), bool(transaction["changed"]),
                                "Child whitelist updated.", transaction.get("revision", revision),
                                transaction.get("firstMissingSignal", "none"), mac=mac,
                                hostnames=list(candidate[mac]["hostnames"]), enforcement=enforcement,
                                rollback=transaction.get("rollback", "not-needed"),
                                **{key: value for key, value in transaction.items()
                                   if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})
            raise FirewallRefused("firewall-action-invalid")
        finally:
            for fd in reversed(list(parents.values())):
                os.close(fd)
    except Exception as exc:
        if isinstance(exc, FirewallRefused):
            signal = str(exc)
        elif isinstance(exc, (OSError, DhcpError, EnvelopeError)):
            signal = "firewall-operation-unavailable"
        else:
            signal = "firewall-operation-failed"
        extra: dict[str, Any] = {"rollback": "not-needed"}
        if mac is not None:
            extra["mac"] = mac
            if mac in bound and leases is not None:
                extra["enforcement"] = _enforcement(mac, bound[mac], leases)
        if action == "register":
            extra["pinned"] = {"ip": pinned_ip, "created": created}
        return _receipt(action if isinstance(action, str) else "invalid", False, created,
                        "Firewall request refused.", revision, signal, **extra)


def main(argv: Sequence[str] | None = None, *, policy_path: Path = DEFAULT_POLICY,
         nft_path: Path = DEFAULT_NFT,
         runner: Callable[[list[str]], tuple[bool, str, str]] = _run,
         dhcp_manager_factory: Any = DhcpManager) -> int:
    del argv
    try:
        request = read_fields("action", "mac", "hostnames", "revision")
    except EnvelopeError as exc:
        value = _receipt("invalid", False, False, "Firewall envelope refused.", None, str(exc))
        print(json.dumps(value, separators=(",", ":"), sort_keys=True))
        return 1
    if len(request.raw_envelope.encode("utf-8")) > MAX_INPUT_BYTES:
        value = _receipt("invalid", False, False, "Firewall input refused.", None, "firewall-input-too-large")
    else:
        value = dispatch(request.payload, policy_path=policy_path, nft_path=nft_path,
                         runner=runner, dhcp_manager_factory=dhcp_manager_factory)
    value = attach(value, request)
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))
    return 0 if value.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

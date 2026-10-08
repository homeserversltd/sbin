"""Shared runtime for the additive Transmission staff sequence."""
from __future__ import annotations

import base64
import fcntl
import importlib.util
import io
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from agathodaimon._envelope import EnvelopeError, attach as attach_envelope, read as read_envelope

SCHEMA_UP = "caduceus.transmission.up.v1"
SCHEMA_DOWN = "caduceus.transmission.down.v1"
SCHEMA_STATUS = "caduceus.transmission.status.v1"
SCHEMA_HOLD = "caduceus.transmission.vpn.hold.v1"
MAX_INPUT = 65536
VPN_NAMESPACE = "vpn"
HOST_VETH = "veth0"
NS_VETH = "veth1"
HOST_ADDRESS = "192.168.2.1/24"
NS_ADDRESS = "192.168.2.2/24"
NS_GATEWAY = "192.168.2.1"
NS_ADDRESS_ONLY = "192.168.2.2"
DNS_PATH = "/etc/netns/vpn/resolv.conf"
CONFIG_PATH = "/etc/appliance/config.json"
HOLD_UNIT = "hold-port-forward@{}.service"
DAEMON_UNIT = "transmission-vpn@{}.service"
STATE_DIR = "/run/agathodaimon/transmission"
KEYMAN = "/vault/keyman/keyman"
EXCHANGE_DIR = "/mnt/keyexchange"
KEY_LOCK = "/run/lock/agathodaimon-transmission-keyman-export.lock"
IP = "/usr/sbin/ip"
SYSTEMCTL = "/usr/bin/systemctl"
SYSCTL = "/usr/sbin/sysctl"
NFT = "/usr/sbin/nft"
CURL = "/usr/bin/curl"
_PROVIDER_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")
_PORT_RE = re.compile(r"^[1-9][0-9]{0,4}$")


class TransmissionError(Exception):
    def __init__(self, signal_name: str, step: str, detail: Mapping[str, Any] | None = None):
        super().__init__(signal_name)
        self.signal_name = signal_name
        self.step = step
        self.detail = dict(detail or {})


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _scratch_root() -> Path | None:
    raw = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    if raw is None:
        return None
    if (not raw or not os.path.isabs(raw) or raw == "/" or "\x00" in raw
            or any(part in {".", ".."} for part in raw.split("/") if part)):
        raise TransmissionError("transmission-scratch-root-invalid", "scratch-root")
    root = Path(raw)
    try:
        resolved = root.resolve(strict=False)
        resolved.relative_to(root.resolve(strict=False))
        info = os.stat(root)
    except FileNotFoundError:
        return root
    except (OSError, RuntimeError, ValueError):
        raise TransmissionError("transmission-scratch-root-invalid", "scratch-root") from None
    if not stat.S_ISDIR(info.st_mode):
        raise TransmissionError("transmission-scratch-root-invalid", "scratch-root")
    return resolved


def runtime_path(path: str) -> Path:
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or "\x00" in path or os.path.normpath(path) != path
            or any(part in {".", ".."} for part in path.split("/") if part)):
        raise TransmissionError("transmission-runtime-path-invalid", "runtime-path")
    root = _scratch_root()
    if root is None:
        return Path(path)
    mapped = root.joinpath(*Path(path).parts[1:])
    try:
        mapped.resolve(strict=False).relative_to(root)
    except (OSError, RuntimeError, ValueError):
        raise TransmissionError("transmission-scratch-path-escape", "runtime-path") from None
    return mapped


def command_argv(argv: list[str] | tuple[str, ...]) -> list[str]:
    if not argv or not isinstance(argv[0], str) or not argv[0]:
        raise TransmissionError("transmission-command-invalid", "command")
    values = list(argv)
    root = _scratch_root()
    if root is None:
        return values
    executable_indexes = [0]
    # ip netns exec starts another binary; resolve that binary in the same fake root.
    if len(values) >= 5 and os.path.basename(values[0]) == "ip" and values[1:3] == ["netns", "exec"]:
        executable_indexes.append(4)
    for index in executable_indexes:
        basename = os.path.basename(values[index])
        if basename in {"", ".", ".."} or "\x00" in basename:
            raise TransmissionError("transmission-command-invalid", "command")
        executable = root / "bin" / basename
        try:
            before = os.lstat(executable)
            after = os.stat(executable)
        except OSError:
            raise TransmissionError("transmission-command-unavailable", "command") from None
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(after.st_mode)
                or not os.access(executable, os.X_OK)):
            raise TransmissionError("transmission-command-unavailable", "command")
        values[index] = str(executable)
    return values


def run(argv: list[str] | tuple[str, ...], *, input_data: bytes | None = None,
        timeout: int = 45, step: str = "command") -> subprocess.CompletedProcess[bytes]:
    values = command_argv(argv)
    env = None
    root = _scratch_root()
    if root is not None:
        env = os.environ.copy()
        env["PATH"] = str(root / "bin")
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            values,
            stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            close_fds=True,
            start_new_session=True,
        )
        stdout, _ = process.communicate(input=input_data, timeout=timeout)
        return subprocess.CompletedProcess(values, process.returncode, stdout or b"", b"")
    except subprocess.TimeoutExpired:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.communicate(timeout=3)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    pass
        raise TransmissionError("transmission-command-timeout", step) from None
    except OSError:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise TransmissionError("transmission-command-unavailable", step) from None


def _open_absolute_dir(path: str) -> int:
    parts = Path(path).parts
    if not parts or parts[0] != "/" or any(part in {".", ".."} for part in parts):
        raise OSError("unsafe-directory")
    root = _scratch_root()
    mapped = runtime_path(path)
    if root is None:
        base = "/"
        tail = parts[1:]
    else:
        base = str(root)
        tail = Path(mapped).relative_to(root).parts
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(base, flags)
    try:
        for part in tail:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def read_regular(path: str, maximum: int = 1024 * 1024) -> tuple[bytes, os.stat_result]:
    parent = str(Path(path).parent)
    name = Path(path).name
    fd = _open_absolute_dir(parent)
    file_fd = None
    try:
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode) or before.st_size > maximum:
            raise OSError("not-bounded-regular-file")
        file_fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK, dir_fd=fd)
        opened = os.fstat(file_fd)
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_size > maximum):
            raise OSError("file-raced-or-invalid")
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
        return b"".join(chunks), opened
    finally:
        if file_fd is not None:
            os.close(file_fd)
        os.close(fd)


def write_atomic(path: str, data: bytes, mode: int = 0o600) -> tuple[int, int]:
    target = runtime_path(path)
    parent_path = str(Path(path).parent)
    parent = runtime_path(parent_path)
    os.makedirs(parent, mode=0o755, exist_ok=True)
    parent_fd = _open_absolute_dir(parent_path)
    name = Path(path).name
    temp = f".{name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = None
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                     mode, dir_fd=parent_fd)
        os.fchmod(fd, mode)
        if _scratch_root() is None and os.geteuid() == 0:
            os.fchown(fd, 0, 0)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
        identity = os.fstat(fd)
        os.close(fd)
        fd = None
        os.replace(temp, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.fsync(parent_fd)
        return identity.st_dev, identity.st_ino
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temp, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def safe_unlink(path: str, identity: tuple[int, int] | None = None) -> bool:
    parent_fd = _open_absolute_dir(str(Path(path).parent))
    name = Path(path).name
    try:
        try:
            info = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return False
        if identity is not None and (info.st_dev, info.st_ino) != identity:
            return False
        os.unlink(name, dir_fd=parent_fd)
        return True
    except OSError:
        return False
    finally:
        os.close(parent_fd)


def read_request(*, known_fields: tuple[str, ...] = ("provider",),
                 declared_flags: tuple[str, ...] = ("vpn",)) -> Any:
    raw = sys.stdin.read(MAX_INPUT + 1)
    if not raw or len(raw.encode("utf-8", "ignore")) > MAX_INPUT:
        raise EnvelopeError("request-size-invalid")
    original = sys.stdin
    try:
        sys.stdin = io.StringIO(raw)
        return read_envelope(known_fields=known_fields, declared_flags=declared_flags)
    finally:
        sys.stdin = original


def _provider_metadata() -> tuple[list[str], str]:
    path = Path(__file__).resolve().parent / "vpn" / "index.json"
    try:
        metadata = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-provider-metadata-unreadable", "provider-metadata") from None
    providers = metadata.get("providers")
    default = metadata.get("defaultProvider")
    if (not isinstance(providers, list) or not providers
            or any(not isinstance(item, str) or not _PROVIDER_RE.fullmatch(item) for item in providers)
            or len(set(providers)) != len(providers)
            or not isinstance(default, str) or default not in providers):
        raise TransmissionError("transmission-provider-metadata-invalid", "provider-metadata")
    return providers, default


def _provider_candidates(container: Mapping[str, Any]) -> tuple[bool, Any]:
    flags = container.get("flags")
    if not isinstance(flags, Mapping):
        return False, None
    scopes = [flags]
    exousia = flags.get("exousia")
    if isinstance(exousia, Mapping):
        scopes.insert(0, exousia)
    for scope in scopes:
        vpn = scope.get("vpn")
        if isinstance(vpn, Mapping) and "provider" in vpn:
            return True, vpn.get("provider")
    return False, None


def resolve_provider(request: Any) -> tuple[str, list[str]]:
    providers, default = _provider_metadata()
    raw = getattr(request, "value", {})
    payload = raw.get("payload") if isinstance(raw, Mapping) else None
    sources = [item for item in (raw, payload) if isinstance(item, Mapping)]
    selected = False
    value: Any = None
    for source in sources:
        found, candidate = _provider_candidates(source)
        if found:
            selected, value = True, candidate
            break
    if not selected:
        for source in sources:
            if "provider" in source:
                selected, value = True, source.get("provider")
                break
    if not selected or value is None:
        return default, providers
    if not isinstance(value, str) or not _PROVIDER_RE.fullmatch(value) or value not in providers:
        raise TransmissionError("provider-unknown", "provider-resolution")
    return value, providers


def provider_face(provider: str) -> Any:
    providers, _default = _provider_metadata()
    if provider not in providers:
        raise TransmissionError("provider-unknown", "provider-resolution")
    path = Path(__file__).resolve().parent / "vpn" / provider / "index.py"
    if not path.is_file():
        raise TransmissionError("transmission-provider-band-unreadable", "provider-load")
    module_name = "agathodaimon.face_transmission_vpn_" + provider
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise TransmissionError("transmission-provider-band-unreadable", "provider-load")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "agathodaimon"
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise TransmissionError("transmission-provider-band-unreadable", "provider-load") from None
    for name in ("connect", "forward", "keepalive", "teardown"):
        if not callable(getattr(module, name, None)):
            raise TransmissionError("transmission-provider-face-incomplete", "provider-load")
    return module


def _stamp(receipt: dict[str, Any], step: str, observed: Any, could_change: Any,
           attempt: Any, final_state: Any) -> None:
    receipt.setdefault("steps", []).append({
        "step": step,
        "observed": observed,
        "could-change": could_change,
        "attempt": attempt,
        "finalState": final_state,
    })


def receipt(schema: str, provider: str | None = None) -> dict[str, Any]:
    return {
        "schema": schema,
        "ok": False,
        "firstMissingSignal": "transmission-not-complete",
        "provider": provider,
        "steps": [],
    }


def finish(receipt_value: dict[str, Any], request: Any | None = None,
           *, successful_read: bool = False) -> dict[str, Any]:
    if request is None:
        return receipt_value
    if successful_read and receipt_value.get("ok") is True:
        attach_value = dict(receipt_value)
        attach_value["firstMissingSignal"] = "none"
        result = attach_envelope(attach_value, request)
        if isinstance(result, dict):
            result.update(receipt_value)
            if "firstMissingSignal" not in receipt_value:
                result.pop("firstMissingSignal", None)
        return result
    return attach_envelope(receipt_value, request)


def print_receipt(value: dict[str, Any]) -> int:
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0 if value.get("ok") is True else 1


def namespace_names() -> list[str]:
    result = run([IP, "-j", "netns", "list"], step="namespace-readback")
    if result.returncode != 0:
        raise TransmissionError("transmission-namespace-read-failed", "namespace-readback")
    if not result.stdout.strip():
        # iproute2 reports a successful empty namespace set as an empty byte
        # string on this Hermes image (not JSON []); malformed nonempty output
        # remains a refusal below.
        return []
    try:
        rows = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-namespace-read-invalid", "namespace-readback") from None
    if not isinstance(rows, list):
        raise TransmissionError("transmission-namespace-read-invalid", "namespace-readback")
    names = []
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("name"), str):
            names.append(row["name"])
    return names


def _link_data(namespace: str | None, interface: str) -> list[dict[str, Any]] | None:
    if not _IFACE_RE.fullmatch(interface):
        raise TransmissionError("transmission-interface-invalid", "interface-readback")
    command = [IP]
    if namespace is not None:
        command += ["-j", "-n", namespace, "link", "show", "dev", interface]
    else:
        command += ["-j", "link", "show", "dev", interface]
    result = run(command, step="interface-readback")
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-interface-read-invalid", "interface-readback") from None
    if not isinstance(value, list):
        raise TransmissionError("transmission-interface-read-invalid", "interface-readback")
    return [item for item in value if isinstance(item, dict)]


def link_up(namespace: str | None, interface: str) -> bool:
    rows = _link_data(namespace, interface)
    if not rows:
        return False
    flags = rows[0].get("flags", [])
    if isinstance(flags, str):
        flags = flags.strip("<>").split(",")
    return isinstance(flags, list) and "UP" in flags


def _ipv4_addresses(namespace: str | None, interface: str) -> set[str]:
    command = [IP]
    if namespace is not None:
        command += ["-j", "-n", namespace, "-4", "addr", "show", "dev", interface]
    else:
        command += ["-j", "-4", "addr", "show", "dev", interface]
    result = run(command, step="address-readback")
    if result.returncode != 0:
        return set()
    try:
        rows = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-address-read-invalid", "address-readback") from None
    addresses: set[str] = set()
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            for info in row.get("addr_info", []):
                if isinstance(info, dict) and isinstance(info.get("local"), str):
                    addresses.add(info["local"] + "/" + str(info.get("prefixlen", "")))
    return addresses


def _ensure_command(argv: list[str], step: str) -> None:
    result = run(argv, step=step)
    if result.returncode != 0:
        raise TransmissionError("transmission-network-command-failed", step)


def _read_route_device() -> str:
    result = run([IP, "-4", "route", "get", "1.1.1.1"], step="wan-interface-readback")
    if result.returncode != 0:
        raise TransmissionError("transmission-wan-interface-unavailable", "wan-interface-readback")
    try:
        fields = result.stdout.decode("utf-8").split()
        dev = fields[fields.index("dev") + 1]
    except (UnicodeError, ValueError, IndexError):
        raise TransmissionError("transmission-wan-interface-invalid", "wan-interface-readback") from None
    if not _IFACE_RE.fullmatch(dev) or dev in {HOST_VETH, "lo"}:
        raise TransmissionError("transmission-wan-interface-invalid", "wan-interface-readback")
    return dev


def _ensure_nft_rule(family: str, table: str, chain: str, marker: str,
                     rule: list[str], step: str) -> None:
    listed = run([NFT, "list", "chain", family, table, chain], step=step + "-readback")
    if listed.returncode != 0:
        raise TransmissionError("transmission-firewall-chain-unavailable", step)
    try:
        text = listed.stdout.decode("utf-8")
    except UnicodeError:
        raise TransmissionError("transmission-firewall-read-invalid", step) from None
    if marker in text:
        return
    # Insert narrow allow rules before existing terminal drops; never weaken or
    # replace the host's established policy.
    command = [NFT, "insert", "rule", family, table, chain, *rule, "comment", marker]
    result = run(command, step=step)
    if result.returncode != 0:
        raise TransmissionError("transmission-firewall-rule-failed", step)
    checked = run([NFT, "list", "chain", family, table, chain], step=step + "-final-readback")
    if checked.returncode != 0 or marker not in checked.stdout.decode("utf-8", "ignore"):
        raise TransmissionError("transmission-firewall-rule-readback-failed", step)


def _enable_host_forwarding_and_nat(wan: str) -> None:
    result = run([SYSCTL, "-w", "net.ipv4.ip_forward=1"], step="ip-forward-enable")
    if result.returncode != 0:
        raise TransmissionError("transmission-ip-forward-enable-failed", "ip-forward-enable")
    readback = run([SYSCTL, "-n", "net.ipv4.ip_forward"], step="ip-forward-readback")
    if readback.returncode != 0 or readback.stdout.strip() != b"1":
        raise TransmissionError("transmission-ip-forward-readback-failed", "ip-forward-readback")
    _ensure_nft_rule(
        "inet", "filter", "forward", "agathodaimon-transmission-outbound-vpn-traffic",
        ["iifname", HOST_VETH, "oifname", wan, "ip", "saddr", "192.168.2.0/24", "accept"],
        "outbound-forward-rule",
    )
    _ensure_nft_rule(
        "inet", "filter", "forward", "agathodaimon-transmission-vpn-return-traffic",
        ["iifname", wan, "oifname", HOST_VETH, "ip", "daddr", "192.168.2.0/24",
         "ct", "state", "established,related", "accept"],
        "return-forward-rule",
    )
    _ensure_nft_rule(
        "ip", "nat", "postrouting", "agathodaimon-transmission-nat-masquerade-vpn",
        ["ip", "saddr", "192.168.2.0/24", "oifname", wan, "masquerade"],
        "namespace-nat-rule",
    )


def _ensure_namespace() -> dict[str, Any]:
    if os.geteuid() != 0 and _scratch_root() is None:
        raise TransmissionError("transmission-root-required", "namespace")
    names = namespace_names()
    namespace_created = VPN_NAMESPACE not in names
    if namespace_created:
        _ensure_command([IP, "netns", "add", VPN_NAMESPACE], "namespace-create")
        if VPN_NAMESPACE not in namespace_names():
            raise TransmissionError("transmission-namespace-readback-failed", "namespace")
    host_link = _link_data(None, HOST_VETH)
    namespace_link = _link_data(VPN_NAMESPACE, NS_VETH)
    veth_created = False
    if not host_link:
        if namespace_link:
            raise TransmissionError("transmission-veth-state-conflict", "namespace")
        _ensure_command([IP, "link", "add", HOST_VETH, "type", "veth", "peer", "name", NS_VETH], "veth-create")
        _ensure_command([IP, "link", "set", NS_VETH, "netns", VPN_NAMESPACE], "veth-namespace-attach")
        veth_created = True
        host_link = _link_data(None, HOST_VETH)
        namespace_link = _link_data(VPN_NAMESPACE, NS_VETH)
    if not host_link or not namespace_link:
        raise TransmissionError("transmission-veth-readback-failed", "namespace")
    expected_host = HOST_ADDRESS
    expected_ns = NS_ADDRESS
    host_addresses = _ipv4_addresses(None, HOST_VETH)
    ns_addresses = _ipv4_addresses(VPN_NAMESPACE, NS_VETH)
    if expected_host not in host_addresses:
        _ensure_command([IP, "addr", "add", expected_host, "dev", HOST_VETH], "host-veth-address")
    if expected_ns not in ns_addresses:
        _ensure_command([IP, "-n", VPN_NAMESPACE, "addr", "add", expected_ns, "dev", NS_VETH], "namespace-veth-address")
    _ensure_command([IP, "link", "set", HOST_VETH, "up"], "host-veth-up")
    _ensure_command([IP, "-n", VPN_NAMESPACE, "link", "set", "lo", "up"], "namespace-loopback-up")
    _ensure_command([IP, "-n", VPN_NAMESPACE, "link", "set", NS_VETH, "up"], "namespace-veth-up")
    _ensure_command([IP, "-n", VPN_NAMESPACE, "route", "replace", "default", "via", NS_GATEWAY, "dev", NS_VETH], "namespace-default-route")
    dns = runtime_path(DNS_PATH)
    os.makedirs(dns.parent, mode=0o755, exist_ok=True)
    try:
        content, _metadata = read_regular(DNS_PATH, 4096)
    except FileNotFoundError:
        content = b""
    except OSError:
        raise TransmissionError("transmission-dns-config-unreadable", "namespace") from None
    wanted_dns = b"nameserver 1.1.1.1\n"
    if content != wanted_dns:
        write_atomic(DNS_PATH, wanted_dns, 0o644)
    wan = _read_route_device()
    _enable_host_forwarding_and_nat(wan)
    final = {
        "namespace": VPN_NAMESPACE in namespace_names(),
        "hostVethUp": link_up(None, HOST_VETH),
        "namespaceVethUp": link_up(VPN_NAMESPACE, NS_VETH),
        "hostAddress": expected_host in _ipv4_addresses(None, HOST_VETH),
        "namespaceAddress": expected_ns in _ipv4_addresses(VPN_NAMESPACE, NS_VETH),
        "defaultRouteVia": _namespace_default_route(),
        "resolvConf": _read_dns_config(),
        "wanInterface": wan,
        "ipForward": True,
    }
    if not all(final[key] is True for key in ("namespace", "hostVethUp", "namespaceVethUp", "hostAddress", "namespaceAddress", "ipForward")) or final["defaultRouteVia"] is not True or final["resolvConf"] is not True:
        raise TransmissionError("transmission-namespace-readback-mismatch", "namespace")
    return {"observed": {"namespacePresent": not namespace_created, "hostVethPresent": not veth_created},
            "could-change": ["vpn namespace", "veth0/veth1 addresses and link state", "namespace default route", "resolv.conf", "ip_forward", "narrow VPN forwarding/NAT rules"],
            "attempt": "ensure exact vpn namespace plumbing and routes",
            "finalState": final}


def _namespace_default_route() -> bool:
    result = run([IP, "-j", "-n", VPN_NAMESPACE, "-4", "route", "show", "default"],
                 step="namespace-route-readback")
    if result.returncode != 0:
        return False
    try:
        rows = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-route-read-invalid", "namespace-route-readback") from None
    if not isinstance(rows, list):
        raise TransmissionError("transmission-route-read-invalid", "namespace-route-readback")
    return any(isinstance(row, dict)
               and row.get("dst") in {"default", None}
               and row.get("gateway") == NS_GATEWAY
               and row.get("dev") == NS_VETH for row in rows)


def _read_dns_config() -> bool:
    try:
        content, _metadata = read_regular(DNS_PATH, 4096)
    except OSError:
        return False
    return content == b"nameserver 1.1.1.1\n"


def ensure_namespace() -> dict[str, Any]:
    before_names: set[str] = set()
    before_host = False
    try:
        before_names = set(namespace_names())
        before_host = bool(_link_data(None, HOST_VETH))
    except TransmissionError:
        # The owned-attempt report below will carry any follow-up read failure.
        pass
    try:
        return _ensure_namespace()
    except Exception as failure:
        final_names: set[str] = set()
        final_host = False
        final_ns = False
        try:
            final_names = set(namespace_names())
            final_host = bool(_link_data(None, HOST_VETH))
            final_ns = VPN_NAMESPACE in final_names and bool(_link_data(VPN_NAMESPACE, NS_VETH))
        except Exception:
            pass
        owned = []
        if VPN_NAMESPACE not in before_names and VPN_NAMESPACE in final_names:
            owned.append("vpn namespace created by this attempted bring-up; preserved")
        if not before_host and final_host:
            owned.append("veth0/veth1 pair created by this attempted bring-up; preserved")
        detail = {
            "observedBefore": {"namespacePresent": VPN_NAMESPACE in before_names,
                               "hostVethPresent": before_host},
            "attempt": "ensure exact vpn namespace plumbing and routes",
            "preservedOwnedResources": owned,
            "finalState": {"namespacePresent": VPN_NAMESPACE in final_names,
                           "hostVethPresent": final_host,
                           "namespaceVethPresent": final_ns},
        }
        if isinstance(failure, TransmissionError):
            failure.detail.update({"namespaceAttempt": detail})
            raise
        raise TransmissionError("transmission-namespace-setup-failed", "namespace",
                                {"namespaceAttempt": detail}) from None


def portal_port() -> int:
    try:
        raw, _metadata = read_regular(CONFIG_PATH, 4 * 1024 * 1024)
        config = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-portal-config-read-failed", "portal-row") from None
    try:
        portals = config["tabs"]["portals"]["data"]["portals"]
    except (TypeError, KeyError):
        raise TransmissionError("transmission-portal-map-invalid", "portal-row") from None
    if not isinstance(portals, list):
        raise TransmissionError("transmission-portal-map-invalid", "portal-row")
    rows = [row for row in portals if isinstance(row, dict)
            and isinstance(row.get("name"), str) and row["name"].casefold() == "transmission"]
    if len(rows) != 1:
        raise TransmissionError("transmission-portal-row-missing-or-ambiguous", "portal-row")
    port = rows[0].get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise TransmissionError("transmission-portal-port-invalid", "portal-row")
    return port


def unit_active(unit: str, *, step: str = "unit-state-readback") -> bool:
    result = run([SYSTEMCTL, "is-active", unit], timeout=30, step=step)
    state = result.stdout.decode("utf-8", "ignore").strip()
    if result.returncode == 0 and state == "active":
        return True
    if result.returncode in {3, 4} and state in {"inactive", "failed", "unknown", ""}:
        return False
    raise TransmissionError("transmission-unit-state-unreadable", step)


def start_unit(unit: str, step: str) -> None:
    result = run([SYSTEMCTL, "start", unit], timeout=180, step=step)
    if result.returncode != 0:
        raise TransmissionError("transmission-unit-start-failed", step)
    if not unit_active(unit, step=step + "-readback"):
        raise TransmissionError("transmission-unit-start-readback-failed", step)


def stop_unit(unit: str, step: str) -> None:
    if not unit_active(unit, step=step + "-preflight"):
        return
    result = run([SYSTEMCTL, "stop", unit], timeout=180, step=step)
    if result.returncode != 0:
        raise TransmissionError("transmission-unit-stop-failed", step)
    if unit_active(unit, step=step + "-readback"):
        raise TransmissionError("transmission-unit-stop-readback-failed", step)


def _timestamp_seconds(value: Any) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, OverflowError):
        return None


def write_provider_state(provider: str, forward: Mapping[str, Any], tunnel_interface: str,
                         *, peer_port_applied: bool = False, peer_port_readback: int | None = None,
                         rpc_port: int | None = None, bound_at: str | None = None) -> tuple[int, int]:
    port = forward.get("port")
    interval = forward.get("keepaliveInterval")
    if (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
            or isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0
            or not _IFACE_RE.fullmatch(tunnel_interface)):
        raise TransmissionError("transmission-forward-state-invalid", "forward-state-write")
    state = {
        "provider": provider,
        "boundAt": bound_at or now_utc(),
        "keepaliveInterval": interval,
        "forwardPort": port,
        "tunnelInterface": tunnel_interface,
        "peerPortApplied": bool(peer_port_applied),
        "peerPortReadback": peer_port_readback,
        "rpcPort": rpc_port,
    }
    path = f"{STATE_DIR}/{provider}.json"
    try:
        return write_atomic(path, json.dumps(state, sort_keys=True, separators=(",", ":")).encode(), 0o600)
    except (OSError, TransmissionError):
        raise TransmissionError("transmission-forward-state-write-failed", "forward-state-write") from None


def remove_provider_state(provider: str, identity: tuple[int, int] | None = None) -> bool:
    return safe_unlink(f"{STATE_DIR}/{provider}.json", identity)


def read_provider_state(provider: str) -> dict[str, Any] | None:
    path = f"{STATE_DIR}/{provider}.json"
    try:
        raw, metadata = read_regular(path, 65536)
    except FileNotFoundError:
        return None
    except OSError:
        raise TransmissionError("transmission-forward-state-read-failed", "forward-state-readback") from None
    if stat.S_IMODE(metadata.st_mode) != 0o600 or (_scratch_root() is None and metadata.st_uid != 0):
        raise TransmissionError("transmission-forward-state-permissions-invalid", "forward-state-readback")
    try:
        state = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-forward-state-invalid", "forward-state-readback") from None
    if not isinstance(state, dict) or state.get("provider") != provider:
        raise TransmissionError("transmission-forward-state-invalid", "forward-state-readback")
    return state


def state_is_fresh(state: Mapping[str, Any] | None) -> bool:
    if state is None:
        return False
    bound = _timestamp_seconds(state.get("boundAt"))
    interval = state.get("keepaliveInterval")
    if bound is None or isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0:
        raise TransmissionError("transmission-forward-state-invalid", "forward-state-readback")
    age = time.time() - bound
    return 0 <= age < interval


def _open_key_exchange_dir(*, required: bool = True, require_tmpfs: bool = True) -> int | None:
    try:
        fd = _open_absolute_dir(EXCHANGE_DIR)
    except FileNotFoundError:
        if not required:
            return None
        raise TransmissionError("transmission-key-exchange-unavailable", "key-export") from None
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise TransmissionError("transmission-key-exchange-unavailable", "key-export")
    if not require_tmpfs:
        return fd
    # Keyman owns exchange-directory preparation; verify the prepared transit
    # surface only after its export command has run.
    mountinfo_path = runtime_path("/proc/self/mountinfo")
    try:
        text = mountinfo_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        os.close(fd)
        raise TransmissionError("transmission-key-exchange-unavailable", "key-export") from None
    mounted = False
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        fields = left.split()
        tail = right.split()
        if sep and len(fields) > 4 and len(tail) > 0 and fields[4].replace("\\040", " ") == EXCHANGE_DIR and tail[0] == "tmpfs":
            mounted = True
            break
    if not mounted:
        os.close(fd)
        raise TransmissionError("transmission-key-exchange-unavailable", "key-export")
    return fd


def _read_exchange_file(directory_fd: int, service: str) -> tuple[bytearray, os.stat_result]:
    try:
        before = os.stat(service, dir_fd=directory_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or before.st_uid != 0 or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_size <= 0 or before.st_size > 65536):
            raise OSError("exchange-file-invalid")
        fd = os.open(service, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK, dir_fd=directory_fd)
    except OSError:
        raise TransmissionError("transmission-key-export-invalid", "key-export") from None
    try:
        opened = os.fstat(fd)
        after = os.stat(service, dir_fd=directory_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                or (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
                or stat.S_IMODE(opened.st_mode) != 0o600 or opened.st_size > 65536):
            raise OSError("exchange-file-raced")
        chunks = bytearray()
        while len(chunks) <= 65536:
            part = os.read(fd, min(8192, 65537 - len(chunks)))
            if not part:
                break
            chunks.extend(part)
        if not chunks or len(chunks) > 65536:
            raise OSError("exchange-file-invalid")
    except OSError:
        raise TransmissionError("transmission-key-export-invalid", "key-export") from None
    finally:
        os.close(fd)
    try:
        current = os.stat(service, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("exchange-file-raced")
        os.unlink(service, dir_fd=directory_fd)
    except OSError:
        for index in range(len(chunks)):
            chunks[index] = 0
        raise TransmissionError("transmission-key-export-cleanup-failed", "key-export") from None
    return chunks, opened


def _parse_key_material(material: bytearray) -> tuple[str, str]:
    try:
        text = material.decode("utf-8")
    except UnicodeError:
        raise TransmissionError("transmission-key-export-invalid", "key-export") from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip().strip("\"'")
        if key in {"username", "user"}:
            values["username"] = value
        elif key in {"password", "pass"}:
            values["password"] = value
    username, password = values.get("username"), values.get("password")
    if (not username or not password or any(ch in username + password for ch in "\r\n\x00")):
        raise TransmissionError("transmission-key-export-invalid", "key-export")
    return username, password


@contextmanager
def exported_credentials(service: str) -> Iterator[tuple[str, str]]:
    providers, _default = _provider_metadata()
    if (not isinstance(service, str) or not _PROVIDER_RE.fullmatch(service)
            or service not in set(providers) | {"transmission"}):
        raise TransmissionError("transmission-key-service-invalid", "key-export")
    if os.geteuid() != 0 and _scratch_root() is None:
        raise TransmissionError("transmission-root-required", "key-export")
    lock_path = runtime_path(KEY_LOCK)
    os.makedirs(lock_path.parent, mode=0o755, exist_ok=True)
    lock_fd = None
    exchange_fd = None
    try:
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
                          | getattr(os, "O_CLOEXEC", 0), 0o600)
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or stat.S_IMODE(lock_info.st_mode) != 0o600
                or (_scratch_root() is None and lock_info.st_uid != 0)):
            raise OSError("unsafe-export-lock")
        # Refuse stale plaintext before asking Keyman to export. The directory
        # may legitimately be absent: Keyman prepares it as part of export.
        exchange_fd = _open_key_exchange_dir(required=False, require_tmpfs=False)
    except (OSError, TransmissionError):
        if lock_fd is not None:
            os.close(lock_fd)
        raise TransmissionError("transmission-key-export-unavailable", "key-export") from None
    material: bytearray | None = None
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        if exchange_fd is not None:
            try:
                os.stat(service, dir_fd=exchange_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            except OSError:
                raise TransmissionError("transmission-key-export-unavailable", "key-export") from None
            else:
                raise TransmissionError("transmission-key-export-preexisting", "key-export")
            os.close(exchange_fd)
            exchange_fd = None
        result = run([KEYMAN, "export", service], timeout=15, step="keyman-export")
        if result.returncode != 0:
            raise TransmissionError("transmission-key-export-failed", "key-export")
        exchange_fd = _open_key_exchange_dir(required=True, require_tmpfs=True)
        assert exchange_fd is not None
        material, _identity = _read_exchange_file(exchange_fd, service)
        username, password = _parse_key_material(material)
        yield username, password
    finally:
        if material is not None:
            for index in range(len(material)):
                material[index] = 0
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        if exchange_fd is not None:
            os.close(exchange_fd)
        if lock_fd is not None:
            os.close(lock_fd)


def _curl_config_value(key: str, value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise TransmissionError("transmission-rpc-request-invalid", "rpc-request")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'{key} = "{escaped}"\n'


def _curl_http(url: str, *, username: str | None = None, password: str | None = None,
               session_id: str | None = None, body: str | None = None,
               connect_to: str | None = None, ca_file: str | None = None,
               namespace: str | None = None, method: str | None = None,
               form: Mapping[str, str] | None = None,
               step: str = "http-request") -> tuple[int, dict[str, str], bytes]:
    cfg = "silent\nshow-error\ninclude\nmax-time = 15\n" + _curl_config_value("url", url)
    if username is not None and password is not None:
        cfg += _curl_config_value("user", username + ":" + password)
    if session_id is not None:
        cfg += _curl_config_value("header", "X-Transmission-Session-Id: " + session_id)
    if body is not None:
        cfg += _curl_config_value("header", "Content-Type: application/json")
        cfg += _curl_config_value("data", body)
    if method is not None:
        cfg += _curl_config_value("request", method.upper())
    if form is not None:
        for key, value in form.items():
            cfg += _curl_config_value("data-urlencode", f"{key}={value}")
    if connect_to is not None:
        cfg += _curl_config_value("connect-to", connect_to)
    if ca_file is not None:
        cfg += _curl_config_value("cacert", ca_file)
    command: list[str]
    if namespace is None:
        command = [CURL, "--config", "-"]
    else:
        command = [IP, "netns", "exec", namespace, CURL, "--config", "-"]
    result = run(command, input_data=cfg.encode("utf-8"), timeout=25, step=step)
    if result.returncode != 0:
        raise TransmissionError("transmission-http-request-failed", step)
    try:
        response = result.stdout.decode("utf-8")
    except UnicodeError:
        raise TransmissionError("transmission-http-response-invalid", step) from None
    headers: dict[str, str] = {}
    status_code = 200
    body_text = response
    if "\r\n\r\n" in response or "\n\n" in response:
        header_text, _, body_text = re.split(r"\r?\n\r?\n", response, maxsplit=1)
        match = re.search(r"(?m)^HTTP/\S+\s+(\d{3})", header_text)
        if match:
            status_code = int(match.group(1))
        for line in header_text.splitlines()[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
    return status_code, headers, body_text.encode("utf-8")


def rpc_call(port: int, method: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise TransmissionError("transmission-rpc-port-invalid", "rpc-request")
    body = json.dumps({"method": method, "arguments": arguments or {}}, separators=(",", ":"))
    with exported_credentials("transmission") as (username, password):
        url = f"http://127.0.0.1:{port}/transmission/rpc"
        status, headers, raw = _curl_http(url, username=username, password=password,
                                          body=body, namespace=VPN_NAMESPACE, step="transmission-rpc")
        if status == 409:
            session_id = headers.get("x-transmission-session-id")
            if not session_id:
                raise TransmissionError("transmission-rpc-session-id-missing", "rpc-session")
            status, _headers, raw = _curl_http(url, username=username, password=password,
                                               session_id=session_id, body=body,
                                               namespace=VPN_NAMESPACE, step="transmission-rpc-retry")
    if status != 200:
        raise TransmissionError("transmission-rpc-response-failed", "rpc-response")
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-rpc-response-invalid", "rpc-response") from None
    if not isinstance(response, dict) or response.get("result") != "success" or not isinstance(response.get("arguments"), dict):
        raise TransmissionError("transmission-rpc-response-failed", "rpc-response")
    return response["arguments"]


def rpc_get_peer_port(port: int) -> int:
    arguments = rpc_call(port, "session-get")
    value = arguments.get("peer-port")
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise TransmissionError("transmission-peer-port-readback-invalid", "peer-port-readback")
    return value


def rpc_set_peer_port(port: int, peer_port: int) -> bool:
    rpc_call(port, "session-set", {"peer-port": peer_port})
    return rpc_get_peer_port(port) == peer_port


def rpc_set_download_settings(port: int, peer_port: int) -> dict[str, Any]:
    desired = {
        "peer-port": peer_port,
        "download-dir": "/mnt/nas/downloads/complete/",
        "incomplete-dir": "/mnt/nas/downloads/incomplete/",
        "incomplete-dir-enabled": True,
        "watch-dir": "/mnt/nas/downloads/objectives/",
        "watch-dir-enabled": True,
    }
    rpc_call(port, "session-set", desired)
    observed = rpc_call(port, "session-get")
    readback = {key: observed.get(key) for key in desired}
    if readback != desired:
        raise TransmissionError("transmission-settings-readback-mismatch", "settings-readback")
    return readback


def ensure_rpc_lan_rules(rpc_port: int) -> list[str]:
    result = run([IP, "-j", "-4", "addr", "show"], step="lan-interface-readback")
    if result.returncode != 0:
        raise TransmissionError("transmission-lan-interface-unavailable", "lan-interface-readback")
    try:
        rows = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise TransmissionError("transmission-lan-interface-invalid", "lan-interface-readback") from None
    if not isinstance(rows, list):
        raise TransmissionError("transmission-lan-interface-invalid", "lan-interface-readback")
    interfaces: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        name = row.get("ifname")
        if not isinstance(name, str) or not _IFACE_RE.fullmatch(name) or name in {"lo", HOST_VETH}:
            continue
        for addr in row.get("addr_info", []):
            if not isinstance(addr, dict) or addr.get("family") != "inet" or addr.get("scope") != "global":
                continue
            local = addr.get("local")
            try:
                address = ipaddress.ip_address(local)
            except (ValueError, TypeError):
                continue
            if isinstance(address, ipaddress.IPv4Address) and address.is_private:
                interfaces.add(name)
                break
    if not interfaces:
        raise TransmissionError("transmission-lan-interface-unavailable", "lan-interface-readback")
    for interface in sorted(interfaces):
        safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", interface)
        _ensure_nft_rule(
            "inet", "filter", "forward", f"agathodaimon-transmission-lan-rpc-{rpc_port}-{safe_name}",
            ["iifname", interface, "oifname", HOST_VETH, "ip", "daddr", NS_ADDRESS_ONLY,
             "tcp", "dport", str(rpc_port), "accept"],
            "lan-rpc-forward-rule",
        )
        _ensure_nft_rule(
            "inet", "filter", "forward", f"agathodaimon-transmission-vpn-lan-rpc-{rpc_port}-{safe_name}",
            ["iifname", HOST_VETH, "oifname", interface, "ip", "saddr", NS_ADDRESS_ONLY,
             "tcp", "sport", str(rpc_port), "ct", "state", "established,related", "accept"],
            "vpn-lan-rpc-return-rule",
        )
    return sorted(interfaces)


def _status_unit_read(unit: str) -> tuple[bool, bool]:
    """Return (readable, active), treating a known inactive/unloaded unit as off."""
    try:
        return True, unit_active(unit)
    except TransmissionError:
        raise


def status_read(provider: str, provider_names: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema": SCHEMA_STATUS,
        "ok": False,
        "on": False,
        "provider": provider,
        "conditions": {"namespace": False, "tunnel": False, "forward": False, "daemon": False, "peerPort": False},
        "forwardPort": None,
        "peerPort": None,
        "rpcPort": None,
        "firstMissingSignal": "namespace",
        "steps": [],
    }
    try:
        provider_names_present, _default = _provider_metadata()
        if provider not in provider_names_present:
            result.update(firstMissingSignal="provider-unknown", providers=provider_names_present)
            return result
        names = namespace_names()
        if VPN_NAMESPACE not in names:
            _stamp(result, "namespace", {"present": False}, False, "read-only", {"present": False, "veth1Up": False})
            result["ok"] = True
            result["firstMissingSignal"] = "namespace"
            return result
        namespace_ok = link_up(VPN_NAMESPACE, NS_VETH)
        result["conditions"]["namespace"] = namespace_ok
        _stamp(result, "namespace", {"present": True}, False, "read-only", {"present": True, "veth1Up": namespace_ok})
        face = provider_face(provider)
        tunnel_interface = getattr(face, "TUNNEL_INTERFACE", None)
        if not isinstance(tunnel_interface, str) or not _IFACE_RE.fullmatch(tunnel_interface):
            raise TransmissionError("transmission-provider-interface-invalid", "tunnel-readback")
        tunnel_ok = link_up(VPN_NAMESPACE, tunnel_interface)
        result["conditions"]["tunnel"] = tunnel_ok
        _stamp(result, "tunnel", {"interface": tunnel_interface}, False, "read-only", {"up": tunnel_ok})
        hold_unit = HOLD_UNIT.format(provider)
        hold_active = unit_active(hold_unit, step="hold-unit-readback")
        state = read_provider_state(provider)
        forward_ok = hold_active and state_is_fresh(state)
        if state is not None:
            forward_port = state.get("forwardPort")
            if isinstance(forward_port, int) and not isinstance(forward_port, bool) and 1 <= forward_port <= 65535:
                result["forwardPort"] = forward_port
        result["conditions"]["forward"] = forward_ok
        _stamp(result, "forward", {"holdActive": hold_active, "statePresent": state is not None}, False,
               "read-only", {"fresh": forward_ok, "forwardPort": result["forwardPort"]})
        rpc_port = portal_port()
        result["rpcPort"] = rpc_port
        daemon_active = unit_active(DAEMON_UNIT.format(rpc_port), step="daemon-unit-readback")
        result["conditions"]["daemon"] = daemon_active
        _stamp(result, "daemon", {"unit": DAEMON_UNIT.format(rpc_port)}, False, "read-only", {"active": daemon_active})
        if daemon_active:
            peer_port = rpc_get_peer_port(rpc_port)
            result["peerPort"] = peer_port
            peer_ok = result["forwardPort"] is not None and peer_port == result["forwardPort"] and forward_ok
            result["conditions"]["peerPort"] = peer_ok
            _stamp(result, "peerPort", {"peerPort": peer_port, "forwardPort": result["forwardPort"]}, False,
                   "read-only", {"matches": peer_ok})
        else:
            _stamp(result, "peerPort", {"daemonActive": False}, False, "not-needed", {"matches": False})
        conditions = result["conditions"]
        result["on"] = all(conditions.values())
        result["ok"] = True
        result["firstMissingSignal"] = next((key for key, value in conditions.items() if not value), "none")
        return result
    except TransmissionError as failure:
        result["ok"] = False
        result["firstMissingSignal"] = failure.signal_name
        result["failedStep"] = failure.step
        return result


def failure_receipt(schema: str, failure: Exception, provider: str | None = None) -> dict[str, Any]:
    value = receipt(schema, provider)
    if isinstance(failure, TransmissionError):
        value["firstMissingSignal"] = failure.signal_name
        value["failedRung"] = "request"
        value["failedCommandError"] = {"signal": failure.signal_name, "step": failure.step}
        if failure.detail:
            value.update(failure.detail)
    else:
        value["firstMissingSignal"] = "transmission-request-invalid"
        value["failedRung"] = "request"
        value["failedCommandError"] = {"signal": "transmission-request-invalid", "step": "request"}
    value["ok"] = False
    return value

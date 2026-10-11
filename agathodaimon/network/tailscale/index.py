"""Bounded native Tailscale staff verbs and rollback-safe tailnet changes."""
from __future__ import annotations

import copy
import datetime
import fcntl
import importlib.util
import json
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, replace
from io import StringIO
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from agathodaimon._envelope import EnvelopeError, Request, appliance_runtime_path, attach, read

NOUN = "tailscale"
VERBS = ["status", "up", "down", "authkey", "tailnet"]
SCHEMA = "caduceus.staff.v1"
TAILSCALE = "/usr/bin/tailscale"
NGINX = "/usr/sbin/nginx"
SYSTEMCTL = "/usr/bin/systemctl"
MAX_BYTES = 32 * 1024 * 1024
KEY_PATTERN = re.compile(r"^tskey-(auth|client)-[A-Za-z0-9-]+$")
NAME_PATTERN = re.compile(r"^[a-z0-9-]{1,63}$")
LOGIN_URL = re.compile(r"https://login\.tailscale\.com/[^\s\"'<>]+")
SECRET_MARKER = re.compile(r"tskey-", re.IGNORECASE)
SITES_AVAILABLE = Path("/etc/nginx/sites-available")
NGINX_CONF_D = Path("/etc/nginx/conf.d")
OG_CONFIG = Path("/var/www/homeserver/src/config/homeserver.json")
BACKUP_ROOT = Path("/var/lib/agathodaimon/tailscale/backups")


class Refused(ValueError):
    def __init__(self, signal: str):
        super().__init__(signal)
        self.signal = signal


class TransactionInterrupted(BaseException):
    def __init__(self, signum: int):
        super().__init__(signum)
        self.signum = signum


@dataclass(frozen=True)
class Image:
    existed: bool
    mode: int = 0
    uid: int = 0
    gid: int = 0
    data: bytes | None = None

    @property
    def kind(self) -> str:
        if not self.existed:
            return "absent"
        if stat.S_ISLNK(self.mode):
            return "symlink"
        if stat.S_ISDIR(self.mode):
            return "directory"
        if stat.S_ISREG(self.mode):
            return "file"
        return "other"


def _receipt(action: str, ok: bool, signal_name: str = "none", *, observed: Any = None,
             could_change: Sequence[str] = (), attempt: Any = None, final: Any = None,
             mutation: bool = False, **fields: Any) -> dict[str, Any]:
    result = {
        "schema": SCHEMA,
        "ok": ok,
        "action": action,
        "firstMissingSignal": signal_name,
        "mutationPerformed": mutation,
        "observed": observed,
        "could-change": list(could_change),
        "attempt": attempt,
        "final": final,
    }
    if isinstance(final, dict):
        for key in ("connected", "loginUrl"):
            if key in final:
                result[key] = final[key]
    result.update(fields)
    return result


def _scrub(value: Any) -> Any:
    """Erase every token-bearing string, including map keys and nested echoes."""
    if isinstance(value, str):
        return "[REDACTED]" if SECRET_MARKER.search(value) else value
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub(item) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            safe_key = _scrub(key) if isinstance(key, str) else key
            result[safe_key] = _scrub(child)
        return result
    return value


def _safe_request(request: Request) -> Request:
    value = _scrub(copy.deepcopy(request.value))
    payload = _scrub(copy.deepcopy(request.payload))
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return replace(
        request,
        value=value,
        payload=payload,
        raw_envelope=raw,
        intent_id=_scrub(request.intent_id),
        transition=_scrub(request.transition),
        version=_scrub(request.version),
        timestamp=_scrub(request.timestamp),
    )


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()


def _run(argv: Sequence[str], timeout: float, *, stdin: str | None = None) -> subprocess.CompletedProcess[str] | None:
    try:
        process = subprocess.Popen(
            list(argv), stdin=subprocess.PIPE if stdin is not None else None,
            text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        stdout, stderr = process.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        return None
    except (OSError, subprocess.SubprocessError):
        try:
            _kill_process_group(process)
        except BaseException:
            pass
        return None
    except BaseException:
        try:
            _kill_process_group(process)
        except BaseException:
            pass
        raise
    return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)


def _status(timeout: float = 8) -> tuple[dict[str, Any] | None, str]:
    result = _run([TAILSCALE, "status", "--json", "--peers=false"], timeout)
    if result is None:
        return None, "tailscale-status-launch-or-timeout"
    if result.returncode != 0:
        return None, "tailscale-status-command-failed"
    if len(result.stdout.encode("utf-8", "replace")) > 1024 * 1024:
        return None, "tailscale-status-output-too-large"
    try:
        data = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError):
        return None, "tailscale-status-json-invalid"
    if not isinstance(data, dict):
        return None, "tailscale-status-shape-invalid"
    backend = data.get("BackendState")
    if backend == "Running":
        state, connected = "connected", True
    elif backend == "NeedsLogin":
        state, connected = "needs-login", False
    elif backend in {"Stopped", "NoState", "Starting", "NeedsMachineAuth"}:
        state, connected = "disconnected", False
    else:
        return None, "tailscale-status-state-unusable"
    node_value = data.get("Self")
    node: dict[str, Any] = node_value if isinstance(node_value, dict) else {}
    ips = node.get("TailscaleIPs")
    ip = next((item for item in ips if isinstance(item, str)), None) if isinstance(ips, list) else None
    current = data.get("CurrentTailnet")
    tailnet = current.get("Name") if isinstance(current, dict) else None
    login = data.get("AuthURL")
    match = LOGIN_URL.search(login) if isinstance(login, str) else None
    return {
        "status": state,
        "connected": connected,
        "loginUrl": match.group(0) if match else None,
        "interface": "tailscale0" if connected else None,
        "ip": ip,
        "tailnet": tailnet if isinstance(tailnet, str) else None,
        "backendState": backend,
    }, "none"


def _read_regular(path: Path, signal_name: str = "tailscale-config-unreadable") -> tuple[bytes, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise Refused(signal_name) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise Refused("tailscale-config-invalid")
        pieces: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_BYTES:
                raise Refused("tailscale-config-too-large")
            pieces.append(chunk)
        return b"".join(pieces), info
    finally:
        os.close(fd)


def _load_runtime_config(path: Path) -> tuple[dict[str, Any], bytes, os.stat_result]:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise Refused("tailscale-config-canonical-unavailable") from error
    if stat.S_ISLNK(info.st_mode):
        raise Refused("tailscale-config-factory-selected")
    factory = appliance_runtime_path("factory")
    try:
        if os.path.samefile(path, factory):
            raise Refused("tailscale-config-factory-selected")
    except FileNotFoundError:
        pass
    except OSError as error:
        raise Refused("tailscale-config-selection-unreadable") from error
    raw, meta = _read_regular(path)
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused("tailscale-config-invalid") from error
    if not isinstance(value, dict):
        raise Refused("tailscale-config-invalid")
    return value, raw, meta


def _cors(config: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    global_value = config.get("global")
    cors_value = global_value.get("cors") if isinstance(global_value, Mapping) else None
    origins_value = cors_value.get("allowed_origins") if isinstance(cors_value, Mapping) else None
    if not isinstance(cors_value, dict) or not isinstance(origins_value, list) or any(not isinstance(item, str) for item in origins_value):
        raise Refused("tailscale-config-cors-invalid")
    return cors_value, origins_value


def _origin_label(value: str) -> str | None:
    if ".ts.net" not in value.lower():
        return None
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError as error:
        raise Refused("tailscale-origin-invalid") from error
    labels = host.split(".")
    if len(labels) != 4 or labels[0] != "home" or labels[2:] != ["ts", "net"]:
        return None
    if not NAME_PATTERN.fullmatch(labels[1]):
        raise Refused("tailscale-origin-label-invalid")
    if not parsed.scheme or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise Refused("tailscale-origin-invalid")
    return labels[1]


def _served_certificate_sans() -> set[str]:
    result = _run(["/usr/bin/openssl", "x509", "-in", "/etc/ssl/home.arpa/cert.pem", "-noout", "-ext", "subjectAltName"], 10)
    if result is None or result.returncode != 0:
        return set()
    return {item.strip()[4:] for item in result.stdout.replace("\n", ",").split(",") if item.strip().startswith("DNS:")}


def _declared_tailnet(config: Mapping[str, Any]) -> str:
    _cors_value, origins = _cors(config)
    for origin in origins:
        label = _origin_label(origin)
        if label is not None:
            return label
    raise Refused("tailscale-declared-tailnet-origin-missing")


def _status_receipt() -> dict[str, Any]:
    value, signal_name = _status()
    if value is None:
        return _receipt("status", False, signal_name,
                        observed={"source": "tailscale status --json --peers=false"}, attempt="read-status")
    declared: str | None = None
    declared_signal = "none"
    try:
        config, _raw, _meta = _load_runtime_config(appliance_runtime_path("config"))
        declared = _declared_tailnet(config)
    except Refused as error:
        # A body that declares no tailnet still reports its live state.
        declared_signal = error.signal
    value["declaredTailnet"] = declared
    value["declaredTailnetSignal"] = declared_signal
    return _receipt("status", True, observed={"backendState": value["backendState"], "liveTailnet": value.get("tailnet"), "declaredTailnet": declared},
                    attempt="read-live-and-declared-tailnet", final=value)


def _up_receipt() -> dict[str, Any]:
    before, signal_name = _status()
    if before is None:
        return _receipt("up", False, signal_name, observed={"status": "unreadable"}, attempt="read-preflight")
    if before["connected"]:
        final = dict(before)
        final["loginUrl"] = None
        return _receipt("up", True, observed=before, attempt="already-connected-nochange", final=final, changed=False)
    result = _run([TAILSCALE, "up", "--timeout=12s"], 15)
    output = "" if result is None else result.stdout + "\n" + result.stderr
    match = LOGIN_URL.search(output)
    output_url = match.group(0) if match else None
    after, signal_name = _status()
    if after is None:
        return _receipt("up", False, signal_name, observed=before, could_change=["tailscaled login state"],
                        attempt={"command": "tailscale up --timeout=12s", "returnCode": result.returncode if result else None}, mutation=result is not None)
    login_url = after.get("loginUrl") or output_url
    final = dict(after)
    final["loginUrl"] = None if after["connected"] else login_url
    pending = result is not None and after["status"] == "needs-login" and bool(login_url)
    ok = (result is not None and result.returncode == 0 and after["connected"]) or pending
    changed = before["status"] != after["status"] or before["loginUrl"] != final["loginUrl"] or (result is not None and result.returncode == 0)
    return _receipt("up", ok, "none" if ok else "tailscale-up-not-connected", observed=before,
                    could_change=["tailscaled login state"],
                    attempt={"command": "tailscale up --timeout=12s", "returnCode": result.returncode if result else None},
                    final=final, mutation=changed, changed=changed)


def _down_receipt() -> dict[str, Any]:
    before, signal_name = _status()
    if before is None:
        return _receipt("down", False, signal_name, observed={"status": "unreadable"}, attempt="read-preflight")
    result = _run([TAILSCALE, "down"], 15)
    after, signal_name = _status()
    if after is None:
        return _receipt("down", False, signal_name, observed=before, could_change=["tailscaled login state"],
                        attempt={"command": "tailscale down", "returnCode": result.returncode if result else None}, mutation=result is not None)
    ok = result is not None and result.returncode == 0 and after["connected"] is False
    changed = before["status"] != after["status"]
    return _receipt("down", ok, "none" if ok else "tailscale-down-readback-failed", observed=before,
                    could_change=["tailscaled login state"],
                    attempt={"command": "tailscale down", "returnCode": result.returncode if result else None},
                    final=after, mutation=changed, changed=changed)


def _authkey_receipt(key: str | None) -> dict[str, Any]:
    if not isinstance(key, str) or len(key) > 1024 or not KEY_PATTERN.fullmatch(key):
        return _receipt("authkey", False, "tailscale-authkey-pattern-refused",
                        observed={"keySupplied": key is not None}, attempt="validate-key")
    before, signal_name = _status(4)
    if before is None:
        return _receipt("authkey", False, signal_name, observed={"status": "unreadable"}, attempt="read-preflight")
    result = _run([TAILSCALE, "up", "--auth-key=file:/dev/stdin", "--timeout=18s"], 20, stdin=key + "\n")
    key = None
    after, signal_name = _status(4)
    if after is None:
        return _receipt("authkey", False, signal_name, observed=before, could_change=["tailscaled login state"],
                        attempt={"command": "tailscale up --auth-key=file:/dev/stdin --timeout=18s", "returnCode": result.returncode if result else None}, mutation=result is not None)
    ok = result is not None and result.returncode == 0 and after["connected"] is True
    changed = before["status"] != after["status"] or (result is not None and result.returncode == 0)
    return _receipt("authkey", ok, "none" if ok else "tailscale-authkey-authentication-failed", observed=before,
                    could_change=["tailscaled login state"],
                    attempt={"command": "tailscale up --auth-key=file:/dev/stdin --timeout=18s", "returnCode": result.returncode if result else None},
                    final=after, mutation=changed, changed=changed)


def _request() -> Request:
    stream = sys.stdin
    try:
        raw = stream.read()
    except (OSError, UnicodeError) as error:
        raise EnvelopeError("staff envelope read failed") from error
    if not raw.strip():
        return Request({}, False, {}, raw)
    try:
        sys.stdin = StringIO(raw)
        return read(
            known_fields=("action", "operation", "state", "key", "authkey", "name", "backup-dir", "backup_dir", "backupDir", "args"),
            declared_flags=("key", "authkey", "name", "backup-dir", "backup_dir", "backupDir"),
        )
    finally:
        sys.stdin = stream


def _parse(action_args: Sequence[str], request: Request) -> tuple[str, dict[str, str]]:
    args = list(action_args)
    payload = request.payload if isinstance(request.payload, Mapping) else {}
    if not args and "args" in payload:
        if not isinstance(payload["args"], list) or any(not isinstance(item, str) for item in payload["args"]):
            raise Refused("tailscale-arguments-invalid")
        args = list(payload["args"])
    allowed_actions = set(VERBS)
    action = args.pop(0) if args and args[0] in allowed_actions else None
    if action is None:
        for source in (payload, request.value):
            if isinstance(source, Mapping):
                candidate = next((source.get(key) for key in ("action", "operation", "state") if isinstance(source.get(key), str)), None)
                if candidate in allowed_actions:
                    action = candidate
                    break
    if action is None and request.verb in allowed_actions:
        action = request.verb
    if action is None:
        raise Refused("tailscale-operation-required")

    values: dict[str, str] = {}
    sources = [payload] + ([request.value] if isinstance(request.value, Mapping) else [])
    for source in sources:
        for field in ("key", "authkey", "name", "backup-dir", "backup_dir", "backupDir"):
            if field not in source:
                continue
            value = source[field]
            if not isinstance(value, str):
                raise Refused("tailscale-envelope-option-invalid")
            dest = "key" if field in {"key", "authkey"} else "name" if field == "name" else "backup-dir"
            if dest in values and values[dest] != value:
                raise Refused("tailscale-envelope-option-conflict")
            values[dest] = value
    seen: set[str] = set()
    index = 0
    while index < len(args):
        item = args[index]
        if item in {"--key", "--authkey", "--name", "--backup-dir"}:
            if index + 1 >= len(args) or args[index + 1].startswith("--"):
                raise Refused("tailscale-option-value-missing")
            flag, value = item, args[index + 1]
            index += 2
        elif any(item.startswith(prefix) for prefix in ("--key=", "--authkey=", "--name=", "--backup-dir=")):
            flag, value = item.split("=", 1)
            index += 1
        else:
            raise Refused("tailscale-arguments-invalid")
        dest = "key" if flag in {"--key", "--authkey"} else "name" if flag == "--name" else "backup-dir"
        if dest in seen:
            raise Refused("tailscale-option-duplicate")
        seen.add(dest)
        if dest in values and values[dest] != value:
            raise Refused("tailscale-envelope-option-conflict")
        values[dest] = value
    allowed = {"status": set(), "up": set(), "down": set(), "authkey": {"key"}, "tailnet": {"name", "backup-dir"}}[action]
    if set(values) - allowed:
        raise Refused("tailscale-option-not-admitted")
    return action, values


def _validate_backup_argument(value: str | None) -> str | None:
    if value is None:
        return None
    path = Path(value)
    if not path.is_absolute() or path == Path("/") or any(part in {".", ".."} for part in path.parts):
        raise Refused("tailscale-tailnet-backup-path-invalid")
    return str(path)


def _tailnet_label_from_url(value: str, *, origin: bool = False) -> str:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        _port = parsed.port
    except ValueError as error:
        raise Refused("tailscale-tailnet-url-invalid") from error
    labels = host.split(".")
    if not parsed.scheme or not host or len(labels) < 4 or labels[-2:] != ["ts", "net"] or not NAME_PATTERN.fullmatch(labels[-3]):
        raise Refused("tailscale-tailnet-url-invalid")
    if origin and (parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise Refused("tailscale-tailnet-origin-invalid")
    return labels[-3]


def _rewrite_remote(value: str, name: str) -> str:
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        _port = parsed.port
    except ValueError as error:
        raise Refused("tailscale-tailnet-remote-url-invalid") from error
    labels = host.split(".")
    if not parsed.scheme or parsed.scheme.lower() not in {"http", "https"} or len(labels) < 4 or labels[-2:] != ["ts", "net"] or not NAME_PATTERN.fullmatch(labels[-3]):
        raise Refused("tailscale-tailnet-remote-url-invalid")
    authority = parsed.netloc
    userinfo, hostport = (authority.rsplit("@", 1)[0] + "@", authority.rsplit("@", 1)[1]) if "@" in authority else ("", authority)
    if hostport.startswith("["):
        raise Refused("tailscale-tailnet-remote-url-invalid")
    port_text = ""
    host_text = hostport
    if ":" in hostport:
        candidate_host, candidate_port = hostport.rsplit(":", 1)
        if candidate_port.isdigit():
            host_text, port_text = candidate_host, ":" + candidate_port
    suffix = re.compile(r"\.[a-z0-9-]+\.ts\.net\.?$", re.IGNORECASE)
    match = suffix.search(host_text)
    if match is None:
        raise Refused("tailscale-tailnet-remote-url-invalid")
    new_host = host_text[:match.start()] + f".{name}.ts.net"
    return urlunsplit((parsed.scheme, userinfo + new_host + port_text, parsed.path, parsed.query, parsed.fragment))


def _config_parts(config: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[dict[str, Any]]]:
    cors, origins = _cors(config)
    tabs = config.get("tabs")
    portal_root = tabs.get("portals") if isinstance(tabs, Mapping) else None
    portal_data = portal_root.get("data") if isinstance(portal_root, Mapping) else None
    portals_value = portal_data.get("portals") if isinstance(portal_data, Mapping) else None
    if portals_value is None:
        portals_value = []
    if not isinstance(portals_value, list) or any(not isinstance(item, dict) for item in portals_value):
        raise Refused("tailscale-config-portals-invalid")
    for portal in portals_value:
        if "remoteURL" in portal and portal["remoteURL"] is not None and not isinstance(portal["remoteURL"], str):
            raise Refused("tailscale-config-portals-invalid")
    return cors, origins, portals_value


def _rewrite_config(config: dict[str, Any], name: str) -> tuple[bytes, set[str]]:
    cors, origins, portals = _config_parts(config)
    old: set[str] = set()
    rewritten: list[str] = []
    saw_tsnet = False
    new_origin = f"https://home.{name}.ts.net"
    for value in origins:
        if ".ts.net" in value.lower():
            old.add(_tailnet_label_from_url(value, origin=True))
            rewritten.append(new_origin)
            saw_tsnet = True
        else:
            rewritten.append(value)
    if not saw_tsnet:
        rewritten.append(new_origin)
    cors["allowed_origins"] = list(dict.fromkeys(rewritten))
    for portal in portals:
        remote = portal.get("remoteURL")
        if isinstance(remote, str) and ".ts.net" in remote.lower():
            old.add(_tailnet_label_from_url(remote))
            portal["remoteURL"] = _rewrite_remote(remote, name)
    return (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), old


def _plan_runtime_config(path: Path, name: str) -> tuple[bytes, bytes, os.stat_result, str | None, set[str], bool]:
    config, raw, meta = _load_runtime_config(path)
    cors, origins, _portals = _config_parts(config)
    prior = next((label for item in origins if (label := _origin_label(item)) is not None), None)
    if prior == name:
        return raw, raw, meta, prior, set(), False
    new_bytes, old = _rewrite_config(config, name)
    return raw, new_bytes, meta, prior, old, raw != new_bytes


def _plan_optional_config(path: Path, name: str) -> tuple[bytes | None, bytes | None, os.stat_result | None, set[str]]:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, None, None, set()
    except OSError as error:
        raise Refused("tailscale-homeserver-config-unreadable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise Refused("tailscale-homeserver-config-seat-refused")
    raw, meta = _read_regular(path, "tailscale-homeserver-config-unreadable")
    try:
        config = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refused("tailscale-homeserver-config-invalid") from error
    if not isinstance(config, dict):
        raise Refused("tailscale-homeserver-config-invalid")
    updated, old = _rewrite_config(config, name)
    return raw, updated, meta, old


def _image(path: Path) -> Image:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return Image(False)
    except OSError as error:
        raise Refused("tailscale-tailnet-snapshot-read-failed") from error
    if stat.S_ISLNK(info.st_mode):
        return Image(True, info.st_mode, info.st_uid, info.st_gid, os.fsencode(os.readlink(path)))
    if stat.S_ISDIR(info.st_mode):
        return Image(True, info.st_mode, info.st_uid, info.st_gid)
    if not stat.S_ISREG(info.st_mode):
        raise Refused("tailscale-tailnet-managed-seat-not-regular")
    data, current = _read_regular(path, "tailscale-tailnet-snapshot-read-failed")
    return Image(True, current.st_mode, current.st_uid, current.st_gid, data)


def _walk_tree(root: Path) -> list[Path]:
    result: list[Path] = []
    pending = [root]
    while pending:
        path = pending.pop()
        image = _image(path)
        result.append(path)
        if image.kind != "directory":
            continue
        try:
            children = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise Refused("tailscale-tailnet-directory-unreadable") from error
        pending.extend(reversed(children))
    return result


def _snapshot(paths: Sequence[Path], trees: Sequence[Path]) -> tuple[dict[Path, Image], dict[Path, list[str]]]:
    all_paths = set(paths)
    for tree in trees:
        all_paths.update(_walk_tree(tree))
    images = {path: _image(path) for path in all_paths}
    contents: dict[Path, list[str]] = {}
    for path, image in images.items():
        if image.kind == "directory":
            try:
                contents[path] = sorted(child.name for child in path.iterdir())
            except OSError as error:
                raise Refused("tailscale-tailnet-directory-unreadable") from error
    return images, contents


def _within(path: Path, roots: Sequence[Path]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _nginx_sources() -> tuple[dict[Path, bytes], dict[Path, list[Path]], set[str]]:
    roots: list[Path] = []
    for directory in (SITES_AVAILABLE, NGINX_CONF_D):
        try:
            info = os.lstat(directory)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise Refused("tailscale-tailnet-nginx-directory-unreadable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise Refused("tailscale-tailnet-nginx-directory-refused")
        roots.append(directory.resolve())
    files: dict[Path, bytes] = {}
    aliases: dict[Path, list[Path]] = {}
    names: set[str] = set()
    for directory in roots:
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise Refused("tailscale-tailnet-nginx-directory-unreadable") from error
        for entry in entries:
            try:
                entry_info = os.lstat(entry)
                if stat.S_ISLNK(entry_info.st_mode):
                    try:
                        target = entry.resolve(strict=True)
                    except OSError:
                        continue
                    if not _within(target, roots):
                        continue
                    target_info = os.lstat(target)
                    if not stat.S_ISREG(target_info.st_mode):
                        continue
                    aliases.setdefault(target, []).append(entry)
                elif stat.S_ISREG(entry_info.st_mode):
                    target = entry
                else:
                    continue
                if target not in files:
                    image = _image(target)
                    if image.kind != "file" or image.data is None:
                        continue
                    files[target] = image.data
                    names.update(match.decode("ascii").lower() for match in re.findall(rb"(?i)(?<![A-Z0-9_.-])home\.([a-z0-9-]{1,63})\.ts\.net(?![A-Z0-9_.-])", image.data))
            except Refused:
                raise
            except OSError as error:
                raise Refused("tailscale-tailnet-nginx-config-unreadable") from error
    return files, aliases, names


def _rewrite_nginx(data: bytes, old_names: set[str], new_name: str) -> bytes:
    updated = data
    for old in sorted(old_names, key=len, reverse=True):
        pattern = re.compile(rb"(?i)(?<![A-Z0-9_.-])home\." + re.escape(old.encode("ascii")) + rb"\.ts\.net(?![A-Z0-9_.-])")
        updated = pattern.sub(f"home.{new_name}.ts.net".encode("ascii"), updated)
    return updated


def _nginx_plan(old_names: set[str], new_name: str) -> tuple[dict[Path, bytes], dict[Path, list[Path]], set[str]]:
    files, aliases, observed_names = _nginx_sources()
    all_old = set(old_names) | observed_names
    all_old.discard(new_name)
    plan: dict[Path, bytes] = {}
    for path, data in files.items():
        updated = _rewrite_nginx(data, all_old, new_name)
        if updated != data:
            plan[path] = updated
    affected_aliases = {target: sorted(aliases.get(target, []), key=str) for target in plan}
    return plan, affected_aliases, observed_names


def _safe_components(path: Path, *, allow_missing_leaf: bool = False) -> None:
    if not path.is_absolute():
        raise Refused("tailscale-tailnet-backup-path-invalid")
    current = Path("/")
    components = path.parts[1:]
    for index, part in enumerate(components):
        current = current / part
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_leaf and index == len(components) - 1:
                return
            raise Refused("tailscale-tailnet-backup-parent-unavailable")
        except OSError as error:
            raise Refused("tailscale-tailnet-backup-parent-unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise Refused("tailscale-tailnet-backup-path-refused")


def _mkdir_chain(path: Path) -> None:
    missing: list[Path] = []
    current = path
    while current != Path("/"):
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            missing.append(current)
            current = current.parent
            continue
        except OSError as error:
            raise Refused("tailscale-tailnet-backup-parent-unavailable") from error
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise Refused("tailscale-tailnet-backup-path-refused")
        _safe_components(current)
        break
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o750)
            os.chmod(directory, 0o750)
            _fsync_directory(directory.parent)
        except OSError as error:
            raise Refused("tailscale-tailnet-backup-parent-create-failed") from error


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short durable write")
        view = view[written:]


def _backup(directory: str | None, images: Mapping[Path, Image], directory_contents: Mapping[Path, Sequence[str]]) -> str:
    if directory is None:
        _mkdir_chain(BACKUP_ROOT)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        root = BACKUP_ROOT / stamp
        for suffix in range(100):
            candidate = root if suffix == 0 else BACKUP_ROOT / f"{stamp}-{suffix:02d}"
            try:
                os.mkdir(candidate, 0o700)
                root = candidate
                break
            except FileExistsError:
                continue
            except OSError as error:
                raise Refused("tailscale-tailnet-backup-create-failed") from error
        else:
            raise Refused("tailscale-tailnet-backup-create-failed")
    else:
        root = Path(directory)
        if root.exists() or root.is_symlink():
            raise Refused("tailscale-tailnet-backup-path-exists")
        _safe_components(root.parent)
        try:
            os.mkdir(root, 0o700)
        except OSError as error:
            raise Refused("tailscale-tailnet-backup-create-failed") from error
    try:
        os.chmod(root, 0o700)
        files_dir = root / "files"
        os.mkdir(files_dir, 0o700)
        rows: list[dict[str, Any]] = []
        for index, (path, image) in enumerate(sorted(images.items(), key=lambda pair: str(pair[0]))):
            data_file = None
            if image.existed and image.kind != "directory":
                data_file = f"files/{index:05d}.bin"
                fd = os.open(files_dir / f"{index:05d}.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                try:
                    _write_all(fd, image.data or b"")
                    os.fchmod(fd, 0o600)
                    os.fsync(fd)
                finally:
                    os.close(fd)
            rows.append({
                "path": str(path), "state": image.kind, "existed": image.existed,
                "mode": image.mode, "uid": image.uid, "gid": image.gid,
                "dataFile": data_file,
            })
        manifest = {
            "schema": "agathodaimon.tailscale.preimage.v1",
            "files": rows,
            "directoryEntries": {str(path): list(names) for path, names in sorted(directory_contents.items(), key=lambda pair: str(pair[0]))},
            "restore": "Manual restore only; sidecars retain bytes and symlink targets, rows retain mode/uid/gid and absent/directory states.",
        }
        encoded = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        fd = os.open(root / "snapshot.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            _write_all(fd, encoded)
            os.fchmod(fd, 0o600)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(files_dir)
        _fsync_directory(root)
        _fsync_directory(root.parent)
        return str(root)
    except BaseException as error:
        shutil.rmtree(root, ignore_errors=True)
        if isinstance(error, Refused):
            raise
        if isinstance(error, TransactionInterrupted):
            raise
        raise Refused("tailscale-tailnet-backup-create-failed") from error


def _atomic_write(path: Path, temp: Path, data: bytes, image: Image, owned: set[Path] | None = None) -> None:
    if image.kind != "file":
        raise Refused("tailscale-tailnet-write-seat-refused")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    if owned is not None:
        owned.add(temp)
    try:
        os.fchown(fd, image.uid, image.gid)
        os.fchmod(fd, stat.S_IMODE(image.mode))
        _write_all(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temp, path)
    _fsync_directory(path.parent)


def _restore(path: Path, image: Image, restore_temp: Path | None = None, owned: set[Path] | None = None) -> None:
    current = _image(path)
    if current == image:
        return
    if not image.existed:
        if current.kind == "directory":
            path.rmdir()
        elif current.kind != "absent":
            path.unlink()
        if path.parent.is_dir():
            _fsync_directory(path.parent)
        return
    if image.kind == "symlink":
        if current.kind != "absent":
            path.unlink()
        os.symlink(os.fsdecode(image.data or b""), path)
        os.chown(path, image.uid, image.gid, follow_symlinks=False)
        _fsync_directory(path.parent)
        return
    if image.kind == "directory":
        if current.kind == "symlink" or current.kind == "file":
            path.unlink()
        if not path.exists():
            path.mkdir(mode=stat.S_IMODE(image.mode))
        os.chown(path, image.uid, image.gid)
        os.chmod(path, stat.S_IMODE(image.mode))
        return
    if image.kind != "file":
        raise Refused("tailscale-tailnet-rollback-seat-kind-invalid")
    if current.kind == "symlink" or current.kind == "directory":
        if current.kind == "directory":
            path.rmdir()
        else:
            path.unlink()
    if restore_temp is None:
        raise Refused("tailscale-tailnet-restore-temporary-unplanned")
    fd = os.open(restore_temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    if owned is not None:
        owned.add(restore_temp)
    try:
        os.fchown(fd, image.uid, image.gid)
        os.fchmod(fd, stat.S_IMODE(image.mode))
        _write_all(fd, image.data or b"")
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(restore_temp, path)
    _fsync_directory(path.parent)


def _certificate_module() -> Any:
    path = Path(__file__).resolve().parent.parent / "cert" / "refresh" / "index.py"
    spec = importlib.util.spec_from_file_location("agathodaimon.network.cert.refresh.native", path)
    if spec is None or spec.loader is None:
        raise Refused("tailscale-tailnet-certificate-refresh-unavailable")
    module = importlib.util.module_from_spec(spec)
    module_name = spec.name
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        sys.modules.pop(module_name, None)
        raise Refused("tailscale-tailnet-certificate-refresh-unavailable") from error
    if not callable(getattr(module, "prospective_mutable_inventory", None)) or not callable(getattr(module, "refresh_legacy_certificate", None)):
        raise Refused("tailscale-tailnet-certificate-refresh-unavailable")
    return module


def _safe_backup_parent(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise Refused("tailscale-tailnet-backup-path-exists")
    _safe_components(path.parent)


def _refuse_backup_overlap(path: Path, managed_paths: Sequence[Path]) -> None:
    for managed in managed_paths:
        if path == managed or path in managed.parents or managed in path.parents:
            raise Refused("tailscale-tailnet-backup-managed-path-overlap")


def _image_if_regular(path: Path) -> Image:
    image = _image(path)
    if image.kind == "symlink":
        raise Refused("tailscale-tailnet-config-factory-selected")
    if image.kind not in {"absent", "file"}:
        raise Refused("tailscale-tailnet-config-seat-refused")
    return image


def _tls_readback(host: str, cert_path: Path) -> dict[str, Any] | None:
    deadline = time.monotonic() + 8.0
    try:
        context = ssl.create_default_context(cafile=str(cert_path))
        if hasattr(ssl, "VERIFY_X509_STRICT"):
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    except (OSError, ssl.SSLError, ValueError):
        return None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            with socket.create_connection(("127.0.0.1", 443), timeout=remaining) as raw:
                raw.settimeout(max(0.1, deadline - time.monotonic()))
                with context.wrap_socket(raw, server_hostname=host) as sock:
                    peer = sock.getpeercert()
        except (OSError, ssl.SSLError):
            peer = None
        if isinstance(peer, dict):
            sans = [value for kind, value in peer.get("subjectAltName", ()) if kind == "DNS"]
            if host in sans:
                return {"subjectAltNames": sans, "hostnameVerified": True}
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(0.15, remaining))


def _signal_handlers(previous: dict[int, Any], state: dict[str, bool]) -> None:
    def handler(signum: int, _frame: Any) -> None:
        if not state["rolling_back"]:
            state["rolling_back"] = True
            raise TransactionInterrupted(signum)

    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[signum] = signal.getsignal(signum)
            signal.signal(signum, handler)
    except (OSError, ValueError) as error:
        for signum, old in previous.items():
            signal.signal(signum, old)
        raise Refused("tailscale-tailnet-signal-handler-unavailable") from error
    except BaseException:
        for signum, old in previous.items():
            signal.signal(signum, old)
        raise


def _current_tree_paths(trees: Sequence[Path]) -> set[Path]:
    result: set[Path] = set()
    for tree in trees:
        if _image(tree).kind == "directory":
            result.update(_walk_tree(tree))
    return result


def _tailnet(name: str, backup_dir: str | None) -> dict[str, Any]:
    prior_tailnet: str | None = None
    normalized = name.lower() if isinstance(name, str) else ""
    empty_attempt: list[str] = []
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(normalized):
        return _receipt("tailnet", False, "tailscale-tailnet-name-pattern-refused",
                        observed={"nameSupplied": isinstance(name, str) and bool(name)},
                        attempt="validate-and-normalize-name", final={"newTailnet": None},
                        priorTailnet=None, newTailnet=None, changedFiles=[], attemptedFiles=[], backupPath=None, subjectAltNames=[])
    try:
        backup_override = _validate_backup_argument(backup_dir)
    except Refused as error:
        return _receipt("tailnet", False, error.signal,
                        observed={"normalizedName": normalized, "backupArgumentValidated": False},
                        attempt="validate-backup-argument-before-lock", final={"newTailnet": normalized},
                        priorTailnet=None, newTailnet=normalized, changedFiles=[], attemptedFiles=[], backupPath=None, subjectAltNames=[])

    config_path = appliance_runtime_path("config")
    lock_fd: int | None = None
    try:
        lock_fd = os.open(config_path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        if lock_fd is not None:
            os.close(lock_fd)
        return _receipt("tailnet", False, "tailscale-tailnet-config-lock-unavailable",
                        observed={"configPath": str(config_path)}, attempt="serialize-config-transaction",
                        priorTailnet=None, newTailnet=normalized, changedFiles=[], attemptedFiles=[], backupPath=None, subjectAltNames=[])

    images: dict[Path, Image] = {}
    directory_contents: dict[Path, list[str]] = {}
    tree_roots: list[Path] = []
    restore_temps: dict[Path, Path] = {}
    staging_paths: set[Path] = set()
    owned_staging_paths: set[Path] = set()
    planned_paths: list[Path] = []
    attempted: list[str] = []
    owned_changed_paths: set[Path] = set()
    changed_files: list[str] = []
    aliases_for_changed: dict[Path, list[Path]] = {}
    backup_path: str | None = None
    native_inventory: dict[str, Any] = {}
    sans: list[str] = []
    stage = "preflight"
    write_started = False
    trust_update_attempted = False
    signal_previous: dict[int, Any] = {}
    signal_state: dict[str, bool] | None = None
    observed: dict[str, Any] = {"configPath": str(config_path), "normalizedName": normalized}
    native_module: Any = None

    def make_receipt(ok: bool, signal_name: str = "none", *, attempt: Any = None, final: Any = None,
                     mutation: bool = False, changed: Sequence[str] = (), **extra: Any) -> dict[str, Any]:
        return _receipt(
            "tailnet", ok, signal_name, observed=observed, could_change=attempted,
            attempt=attempt, final=final, mutation=mutation,
            priorTailnet=prior_tailnet, newTailnet=normalized,
            changedFiles=sorted(set(changed)), attemptedFiles=sorted(set(attempted)),
            backupPath=backup_path, subjectAltNames=sans,
            nginxAliases={str(path): [str(alias) for alias in aliases_for_changed.get(path, [])] for path in sorted(aliases_for_changed, key=str)},
            **extra,
        )

    def rollback(failed_signal: str, failed_stage: str) -> dict[str, Any]:
        errors: list[str] = []
        if signal_state is not None:
            signal_state["rolling_back"] = True
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                signal.signal(signum, signal.SIG_IGN)
            except (OSError, ValueError):
                errors.append("signal-mask-failed")
        try:
            try:
                current_paths = _current_tree_paths(tree_roots)
            except Exception:
                current_paths = set()
                errors.append("tailscale-tailnet-rollback-inventory-read-failed")
            original_paths = set(images)
            extras = current_paths - original_paths if trust_update_attempted else set()
            for path in sorted(extras, key=lambda item: (-len(item.parts), str(item))):
                try:
                    image = _image(path)
                    if image.kind == "directory":
                        path.rmdir()
                    elif image.kind != "absent":
                        path.unlink()
                except Exception:
                    errors.append("tailscale-tailnet-transaction-created-seat-remove-failed")
            for path in sorted(owned_staging_paths, key=str):
                try:
                    if _image(path).kind in {"file", "symlink"}:
                        path.unlink()
                except Exception:
                    errors.append("tailscale-tailnet-temporary-cleanup-failed")
            regular = [path for path, image in images.items() if image.kind == "file"]
            symlinks = [path for path, image in images.items() if image.kind == "symlink"]
            directories = [path for path, image in images.items() if image.kind == "directory"]
            absent = [path for path, image in images.items() if not image.existed]
            for path in sorted(directories, key=lambda item: (len(item.parts), str(item))):
                try:
                    _restore(path, images[path])
                except Exception:
                    errors.append("tailscale-tailnet-directory-restore-failed")
            for path in sorted(regular + symlinks, key=str):
                original = images[path]
                try:
                    _restore(path, original, restore_temps.get(path), owned=owned_staging_paths)
                except Exception:
                    errors.append("tailscale-tailnet-file-restore-failed")
            for path in sorted(absent, key=lambda item: (-len(item.parts), str(item))):
                if path not in owned_changed_paths:
                    continue
                try:
                    _restore(path, images[path])
                except Exception:
                    errors.append("tailscale-tailnet-created-seat-remove-failed")
            for path in sorted(directories, key=lambda item: (-len(item.parts), str(item))):
                try:
                    _restore(path, images[path])
                except Exception:
                    errors.append("tailscale-tailnet-directory-restore-failed")
            for path in sorted(owned_staging_paths, key=str):
                try:
                    if _image(path).kind in {"file", "symlink"}:
                        path.unlink()
                except Exception:
                    errors.append("tailscale-tailnet-temporary-cleanup-failed")
        except Exception:
            errors.append("tailscale-tailnet-rollback-inventory-failed")
        test = _run([NGINX, "-t"], 20)
        reload = _run([SYSTEMCTL, "reload", "nginx"], 30)
        reload_ok = reload is not None and reload.returncode == 0
        if not reload_ok:
            errors.append("tailscale-tailnet-nginx-rollback-reload-failed")
        try:
            current_paths = _current_tree_paths(tree_roots)
            extra_paths = current_paths - set(images)
            mismatches: list[str] = [str(path) for path in extra_paths]
            for path, original in images.items():
                try:
                    if _image(path) != original:
                        mismatches.append(str(path))
                except Exception:
                    mismatches.append(str(path))
            for directory, names in directory_contents.items():
                try:
                    current = sorted(child.name for child in directory.iterdir())
                    if current != names:
                        mismatches.append(str(directory))
                except OSError:
                    mismatches.append(str(directory))
        except Exception:
            mismatches = ["final-readback-failed"]
        mismatches = sorted(set(mismatches))
        if mismatches:
            errors.append("tailscale-tailnet-final-readback-mismatch")
        good = not errors and not mismatches and test is not None and test.returncode == 0 and reload_ok
        return make_receipt(
            False,
            failed_signal if good else "tailscale-tailnet-rollback-failed",
            attempt={"failedStage": failed_stage, "rollback": "restored" if good else "failed",
                     "rollbackFailures": sorted(set(errors)), "nginxTestReturnCode": test.returncode if test else None,
                     "nginxReloadReturnCode": reload.returncode if reload else None},
            final={"declaredTailnet": prior_tailnet if good else normalized, "changedFiles": mismatches,
                   "rollbackComplete": good},
            mutation=write_started,
            changed=mismatches,
        )

    try:
        raw_config, new_config_bytes, config_meta, prior_tailnet, config_old_names, config_changed = _plan_runtime_config(config_path, normalized)
        observed.update({"configReadable": True, "declaredTailnet": prior_tailnet})
        if backup_override is not None:
            _safe_backup_parent(Path(backup_override))

        optional_raw, optional_new, optional_meta, optional_old_names = _plan_optional_config(OG_CONFIG, normalized)
        optional_changed = optional_raw is not None and optional_new is not None and optional_raw != optional_new
        nginx_plan, aliases_for_changed, nginx_names = _nginx_plan(config_old_names | optional_old_names, normalized)
        all_old_names = set(config_old_names) | set(optional_old_names) | set(nginx_names)
        observed["priorTailnets"] = sorted(all_old_names)
        native_module = _certificate_module()
        native_inventory = native_module.prospective_mutable_inventory(normalized)
        sans = list(native_inventory.get("subjectAltNames", []))
        if (prior_tailnet == normalized and not config_changed and not optional_changed and not nginx_plan
                and f"home.{normalized}.ts.net" in _served_certificate_sans()):
            observed["unchangedAcrossConfigNginxCertificate"] = True
            return make_receipt(True, attempt="unchanged-declared-tailnet-no-op",
                                final={"declaredTailnet": prior_tailnet, "changedFiles": [], "backupCreated": False,
                                       "certificateRefreshed": False, "nginxReloaded": False},
                                mutation=False, changed=[], attempted=[])
        if not sans or not all(isinstance(item, str) for item in sans):
            raise Refused("tailscale-tailnet-certificate-inventory-invalid")
        tree_roots = [Path(item) for item in native_inventory.get("trees", [])]
        native_paths = [Path(item) for item in native_inventory.get("paths", [])]
        transaction_id = uuid.uuid4().hex
        config_temp = config_path.with_name(f".{config_path.name}.tailscale-{transaction_id}.tmp")
        planned_paths = [config_path, config_temp, *native_paths]
        optional_temp: Path | None = None
        if optional_changed:
            if optional_meta is None:
                raise Refused("tailscale-homeserver-config-invalid")
            optional_temp = OG_CONFIG.with_name(f".{OG_CONFIG.name}.tailscale-{transaction_id}.tmp")
            planned_paths.extend((OG_CONFIG, optional_temp))
            staging_paths.add(optional_temp)
        for target in nginx_plan:
            planned_paths.append(target)
            for alias in aliases_for_changed.get(target, []):
                planned_paths.append(alias)
            planned_paths.append(target.with_name(f".{target.name}.tailscale-{transaction_id}.tmp"))
        planned_paths.extend((config_path.parent,))
        planned_paths.extend(path.parent for path in tuple(planned_paths) if path.parent != Path("/"))
        for path in tuple(planned_paths):
            if path.name.endswith(f".tailscale-{transaction_id}.tmp"):
                staging_paths.add(path)
        for path in native_paths:
            if path.name.endswith(".new") or path.name.endswith(".cnf") or path.name.endswith(".restore"):
                staging_paths.add(path)
        images, directory_contents = _snapshot(planned_paths, tree_roots)
        for path in staging_paths:
            kind = images.get(path, Image(False)).kind
            if kind in {"file", "symlink"}:
                # A prior killed run left one of this verb's own staging names behind.
                path.unlink()
                images[path] = Image(False)
            elif kind != "absent":
                raise Refused("tailscale-tailnet-temporary-seat-exists")
        for target, image in tuple(images.items()):
            if image.kind != "file":
                continue
            temp = target.with_name(f".{target.name}.tailscale-restore-{transaction_id}.tmp")
            if temp in images and images[temp].kind != "absent":
                raise Refused("tailscale-tailnet-restore-temporary-exists")
            if _image(temp).kind != "absent":
                raise Refused("tailscale-tailnet-restore-temporary-exists")
            restore_temps[target] = temp
            planned_paths.append(temp)
            images[temp] = Image(False)
            staging_paths.add(temp)
        if backup_override is not None:
            _refuse_backup_overlap(Path(backup_override), [*planned_paths, *tree_roots])
        for path in restore_temps.values():
            if images.get(path, Image(False)).kind != "absent":
                raise Refused("tailscale-tailnet-restore-temporary-exists")
        observed.update({"prospectiveSeatCount": len(images), "trustUpdater": native_inventory.get("updater", {}).get("program") if isinstance(native_inventory.get("updater"), Mapping) and native_inventory.get("updater", {}).get("enabled") else "not-needed"})
        signal_state = {"rolling_back": False}
        _signal_handlers(signal_previous, signal_state)
        stage = "backup"
        backup_path = _backup(backup_override, images, directory_contents)
        observed["backupComplete"] = True

        if config_changed:
            stage = "write-config"
            write_started = True
            attempted.append(str(config_path))
            _atomic_write(config_path, config_temp, new_config_bytes, images[config_path], owned_staging_paths)
            changed_files.append(str(config_path))
        if optional_changed and optional_raw is not None and optional_new is not None and optional_meta is not None and optional_temp is not None:
            stage = "write-homeserver-config"
            temp = optional_temp
            write_started = True
            attempted.append(str(OG_CONFIG))
            _atomic_write(OG_CONFIG, temp, optional_new, Image(True, optional_meta.st_mode, optional_meta.st_uid, optional_meta.st_gid, optional_raw), owned_staging_paths)
            changed_files.append(str(OG_CONFIG))
        for target, data in sorted(nginx_plan.items(), key=lambda pair: str(pair[0])):
            stage = "rewrite-nginx"
            image = images[target]
            temp = target.with_name(f".{target.name}.tailscale-{transaction_id}.tmp")
            write_started = True
            attempted.append(str(target))
            _atomic_write(target, temp, data, image, owned_staging_paths)
            changed_files.append(str(target))
            changed_files.extend(str(alias) for alias in aliases_for_changed.get(target, []))
        stage = "refresh-legacy-certificate"
        write_started = True

        def mark_trust_update() -> None:
            nonlocal trust_update_attempted
            trust_update_attempted = True

        def mark_native_path(path: Path) -> None:
            owned_changed_paths.add(path)
            attempted.append(str(path))

        certificate = native_module.refresh_legacy_certificate(on_trust_update=mark_trust_update, on_path_change=mark_native_path)
        if isinstance(certificate, dict):
            attempted.extend(item for item in certificate.get("writtenPaths", []) if isinstance(item, str))
        if not isinstance(certificate, dict) or certificate.get("ok") is not True:
            signal_name = certificate.get("firstMissingSignal") if isinstance(certificate, dict) else None
            raise Refused(signal_name if isinstance(signal_name, str) and signal_name != "none" else "tailscale-tailnet-certificate-refresh-failed")
        changed_files.extend(item for item in certificate.get("writtenPaths", []) if isinstance(item, str))
        stage = "nginx-validation"
        tested = _run([NGINX, "-t"], 20)
        if tested is None or tested.returncode != 0:
            raise Refused("tailscale-tailnet-nginx-validation-failed")
        stage = "nginx-reload"
        reloaded = _run([SYSTEMCTL, "reload", "nginx"], 30)
        if reloaded is None or reloaded.returncode != 0:
            raise Refused("tailscale-tailnet-nginx-reload-failed")
        stage = "tls-readback"
        identity = f"home.{normalized}.ts.net"
        tls = _tls_readback(identity, Path("/etc/ssl/home.arpa/cert.pem"))
        if tls is None or tls.get("hostnameVerified") is not True or identity not in tls.get("subjectAltNames", []):
            raise Refused("tailscale-tailnet-nginx-tls-readback-failed")
        current_paths = _current_tree_paths(tree_roots)
        extras = current_paths - set(images)
        for path in extras:
            changed_files.append(str(path))
        for path, original in images.items():
            if _image(path) != original:
                changed_files.append(str(path))
        return make_receipt(
            True,
            attempt={"stages": ["backup", "write-config", "write-homeserver-config" if optional_changed else "homeserver-config-absent-or-unchanged",
                                "rewrite-nginx", "native-certificate-refresh", "nginx-test", "nginx-reload", "tls-readback"]},
            final={"declaredTailnet": normalized, "subjectAltNames": sans, "changedFiles": sorted(set(changed_files)),
                   "nginxReloaded": True, "tlsHostnameVerified": True, "backupComplete": True},
            mutation=write_started,
            changed=changed_files,
            transactionId=transaction_id,
        )
    except BaseException as error:
        if isinstance(error, TransactionInterrupted):
            failed_signal = f"tailscale-tailnet-interrupted-{signal.Signals(error.signum).name.lower()}"
        elif isinstance(error, Refused) or isinstance(getattr(error, "signal", None), str):
            failed_signal = error.signal
        else:
            failed_signal = f"tailscale-tailnet-{stage}-failed"
        if write_started and images and backup_path is not None:
            return rollback(failed_signal, stage)
        return make_receipt(
            False, failed_signal,
            attempt={"failedStage": stage, "rollback": "not-needed-before-first-write"},
            final={"declaredTailnet": prior_tailnet, "changedFiles": [], "backupComplete": bool(backup_path)},
            mutation=False, changed=[],
        )
    finally:
        if signal_state is not None:
            signal_state["rolling_back"] = True
        for signum, old_handler in signal_previous.items():
            try:
                signal.signal(signum, old_handler)
            except (OSError, ValueError):
                pass
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--help"]:
        print(json.dumps({"schema": SCHEMA, "verbs": ["status", "up", "down", "authkey --key <k>", "tailnet --name <n> [--backup-dir <absolute-path>]"]}, sort_keys=True))
        return 0
    request: Request | None = None
    try:
        request = _request()
        action, values = _parse(args, request)
        safe = _safe_request(request)
        if action == "status":
            result = _status_receipt()
        elif action == "up":
            result = _up_receipt()
        elif action == "down":
            result = _down_receipt()
        elif action == "authkey":
            result = _authkey_receipt(values.get("key"))
        else:
            result = _tailnet(values.get("name", ""), values.get("backup-dir"))
        result = attach(result, safe)
    except EnvelopeError:
        result = _receipt("unknown", False, "tailscale-envelope-invalid", attempt="read-envelope")
    except Refused as error:
        result = _receipt("unknown", False, error.signal, attempt="validate-request")
        if request is not None:
            result = attach(result, _safe_request(request))
    except Exception:
        result = _receipt("unknown", False, "tailscale-operation-failed", attempt="bounded-operation")
        if request is not None:
            result = attach(result, _safe_request(request))
    result = _scrub(result)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

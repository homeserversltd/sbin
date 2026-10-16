"""PIA OpenVPN sibling implementation; no provider policy lives here."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from agathodaimon.transmission import runtime as rt

TUNNEL_INTERFACE = "tun06"
TUNNEL_PROTOCOL = "udp"
TUNNEL_PORT = 1198
_IP = rt.IP
_OPENVPN = "/usr/sbin/openvpn"
_BAND = Path(__file__).resolve().parents[1]
_CA_FILE = _BAND / "ca.rsa.2048.crt"
_RUNTIME_DIR = "/run/agathodaimon/transmission/pia"


def interface_name() -> str:
    return TUNNEL_INTERFACE


def _run(argv: list[str], *, step: str, timeout: int = 15) -> subprocess.CompletedProcess[bytes]:
    result = rt.run(argv, timeout=timeout, step=step)
    if result.returncode != 0:
        raise rt.TransmissionError("transmission-openvpn-command-failed", step)
    return result


def _valid_endpoint(endpoint: dict[str, Any]) -> tuple[str, str]:
    address, hostname = endpoint.get("vpnAddress"), endpoint.get("vpnHostname")
    try:
        parsed = ipaddress.ip_address(address)
    except (TypeError, ValueError):
        raise rt.TransmissionError("transmission-provider-endpoint-invalid", "vpn-endpoint") from None
    if parsed.version != 4 or not isinstance(hostname, str) or not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", hostname):
        raise rt.TransmissionError("transmission-provider-endpoint-invalid", "vpn-endpoint")
    return parsed.compressed, hostname


def _route_rows(namespace: str) -> list[dict[str, Any]]:
    result = rt.run([_IP, "-j", "-n", namespace, "-4", "route", "show"],
                    step="openvpn-endpoint-route-read")
    if result.returncode != 0:
        raise rt.TransmissionError("transmission-vpn-endpoint-route-unavailable", "endpoint-route")
    try:
        rows = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise rt.TransmissionError("transmission-vpn-endpoint-route-unavailable", "endpoint-route") from None
    if not isinstance(rows, list):
        raise rt.TransmissionError("transmission-vpn-endpoint-route-unavailable", "endpoint-route")
    return [row for row in rows if isinstance(row, dict)]


def _route_guard_matches(namespace: str, address: str) -> bool:
    return any(route.get("dst") in {address, address + "/32"}
               and route.get("dev") == rt.NS_VETH and route.get("gateway") == rt.NS_GATEWAY
               for route in _route_rows(namespace))


def _ensure_route_guard(namespace: str, address: str) -> bool:
    matching = [route for route in _route_rows(namespace)
                if route.get("dst") in {address, address + "/32"}]
    if matching:
        if any(route.get("dev") == rt.NS_VETH and route.get("gateway") == rt.NS_GATEWAY
               for route in matching):
            return False
        raise rt.TransmissionError("transmission-vpn-endpoint-route-conflict", "endpoint-route")
    _run([_IP, "-n", namespace, "-4", "route", "add", address + "/32",
          "via", rt.NS_GATEWAY, "dev", rt.NS_VETH], step="openvpn-endpoint-route-add")
    return True


def _remove_route_guard(namespace: str, address: str) -> None:
    if _route_guard_matches(namespace, address):
        _run([_IP, "-n", namespace, "-4", "route", "del", address + "/32",
              "via", rt.NS_GATEWAY, "dev", rt.NS_VETH], step="openvpn-endpoint-route-remove")


def _route_uses_tunnel(namespace: str) -> bool:
    result = rt.run([_IP, "-j", "-n", namespace, "-4", "route", "get", "1.1.1.1"],
                    step="openvpn-route-health")
    if result.returncode != 0:
        return False
    try:
        routes = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return False
    return isinstance(routes, list) and any(
        isinstance(row, dict) and row.get("dev") == TUNNEL_INTERFACE for row in routes)


def _private_directory() -> Path:
    path = rt.runtime_path(_RUNTIME_DIR)
    try:
        os.makedirs(path.parent, mode=0o755, exist_ok=True)
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        info = os.lstat(path)
    except OSError:
        raise rt.TransmissionError("transmission-pia-runtime-unavailable", "pia-runtime-files") from None
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o700
            or (rt._scratch_root() is None and info.st_uid != 0)):
        raise rt.TransmissionError("transmission-pia-runtime-unavailable", "pia-runtime-files")
    return path


def _write_files(endpoint: dict[str, Any], username: str, password: str
                 ) -> tuple[str, tuple[int, int], str, tuple[int, int]]:
    _private_directory()
    if any(ch in username + password for ch in "\r\n\x00") or not username or not password:
        raise rt.TransmissionError("transmission-pia-auth-response-invalid", "vpn-auth")
    nonce = f"{os.getpid()}-{secrets.token_hex(12)}"
    auth_path = f"{_RUNTIME_DIR}/openvpn-auth-{nonce}"
    config_path = f"{_RUNTIME_DIR}/openvpn-{nonce}.conf"
    mapped_auth = rt.runtime_path(auth_path)
    mapped_config = rt.runtime_path(config_path)
    auth_identity = config_identity = None
    address, hostname = _valid_endpoint(endpoint)
    port = endpoint.get("vpnPort", TUNNEL_PORT)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise rt.TransmissionError("transmission-provider-endpoint-invalid", "vpn-endpoint")
    legacy_profile = port == TUNNEL_PORT
    ca_file = _CA_FILE if legacy_profile else _BAND / "ca.rsa.4096.crt"
    cipher, auth = (("aes-128-cbc", "sha1") if legacy_profile
                    else ("aes-256-cbc", "sha256"))
    for value in (str(mapped_auth), str(mapped_config), str(ca_file)):
        if any(ch.isspace() or ch in "\r\n\x00\"" for ch in value):
            raise rt.TransmissionError("transmission-pia-runtime-path-invalid", "pia-runtime-files")
    try:
        auth_identity = rt.write_atomic(auth_path, f"{username}\n{password}\n".encode("utf-8"), 0o600)
        config = (
            "client\n"
            f"dev {TUNNEL_INTERFACE}\nproto udp\n"
            f"remote {address} {port}\n"
            f"route {address} 255.255.255.255 net_gateway\n"
            "redirect-gateway def1\n"
            "nobind\nresolv-retry infinite\npersist-key\npersist-tun\n"
            "auth-nocache\ntls-client\nremote-cert-tls server\n"
            f"verify-x509-name {hostname} name\n"
            f"auth-user-pass {mapped_auth}\nca {ca_file}\n"
            f"cipher {cipher}\nauth {auth}\nreneg-sec 0\nverb 3\n"
        )
        config_identity = rt.write_atomic(config_path, config.encode("utf-8"), 0o600)
        for logical, identity in ((auth_path, auth_identity), (config_path, config_identity)):
            info = os.stat(rt.runtime_path(logical), follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or (rt._scratch_root() is None and info.st_uid != 0)
                    or (info.st_dev, info.st_ino) != identity):
                raise OSError("runtime-file-readback-invalid")
        return config_path, config_identity, auth_path, auth_identity
    except Exception as failure:
        if config_identity is not None:
            rt.safe_unlink(config_path, config_identity)
        if auth_identity is not None:
            rt.safe_unlink(auth_path, auth_identity)
        if isinstance(failure, rt.TransmissionError):
            raise
        raise rt.TransmissionError("transmission-pia-runtime-file-create-failed", "pia-runtime-files") from None


class _Tunnel:
    def __init__(self, namespace: str, process: subprocess.Popen[bytes],
                 config_path: str, config_identity: tuple[int, int],
                 auth_path: str, auth_identity: tuple[int, int],
                 endpoint_address: str, route_owned: bool, secrets_to_redact: tuple[str, ...]):
        self.namespace = namespace
        self.process = process
        self.config_path = config_path
        self.config_identity = config_identity
        self.auth_path = auth_path
        self.auth_identity = auth_identity
        self.endpoint_address = endpoint_address
        self.route_owned = route_owned
        self.secrets_to_redact = secrets_to_redact
        self.last_diagnostic: str | None = None
        self.log_thread = threading.Thread(target=self._drain_log, name="transmission-openvpn-log", daemon=True)
        self.log_thread.start()

    def _emit_log_line(self, raw: bytes, *, omitted: bool = False) -> None:
        message = ("OpenVPN diagnostic line omitted (line exceeded bound)" if omitted
                   else rt._safe_diagnostic(raw, self.secrets_to_redact))
        if not message:
            return
        self.last_diagnostic = message[:160]
        line = json.dumps({"kind": "transmission-vpn", "protocol": "openvpn",
                           "diagnostic": message[:120]}, separators=(",", ":"))
        if len(line.encode("utf-8")) < 1024:
            print(line, flush=True)

    def _drain_log(self) -> None:
        stream = self.process.stdout
        if stream is None:
            return
        pending = bytearray()
        dropping = False
        while True:
            chunk = stream.read(4096)
            if not chunk:
                if dropping:
                    self._emit_log_line(b"", omitted=True)
                elif pending:
                    self._emit_log_line(bytes(pending))
                return
            start = 0
            while start < len(chunk):
                newline = chunk.find(b"\n", start)
                complete = newline >= 0
                end = newline if complete else len(chunk)
                piece = chunk[start:end]
                start = end + 1 if complete else len(chunk)
                if dropping:
                    if complete:
                        dropping = False
                        self._emit_log_line(b"", omitted=True)
                    continue
                if len(pending) + len(piece) > 4096:
                    pending.clear()
                    dropping = not complete
                    if complete:
                        self._emit_log_line(b"", omitted=True)
                    continue
                pending.extend(piece)
                if complete:
                    self._emit_log_line(bytes(pending))
                    pending.clear()

    def is_alive(self) -> bool:
        return (self.process.poll() is None and rt.link_up(self.namespace, TUNNEL_INTERFACE)
                and _route_uses_tunnel(self.namespace))

    def wait_ready(self, timeout: float = 60) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if self.process.poll() is not None:
                self.log_thread.join(timeout=0.05)
                detail = ({"tunnelDiagnostic": self.last_diagnostic}
                          if self.last_diagnostic else {})
                raise rt.TransmissionError("transmission-vpn-tunnel-exited", "vpn-tunnel", detail)
            if self.is_alive():
                return True
            if time.monotonic() >= deadline:
                self.log_thread.join(timeout=0.05)
                detail = ({"tunnelDiagnostic": self.last_diagnostic}
                          if self.last_diagnostic else {})
                raise rt.TransmissionError("transmission-vpn-tunnel-not-ready", "vpn-tunnel", detail)
            time.sleep(0.25)

    def stop(self) -> None:
        failures: list[str] = []
        if self.process.poll() is None:
            try:
                os.killpg(self.process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(self.process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    failures.append("transmission-vpn-tunnel-stop-failed")
        self.log_thread.join(timeout=0.25)
        if self.route_owned:
            try:
                _remove_route_guard(self.namespace, self.endpoint_address)
            except rt.TransmissionError as failure:
                failures.append(failure.signal_name)
        for path, identity in ((self.config_path, self.config_identity),
                               (self.auth_path, self.auth_identity)):
            if not rt.safe_unlink(path, identity):
                failures.append("transmission-vpn-runtime-file-cleanup-failed")
        if failures:
            raise rt.TransmissionError("transmission-vpn-teardown-failed", "vpn-teardown",
                                       {"cleanupSignals": failures})


def connect(namespace: str, endpoint: dict[str, Any], token: str, options: dict[str, Any], *,
            dip_credentials: tuple[str, str] | None, dip_info: dict[str, Any] | None,
            retry_call) -> _Tunnel:
    if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", namespace):
        raise rt.TransmissionError("transmission-pia-namespace-invalid", "vpn-connect")
    if options.get("protocol") != "openvpn":
        raise rt.TransmissionError("transmission-vpn-protocol-unknown", "vpn-options", {"field": "protocol"})
    address, _hostname = _valid_endpoint(endpoint)
    if dip_info is not None:
        dip_endpoint = {"vpnAddress": dip_info.get("address"),
                        "vpnHostname": dip_info.get("hostname")}
        dip_address, dip_hostname = _valid_endpoint(dip_endpoint)
        if (dip_address, dip_hostname) != _valid_endpoint(endpoint):
            raise rt.TransmissionError("transmission-provider-endpoint-changed", "vpn-endpoint")
    active_endpoint = dict(endpoint)
    if dip_credentials is not None and dip_info is not None:
        username = "dedicated_ip_" + dip_credentials[1]
        password = dip_info["address"]
    else:
        # PIA's OpenVPN token credential is the paired username/password form.
        username, password = token[:62], token[62:]
        if not password:
            raise rt.TransmissionError("transmission-pia-auth-response-invalid", "vpn-auth")
    config_path = auth_path = None
    config_identity = auth_identity = None
    process = None
    route_owned = False
    try:
        route_owned = _ensure_route_guard(namespace, address)
        active_endpoint["vpnAddress"] = address
        config_path, config_identity, auth_path, auth_identity = _write_files(
            active_endpoint, username, password)
        command = rt.command_argv([_IP, "netns", "exec", namespace, _OPENVPN,
                                   "--config", str(rt.runtime_path(config_path))])
        env = os.environ.copy()
        scratch = rt._scratch_root()
        if scratch is not None:
            env["PATH"] = str(scratch / "bin")
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=env, close_fds=True, start_new_session=True, bufsize=0)
        secrets_to_redact = tuple(value for value in (token, username, password,
                                                      dip_credentials[0] if dip_credentials else None,
                                                      dip_credentials[1] if dip_credentials else None) if value)
        return _Tunnel(namespace, process, config_path, config_identity, auth_path, auth_identity,
                       address, route_owned, secrets_to_redact)
    except Exception as failure:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=3)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if route_owned:
            try:
                _remove_route_guard(namespace, address)
            except Exception:
                pass
        if config_path is not None and config_identity is not None:
            rt.safe_unlink(config_path, config_identity)
        if auth_path is not None and auth_identity is not None:
            rt.safe_unlink(auth_path, auth_identity)
        if isinstance(failure, rt.TransmissionError):
            raise
        raise rt.TransmissionError("transmission-pia-vpn-start-failed", "vpn-connect") from None


def is_alive(tunnel: _Tunnel) -> bool:
    return isinstance(tunnel, _Tunnel) and tunnel.is_alive()


def teardown(tunnel: _Tunnel) -> None:
    if isinstance(tunnel, _Tunnel):
        tunnel.stop()

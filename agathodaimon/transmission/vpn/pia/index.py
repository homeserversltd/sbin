"""PIA OpenVPN tunnel and port-forward provider face."""
from __future__ import annotations

import base64
import ipaddress
import json
import math
import os
import re
import secrets
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
from typing import Any

from agathodaimon.transmission import runtime as rt

TUNNEL_INTERFACE = "tun06"
KEEPALIVE_INTERVAL = 900
_AUTH_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
_SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
_RUNTIME_DIR = "/run/agathodaimon/transmission/pia"
_IP = "/usr/sbin/ip"
_OPENVPN = "/usr/sbin/openvpn"
_CA_FILE = Path(__file__).resolve().with_name("ca.rsa.2048.crt")
_API_CA_FILE = Path(__file__).resolve().with_name("ca.rsa.4096.crt")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class _Endpoint:
    meta_hostname: str
    meta_address: str
    vpn_hostname: str
    vpn_address: str


@dataclass(frozen=True)
class _Signature:
    payload: str
    signature: str
    port: int
    expires_at: float


class _Tunnel:
    def __init__(self, namespace: str, process: subprocess.Popen[bytes],
                 config_path: str, config_id: tuple[int, int],
                 auth_path: str, auth_id: tuple[int, int]):
        self.namespace = namespace
        self.process = process
        self.config_path = config_path
        self.config_id = config_id
        self.auth_path = auth_path
        self.auth_id = auth_id

    def wait_ready(self, timeout: float = 60) -> bool:
        deadline = time.monotonic() + max(0, timeout)
        while True:
            if self.process.poll() is not None:
                raise rt.TransmissionError("transmission-vpn-tunnel-exited", "vpn-tunnel")
            if rt.link_up(self.namespace, TUNNEL_INTERFACE):
                return True
            if time.monotonic() >= deadline:
                raise rt.TransmissionError("transmission-vpn-tunnel-not-ready", "vpn-tunnel")
            time.sleep(0.25)

    def stop(self) -> None:
        failures: list[str] = []
        try:
            _terminate_process(self.process)
        except Exception as failure:
            failures.append(failure.signal_name if isinstance(failure, rt.TransmissionError)
                            else "transmission-vpn-tunnel-stop-failed")
        for path, identity in ((self.config_path, self.config_id), (self.auth_path, self.auth_id)):
            try:
                if not rt.safe_unlink(path, identity):
                    failures.append("transmission-vpn-runtime-file-cleanup-failed")
            except Exception:
                failures.append("transmission-vpn-runtime-file-cleanup-failed")
        if failures:
            raise rt.TransmissionError("transmission-vpn-teardown-failed", "vpn-teardown",
                                       {"cleanupSignals": failures})


@dataclass
class _State:
    tunnel: _Tunnel | None = None
    endpoint: _Endpoint | None = None
    token: str | None = None
    signed: _Signature | None = None


_state = _State()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            raise rt.TransmissionError("transmission-vpn-tunnel-stop-failed", "vpn-teardown") from None


def _endpoint_from_serverlist() -> _Endpoint:
    try:
        status, _headers, raw = rt._curl_http(_SERVERLIST_URL, step="pia-serverlist")
    except rt.TransmissionError:
        raise
    except Exception:
        raise rt.TransmissionError("transmission-pia-serverlist-failed", "pia-serverlist") from None
    if status != 200:
        raise rt.TransmissionError("transmission-pia-serverlist-failed", "pia-serverlist")
    try:
        data = json.loads(raw.splitlines()[0].decode("utf-8"))
        regions = data["regions"]
        if not isinstance(regions, list):
            raise ValueError
        for region in regions:
            if not isinstance(region, dict) or region.get("port_forward") is not True:
                continue
            servers = region.get("servers")
            meta_servers = servers.get("meta") if isinstance(servers, dict) else None
            udp_servers = servers.get("ovpnudp") if isinstance(servers, dict) else None
            if not isinstance(meta_servers, list) or not meta_servers or not isinstance(udp_servers, list):
                continue
            meta = meta_servers[0]
            if not isinstance(meta, dict):
                continue
            meta_hostname = meta.get("cn")
            meta_address = meta.get("ip")
            if (not isinstance(meta_hostname, str) or not _HOST_RE.fullmatch(meta_hostname)
                    or not isinstance(meta_address, str)):
                continue
            try:
                parsed_meta = ipaddress.ip_address(meta_address)
            except (TypeError, ValueError):
                continue
            if parsed_meta.version != 4:
                continue
            for server in udp_servers:
                if not isinstance(server, dict):
                    continue
                vpn_hostname = server.get("cn")
                address = server.get("ip")
                if not isinstance(vpn_hostname, str) or not _HOST_RE.fullmatch(vpn_hostname):
                    continue
                if not isinstance(address, str):
                    continue
                try:
                    parsed_ip = ipaddress.ip_address(address)
                except (TypeError, ValueError):
                    continue
                if parsed_ip.version == 4:
                    return _Endpoint(meta_hostname, parsed_meta.compressed,
                                     vpn_hostname, parsed_ip.compressed)
    except (IndexError, KeyError, TypeError, UnicodeError, ValueError, json.JSONDecodeError):
        raise rt.TransmissionError("transmission-pia-serverlist-invalid", "pia-serverlist") from None
    raise rt.TransmissionError("transmission-pia-forward-region-unavailable", "pia-serverlist")


def _token(username: str, password: str) -> str:
    try:
        status, _headers, raw = rt._curl_http(
            _AUTH_URL, form={"username": username, "password": password}, step="pia-auth")
    except rt.TransmissionError:
        raise
    except Exception:
        raise rt.TransmissionError("transmission-pia-auth-failed", "pia-auth") from None
    if status != 200:
        raise rt.TransmissionError("transmission-pia-auth-failed", "pia-auth")
    try:
        result = json.loads(raw.decode("utf-8"))
        value = result.get("token") if isinstance(result, dict) else None
    except (UnicodeError, json.JSONDecodeError):
        value = None
    if not isinstance(value, str) or not value or any(ch in value for ch in "\r\n\x00"):
        raise rt.TransmissionError("transmission-pia-auth-response-invalid", "pia-auth")
    return value


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


def _write_openvpn_files(endpoint: _Endpoint, token: str
                         ) -> tuple[str, tuple[int, int], str, tuple[int, int]]:
    directory = _private_directory()
    nonce = f"{os.getpid()}-{secrets.token_hex(12)}"
    auth_path = f"{_RUNTIME_DIR}/auth-{nonce}"
    config_path = f"{_RUNTIME_DIR}/openvpn-{nonce}.conf"
    mapped_auth = rt.runtime_path(auth_path)
    mapped_config = rt.runtime_path(config_path)
    for value in (str(mapped_auth), str(mapped_config), str(_CA_FILE), str(_API_CA_FILE)):
        if any(ch.isspace() or ch in "\r\n\x00\"" for ch in value):
            raise rt.TransmissionError("transmission-pia-runtime-path-invalid", "pia-runtime-files")

    auth_id = None
    config_id = None
    try:
        auth_id = rt.write_atomic(auth_path,
                                  f"{token[:62]}\n{token[62:]}\n".encode("utf-8"), 0o600)
        conf = (
            "client\n"
            f"dev {TUNNEL_INTERFACE}\n"
            "proto udp\n"
            f"remote {endpoint.vpn_address} 1198\n"
            "nobind\nresolv-retry infinite\npersist-key\npersist-tun\n"
            "tls-client\nremote-cert-tls server\n"
            f"verify-x509-name {endpoint.vpn_hostname} name\n"
            f"auth-user-pass {mapped_auth}\nca {_CA_FILE}\n"
            "cipher aes-128-cbc\nauth sha1\nreneg-sec 0\nverb 1\n"
        )
        config_id = rt.write_atomic(config_path, conf.encode("utf-8"), 0o600)
        for logical, identity in ((auth_path, auth_id), (config_path, config_id)):
            info = os.stat(rt.runtime_path(logical), follow_symlinks=False)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                    or (rt._scratch_root() is None and info.st_uid != 0)
                    or (info.st_dev, info.st_ino) != identity):
                raise OSError("unsafe-runtime-file")
        return config_path, config_id, auth_path, auth_id
    except Exception as failure:
        if config_id is not None:
            rt.safe_unlink(config_path, config_id)
        if auth_id is not None:
            rt.safe_unlink(auth_path, auth_id)
        if isinstance(failure, rt.TransmissionError):
            raise
        raise rt.TransmissionError("transmission-pia-runtime-file-create-failed", "pia-runtime-files") from None


def connect(namespace: str) -> _Tunnel:
    if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", namespace):
        raise rt.TransmissionError("transmission-pia-namespace-invalid", "vpn-connect")
    if _state.tunnel is not None:
        if _state.tunnel.process.poll() is None:
            raise rt.TransmissionError("transmission-pia-tunnel-already-active", "vpn-connect")
        teardown()

    endpoint = _endpoint_from_serverlist()
    config_path = auth_path = None
    config_id = auth_id = None
    process = None
    try:
        with rt.exported_credentials("pia") as (username, password):
            token = _token(username, password)
            config_path, config_id, auth_path, auth_id = _write_openvpn_files(endpoint, token)
        command = rt.command_argv([
            _IP, "netns", "exec", namespace, _OPENVPN,
            "--config", str(rt.runtime_path(config_path)),
        ])
        env = os.environ.copy()
        scratch = rt._scratch_root()
        if scratch is not None:
            env["PATH"] = str(scratch / "bin")
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, env=env, close_fds=True, start_new_session=True)
        tunnel = _Tunnel(namespace, process, config_path, config_id, auth_path, auth_id)
        _state.tunnel = tunnel
        _state.endpoint = endpoint
        _state.token = token
        _state.signed = None
        return tunnel
    except rt.TransmissionError:
        if process is not None:
            _terminate_process(process)
        if config_path is not None and config_id is not None:
            rt.safe_unlink(config_path, config_id)
        if auth_path is not None and auth_id is not None:
            rt.safe_unlink(auth_path, auth_id)
        raise
    except Exception:
        if process is not None:
            _terminate_process(process)
        if config_path is not None and config_id is not None:
            rt.safe_unlink(config_path, config_id)
        if auth_path is not None and auth_id is not None:
            rt.safe_unlink(auth_path, auth_id)
        raise rt.TransmissionError("transmission-pia-vpn-start-failed", "vpn-connect") from None


def _api_json(endpoint: _Endpoint, namespace: str, path: str,
              query: dict[str, str], step: str) -> dict[str, Any]:
    gateway = _tunnel_gateway(namespace)
    url = f"https://{endpoint.meta_hostname}:19999/{path}?{urlencode(query)}"
    try:
        status, _headers, raw = rt._curl_http(
            url, connect_to=f"{endpoint.meta_hostname}::{gateway}:",
            ca_file=str(_API_CA_FILE), namespace=namespace, step=step)
    except rt.TransmissionError:
        raise
    except Exception:
        raise rt.TransmissionError("transmission-pia-api-failed", step) from None
    if status != 200:
        raise rt.TransmissionError("transmission-pia-api-failed", step)
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise rt.TransmissionError("transmission-pia-api-response-invalid", step) from None
    if not isinstance(result, dict) or result.get("status") != "OK":
        raise rt.TransmissionError("transmission-pia-api-rejected", step)
    return result


def _expiry(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError
    try:
        result = float(value)
    except (TypeError, ValueError):
        if not isinstance(value, str):
            raise ValueError from None
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise ValueError from None
    if not math.isfinite(result) or result <= time.time():
        raise ValueError
    return result


def _tunnel_gateway(namespace: str) -> str:
    result = rt.run([rt.IP, "-j", "-n", namespace, "-4", "route", "show"],
                    step="pia-gateway-readback")
    if result.returncode != 0:
        raise rt.TransmissionError("transmission-pia-tunnel-gateway-unavailable", "pia-gateway")
    try:
        routes = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise rt.TransmissionError("transmission-pia-tunnel-gateway-unavailable", "pia-gateway") from None
    if isinstance(routes, list):
        for row in routes:
            if not isinstance(row, dict) or row.get("dev") != TUNNEL_INTERFACE:
                continue
            gateway = row.get("gateway")
            if not isinstance(gateway, str):
                continue
            try:
                parsed = ipaddress.ip_address(gateway)
            except (TypeError, ValueError):
                continue
            if parsed.version == 4:
                return parsed.compressed

    addresses = rt.run([rt.IP, "-j", "-n", namespace, "-4", "addr", "show",
                        "dev", TUNNEL_INTERFACE], step="pia-gateway-peer-readback")
    if addresses.returncode == 0:
        try:
            rows = json.loads(addresses.stdout.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            rows = []
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict) or row.get("ifname") != TUNNEL_INTERFACE:
                    continue
                for info in row.get("addr_info", []):
                    if not isinstance(info, dict):
                        continue
                    peer = info.get("peer")
                    if not isinstance(peer, str):
                        continue
                    try:
                        parsed = (ipaddress.ip_interface(peer).ip
                                  if "/" in peer
                                  else ipaddress.ip_address(peer))
                    except (TypeError, ValueError):
                        continue
                    if parsed.version == 4:
                        return parsed.compressed
    raise rt.TransmissionError("transmission-pia-tunnel-gateway-unavailable", "pia-gateway")


def _get_signature(namespace: str, endpoint: _Endpoint, token: str) -> _Signature:
    result = _api_json(endpoint, namespace, "getSignature", {"token": token}, "pia-signature")
    payload, signature = result.get("payload"), result.get("signature")
    if not isinstance(payload, str) or not isinstance(signature, str) or not signature:
        raise rt.TransmissionError("transmission-pia-signature-invalid", "pia-signature")
    try:
        decoded = base64.b64decode(payload, validate=True).decode("utf-8")
        payload_data = json.loads(decoded)
        port = payload_data.get("port")
        expires_at = _expiry(payload_data.get("expires_at"))
    except (ValueError, UnicodeError, json.JSONDecodeError, AttributeError):
        raise rt.TransmissionError("transmission-pia-signature-invalid", "pia-signature") from None
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise rt.TransmissionError("transmission-pia-signature-invalid", "pia-signature")
    return _Signature(payload, signature, port, expires_at)


def _bind(namespace: str, endpoint: _Endpoint, signed: _Signature) -> None:
    _api_json(endpoint, namespace, "bindPort",
              {"payload": signed.payload, "signature": signed.signature}, "pia-bind-port")


def _live_tunnel() -> _Tunnel:
    tunnel = _state.tunnel
    if tunnel is None:
        raise rt.TransmissionError("transmission-pia-tunnel-unavailable", "vpn-tunnel")
    tunnel.wait_ready(timeout=0)
    return tunnel


def _fresh_token() -> str:
    with rt.exported_credentials("pia") as (username, password):
        return _token(username, password)


def _public_forward(signed: _Signature) -> dict[str, int]:
    return {"port": signed.port, "keepaliveInterval": KEEPALIVE_INTERVAL}


def forward() -> dict[str, int]:
    tunnel = _live_tunnel()
    if _state.endpoint is None or _state.token is None:
        raise rt.TransmissionError("transmission-pia-forward-state-missing", "pia-forward")
    signed = _get_signature(tunnel.namespace, _state.endpoint, _state.token)
    _bind(tunnel.namespace, _state.endpoint, signed)
    _state.signed = signed
    return _public_forward(signed)


def keepalive(current: dict[str, Any]) -> dict[str, int]:
    tunnel = _live_tunnel()
    signed = _state.signed
    endpoint = _state.endpoint
    if (not isinstance(current, dict) or isinstance(current.get("port"), bool)
            or not isinstance(current.get("port"), int)
            or current.get("keepaliveInterval") != KEEPALIVE_INTERVAL
            or signed is None or endpoint is None or current.get("port") != signed.port):
        raise rt.TransmissionError("transmission-pia-forward-state-invalid", "pia-keepalive")
    if signed.expires_at <= time.time() + KEEPALIVE_INTERVAL + 60:
        token = _fresh_token()
        signed = _get_signature(tunnel.namespace, endpoint, token)
        _state.token = token
    _bind(tunnel.namespace, endpoint, signed)
    _state.signed = signed
    return _public_forward(signed)


def teardown() -> None:
    tunnel = _state.tunnel
    try:
        if tunnel is not None:
            tunnel.stop()
    finally:
        _state.tunnel = None
        _state.endpoint = None
        _state.token = None
        _state.signed = None

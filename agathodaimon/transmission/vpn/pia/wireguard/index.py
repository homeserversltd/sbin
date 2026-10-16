"""PIA WireGuard sibling with ephemeral in-memory private-key material."""
from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
import re
import time
from typing import Any, Mapping
from urllib.parse import urlencode
from pathlib import Path

from agathodaimon.transmission import runtime as rt

TUNNEL_INTERFACE = "piawg"
_IP = rt.IP
_WG = "/usr/bin/wg"
_API_CA_FILE = Path(__file__).resolve().parents[1] / "ca.rsa.4096.crt"
_KEEPALIVE_INTERVAL = 900


def interface_name() -> str:
    return TUNNEL_INTERFACE


def _wg_redactions(*materials: bytes | None) -> tuple[str, ...]:
    values: list[str] = []
    for material in materials:
        if not material:
            continue
        text = material.decode("utf-8", "replace")
        values.append(text)
        for row in text.splitlines():
            row = row.strip()
            if row:
                values.append(row)
                _separator, found, value = row.partition("=")
                if found and value.strip():
                    values.append(value.strip())
    return tuple(dict.fromkeys(values))


def _wg_command(argv: list[str], *, step: str, input_data: bytes | None = None,
                timeout: int = 15, failure_signal: str = "transmission-wireguard-command-failed",
                redact: tuple[bytes, ...] = (), redact_stdout: bool = False) -> Any:
    try:
        result = rt.run(argv, input_data=input_data, timeout=timeout, step=step,
                        capture_stderr=True)
    except rt.TransmissionError as failure:
        diagnostic = ("wg timed out" if failure.signal_name == "transmission-command-timeout"
                      else "wg unavailable" if failure.signal_name == "transmission-command-unavailable"
                      else "wg command failed")
        failure.detail.update({"call": step, "wgError": diagnostic})
        raise
    if result.returncode != 0:
        secrets_to_redact = _wg_redactions(input_data, *redact,
                                           result.stdout if redact_stdout else None)
        diagnostic = rt._safe_diagnostic(result.stderr, secrets_to_redact)
        if not diagnostic:
            diagnostic = f"wg exited {result.returncode}"
        raise rt.TransmissionError(failure_signal, step,
                                   {"call": step, "wgError": diagnostic})
    return result


def _run(argv: list[str], *, step: str, input_data: bytes | None = None,
         timeout: int = 15) -> bytes:
    return _wg_command(argv, input_data=input_data, timeout=timeout, step=step).stdout


def _ipv4(value: Any, step: str) -> str:
    if not isinstance(value, str):
        raise rt.TransmissionError("transmission-pia-wireguard-response-invalid", step)
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        raise rt.TransmissionError("transmission-pia-wireguard-response-invalid", step) from None
    if parsed.version != 4:
        raise rt.TransmissionError("transmission-pia-wireguard-response-invalid", step)
    return parsed.compressed


def _host(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", value))


def _route_rows(namespace: str) -> list[dict[str, Any]]:
    result = rt.run([_IP, "-j", "-n", namespace, "-4", "route", "show"],
                    step="wireguard-route-read")
    if result.returncode != 0:
        raise rt.TransmissionError("transmission-wireguard-route-unavailable", "wireguard-route-read")
    try:
        rows = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise rt.TransmissionError("transmission-wireguard-route-unavailable", "wireguard-route-read") from None
    if not isinstance(rows, list):
        raise rt.TransmissionError("transmission-wireguard-route-unavailable", "wireguard-route-read")
    return [row for row in rows if isinstance(row, dict)]


def _ensure_endpoint_route(namespace: str, address: str) -> bool:
    routes = _route_rows(namespace)
    matching = [route for route in routes
                if route.get("dst") in {address, address + "/32"}]
    if matching:
        if any(route.get("dev") == rt.NS_VETH and route.get("gateway") == rt.NS_GATEWAY
               for route in matching):
            return False
        raise rt.TransmissionError("transmission-vpn-endpoint-route-conflict", "endpoint-route")
    _run([_IP, "-n", namespace, "-4", "route", "add", address + "/32",
          "via", rt.NS_GATEWAY, "dev", rt.NS_VETH], step="wireguard-endpoint-route-add")
    return True


def _remove_endpoint_route(namespace: str, address: str) -> None:
    if any(route.get("dst") in {address, address + "/32"}
           and route.get("dev") == rt.NS_VETH and route.get("gateway") == rt.NS_GATEWAY
           for route in _route_rows(namespace)):
        _run([_IP, "-n", namespace, "-4", "route", "del", address + "/32",
              "via", rt.NS_GATEWAY, "dev", rt.NS_VETH], step="wireguard-endpoint-route-remove")


def _default_route_is(namespace: str, *, device: str, gateway: str | None = None) -> bool:
    return any(route.get("dst") in {None, "default"} and route.get("dev") == device
               and route.get("gateway") == gateway for route in _route_rows(namespace))


def _install_tunnel_default(namespace: str) -> None:
    routes = _route_rows(namespace)
    defaults = [route for route in routes if route.get("dst") in {None, "default"}]
    if (len(defaults) != 1 or defaults[0].get("dev") != rt.NS_VETH
            or defaults[0].get("gateway") != rt.NS_GATEWAY):
        raise rt.TransmissionError("transmission-wireguard-default-route-conflict", "wireguard-route")
    _run([_IP, "-n", namespace, "-4", "route", "replace", "default", "dev", TUNNEL_INTERFACE],
         step="wireguard-default-route")
    if not _default_route_is(namespace, device=TUNNEL_INTERFACE):
        raise rt.TransmissionError("transmission-wireguard-default-route-readback-mismatch", "wireguard-route")


def _restore_namespace_default(namespace: str) -> None:
    if _default_route_is(namespace, device=TUNNEL_INTERFACE):
        _run([_IP, "-n", namespace, "-4", "route", "replace", "default",
              "via", rt.NS_GATEWAY, "dev", rt.NS_VETH], step="wireguard-default-route-restore")


def _public_key(value: Any) -> str:
    if not isinstance(value, str):
        raise rt.TransmissionError("transmission-pia-wireguard-response-invalid", "wireguard-response")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise rt.TransmissionError("transmission-pia-wireguard-response-invalid", "wireguard-response") from None
    if len(decoded) != 32:
        raise rt.TransmissionError("transmission-pia-wireguard-response-invalid", "wireguard-response")
    return value


def _generate_keypair() -> tuple[bytearray, str]:
    private_result = _wg_command([_WG, "genkey"], timeout=10, step="wireguard-keygen",
                                 failure_signal="transmission-wireguard-keygen-failed",
                                 redact_stdout=True)
    private_key = bytearray(private_result.stdout.strip())
    try:
        decoded = base64.b64decode(bytes(private_key), validate=True)
        if len(decoded) != 32:
            raise ValueError
        public_result = _wg_command(
            [_WG, "pubkey"], input_data=bytes(private_key) + b"\n", timeout=10,
            step="wireguard-public-key", failure_signal="transmission-wireguard-keygen-failed",
            redact=(bytes(private_key),))
        public_key = _public_key(public_result.stdout.decode("ascii", "strict").strip())
        return private_key, public_key
    except rt.TransmissionError:
        private_key[:] = b"\x00" * len(private_key)
        raise
    except (ValueError, UnicodeError):
        private_key[:] = b"\x00" * len(private_key)
        raise rt.TransmissionError("transmission-wireguard-keygen-failed", "wireguard-keygen") from None


def _add_key(endpoint: dict[str, Any], public_key: str, token: str,
             dip_credentials: tuple[str, str] | None,
             dip_info: dict[str, Any] | None, retry_call) -> dict[str, Any]:
    hostname = endpoint.get("vpnHostname")
    address = _ipv4(endpoint.get("vpnAddress"), "wireguard-endpoint")
    if not _host(hostname):
        raise rt.TransmissionError("transmission-provider-endpoint-invalid", "wireguard-endpoint")
    query = {"pubkey": public_key}
    username: str | None = None
    password: str | None = None
    headers: Mapping[str, str] | None = None
    if dip_credentials is not None and dip_info is not None:
        username = "dedicated_ip_" + dip_credentials[1]
        password = _ipv4(dip_info.get("address"), "wireguard-dedicated-ip")
        headers = {"Host": str(hostname)}
    else:
        query["pt"] = token
    url = f"https://{hostname}:1337/addKey?{urlencode(query)}"

    def request() -> dict[str, Any]:
        status, _headers, raw = rt._curl_http(
            url, username=username, password=password, headers=headers,
            connect_to=f"{hostname}:1337:{address}:1337", ca_file=str(_API_CA_FILE),
            method="GET", step="pia-add-key")
        if status != 200:
            raise rt.TransmissionError("transmission-pia-add-key-failed", "pia-add-key",
                                       {"call": "addKey", "curlError": f"HTTP status {status}"})
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            raise rt.TransmissionError("transmission-pia-add-key-response-invalid", "pia-add-key",
                                       {"call": "addKey", "curlError": "invalid JSON response"}) from None
        if not isinstance(value, dict) or value.get("status") != "OK":
            raise rt.TransmissionError("transmission-pia-add-key-rejected", "pia-add-key",
                                       {"call": "addKey", "curlError": "PIA rejected request"})
        server_key = _public_key(value.get("server_key"))
        peer_value = value.get("peer_ip")
        try:
            peer = ipaddress.ip_interface(peer_value if isinstance(peer_value, str) and "/" in peer_value
                                          else str(peer_value) + "/32")
        except ValueError:
            raise rt.TransmissionError("transmission-pia-add-key-response-invalid", "pia-add-key",
                                       {"call": "addKey", "curlError": "invalid peer address"}) from None
        if peer.version != 4:
            raise rt.TransmissionError("transmission-pia-add-key-response-invalid", "pia-add-key",
                                       {"call": "addKey", "curlError": "invalid peer address family"})
        raw_port = value.get("server_port")
        if isinstance(raw_port, bool) or not isinstance(raw_port, (int, str)):
            raise rt.TransmissionError("transmission-pia-add-key-response-invalid", "pia-add-key",
                                       {"call": "addKey", "curlError": "invalid peer port"})
        try:
            server_port = int(raw_port)
        except ValueError:
            server_port = 0
        if not 1 <= server_port <= 65535:
            raise rt.TransmissionError("transmission-pia-add-key-response-invalid", "pia-add-key",
                                       {"call": "addKey", "curlError": "invalid peer port"})
        server_vip = value.get("server_vip")
        if server_vip is not None:
            server_vip = _ipv4(server_vip, "pia-add-key-server-vip")
        return {"serverKey": server_key, "peerAddress": peer.with_prefixlen,
                "serverPort": server_port, "serverVip": server_vip}
    return retry_call("addKey", request)


def _interface_exists(namespace: str) -> bool:
    return bool(rt._link_data(namespace, TUNNEL_INTERFACE))


def _handshake_fresh(namespace: str) -> bool:
    result = rt.run([_IP, "netns", "exec", namespace, _WG, "show", TUNNEL_INTERFACE,
                     "latest-handshakes"], timeout=8, step="wireguard-handshake-read")
    if result.returncode != 0:
        return False
    now = int(time.time())
    try:
        rows = result.stdout.decode("utf-8").splitlines()
    except UnicodeError:
        return False
    for row in rows:
        fields = row.split()
        if len(fields) != 2:
            continue
        try:
            stamp = int(fields[1])
        except ValueError:
            continue
        if stamp > 0 and 0 <= now - stamp < 180:
            return True
    return False


class _Tunnel:
    def __init__(self, namespace: str, endpoint_address: str, endpoint_route_owned: bool,
                 peer_address: str, server_vip: str | None):
        self.namespace = namespace
        self.endpoint_address = endpoint_address
        self.endpoint_route_owned = endpoint_route_owned
        self.peer_address = peer_address
        self.server_vip = server_vip
        self.interface_owned = True
        self.default_route_owned = True

    def is_alive(self) -> bool:
        return (_interface_exists(self.namespace)
                and rt.link_up(self.namespace, TUNNEL_INTERFACE)
                and _default_route_is(self.namespace, device=TUNNEL_INTERFACE)
                and _handshake_fresh(self.namespace))

    def wait_ready(self, timeout: float = 60) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if not _interface_exists(self.namespace):
                raise rt.TransmissionError("transmission-vpn-tunnel-interface-absent", "vpn-tunnel")
            if self.is_alive():
                return True
            if time.monotonic() >= deadline:
                raise rt.TransmissionError("transmission-vpn-tunnel-not-ready", "vpn-tunnel")
            time.sleep(0.5)

    def stop(self) -> None:
        failures: list[str] = []
        if self.default_route_owned:
            try:
                _restore_namespace_default(self.namespace)
            except rt.TransmissionError as failure:
                failures.append(failure.signal_name)
        if self.interface_owned and _interface_exists(self.namespace):
            try:
                _run([_IP, "-n", self.namespace, "link", "delete", "dev", TUNNEL_INTERFACE],
                     step="wireguard-interface-delete")
            except rt.TransmissionError as failure:
                failures.append(failure.signal_name)
            if _interface_exists(self.namespace):
                failures.append("transmission-wireguard-interface-cleanup-failed")
        if self.endpoint_route_owned:
            try:
                _remove_endpoint_route(self.namespace, self.endpoint_address)
            except rt.TransmissionError as failure:
                failures.append(failure.signal_name)
        if failures:
            raise rt.TransmissionError("transmission-vpn-teardown-failed", "vpn-teardown",
                                       {"cleanupSignals": failures})


def connect(namespace: str, endpoint: dict[str, Any], token: str, options: dict[str, Any], *,
            dip_credentials: tuple[str, str] | None, dip_info: dict[str, Any] | None,
            retry_call) -> _Tunnel:
    if not isinstance(namespace, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", namespace):
        raise rt.TransmissionError("transmission-pia-namespace-invalid", "vpn-connect")
    if options.get("protocol") != "wireguard":
        raise rt.TransmissionError("transmission-vpn-protocol-unknown", "vpn-options", {"field": "protocol"})
    endpoint_address = _ipv4(endpoint.get("vpnAddress"), "wireguard-endpoint")
    hostname = endpoint.get("vpnHostname")
    if not _host(hostname):
        raise rt.TransmissionError("transmission-provider-endpoint-invalid", "wireguard-endpoint")
    if _interface_exists(namespace):
        raise rt.TransmissionError("transmission-wireguard-interface-already-present", "wireguard-interface")
    private_key = None
    endpoint_route_owned = False
    interface_owned = False
    default_route_owned = False
    try:
        private_key, public_key = _generate_keypair()
        key_data = _add_key(endpoint, public_key, token, dip_credentials, dip_info, retry_call)
        endpoint_route_owned = _ensure_endpoint_route(namespace, endpoint_address)
        _run([_IP, "-n", namespace, "link", "add", "dev", TUNNEL_INTERFACE, "type", "wireguard"],
             step="wireguard-interface-create")
        interface_owned = True
        peer_config = (
            b"[Interface]\nPrivateKey = " + bytes(private_key) + b"\n\n[Peer]\n"
            + b"PublicKey = " + key_data["serverKey"].encode("ascii") + b"\n"
            + b"AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n"
            + b"Endpoint = " + endpoint_address.encode("ascii") + b":"
            + str(key_data["serverPort"]).encode("ascii") + b"\n"
        )
        _run([_IP, "netns", "exec", namespace, _WG, "setconf", TUNNEL_INTERFACE, "/dev/stdin"],
             step="wireguard-set-config", input_data=peer_config)
        _run([_IP, "-n", namespace, "-4", "addr", "add", key_data["peerAddress"],
              "dev", TUNNEL_INTERFACE], step="wireguard-address")
        _run([_IP, "-n", namespace, "link", "set", "dev", TUNNEL_INTERFACE, "up"],
             step="wireguard-interface-up")
        _install_tunnel_default(namespace)
        default_route_owned = True
        tunnel = _Tunnel(namespace, endpoint_address, endpoint_route_owned,
                         key_data["peerAddress"], key_data["serverVip"])
        tunnel.default_route_owned = default_route_owned
        return tunnel
    except Exception as failure:
        if _default_route_is(namespace, device=TUNNEL_INTERFACE):
            try:
                _restore_namespace_default(namespace)
            except Exception:
                pass
        if interface_owned and _interface_exists(namespace):
            try:
                _run([_IP, "-n", namespace, "link", "delete", "dev", TUNNEL_INTERFACE],
                     step="wireguard-interface-cleanup")
            except Exception:
                pass
        if endpoint_route_owned:
            try:
                _remove_endpoint_route(namespace, endpoint_address)
            except Exception:
                pass
        if isinstance(failure, rt.TransmissionError):
            raise
        raise rt.TransmissionError("transmission-wireguard-setup-failed", "wireguard-connect") from None
    finally:
        if private_key is not None:
            private_key[:] = b"\x00" * len(private_key)


def is_alive(tunnel: _Tunnel) -> bool:
    return isinstance(tunnel, _Tunnel) and tunnel.is_alive()


def teardown(tunnel: _Tunnel) -> None:
    if isinstance(tunnel, _Tunnel):
        tunnel.stop()

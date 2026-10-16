"""PIA provider face; protocol implementations are sibling bands."""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import math
import os
import re
import socket
import stat
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlencode

from agathodaimon.transmission import runtime as rt

_BAND = Path(__file__).resolve().parent
_RUNTIME_DIR = "/run/agathodaimon/transmission/pia"
_ENDPOINT_PATH = _RUNTIME_DIR + "/endpoint.json"
_SERVERLIST_URL = "https://serverlist.piaservers.net/vpninfo/servers/v6"
_AUTH_URL = "https://www.privateinternetaccess.com/api/client/v2/token"
_DEDICATED_IP_URL = "https://www.privateinternetaccess.com/api/client/v2/dedicated_ip"
_API_CA_FILE = _BAND / "ca.rsa.4096.crt"
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_PROTOCOLS = {"openvpn", "wireguard"}
_DNS_SERVER = "10.0.0.242"


@dataclass(frozen=True)
class _Signature:
    payload: str
    signature: str
    port: int
    expires_at: float


@dataclass
class _State:
    endpoint: dict[str, Any] | None = None
    options: dict[str, Any] | None = None
    token: str | None = None
    signed: _Signature | None = None
    tunnel: Any = None
    tunnel_face: Any = None


_state = _State()
_protocol_modules: dict[str, Any] = {}


def select_protocol(protocol: str) -> Any:
    if protocol not in _PROTOCOLS:
        raise rt.TransmissionError("transmission-vpn-protocol-unknown", "vpn-options",
                                   {"field": "protocol"})
    if protocol in _protocol_modules:
        return _protocol_modules[protocol]
    path = _BAND / protocol / "index.py"
    if not path.is_file():
        raise rt.TransmissionError("transmission-provider-protocol-unreadable", "provider-load")
    name = "agathodaimon.face_transmission_vpn_pia_" + protocol
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise rt.TransmissionError("transmission-provider-protocol-unreadable", "provider-load")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "agathodaimon"
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        raise rt.TransmissionError("transmission-provider-protocol-unreadable", "provider-load") from None
    for method in ("connect", "interface_name", "is_alive", "teardown"):
        if not callable(getattr(module, method, None)):
            raise rt.TransmissionError("transmission-provider-protocol-incomplete", "provider-load")
    _protocol_modules[protocol] = module
    return module


def dns_server(selection: str | None) -> str:
    if selection is None:
        return "1.1.1.1"
    if selection == "provider":
        return _DNS_SERVER
    raise rt.TransmissionError("transmission-vpn-dns-unknown", "vpn-options", {"field": "dns"})


def _retry_pia_call(call: str, operation, *, attempts: int = 3):
    last: rt.TransmissionError | None = None
    for index in range(attempts):
        try:
            return operation()
        except rt.TransmissionError as failure:
            last = failure
        except Exception:
            last = rt.TransmissionError("transmission-pia-call-failed", call)
        if index + 1 < attempts:
            time.sleep(min(2.0, 0.5 * (2 ** index)))
    if last is None:
        last = rt.TransmissionError("transmission-pia-call-failed", call)
    detail = dict(last.detail)
    detail["call"] = call
    if "curlError" not in detail:
        detail["curlError"] = "PIA call failed after bounded retries"
    raise rt.TransmissionError(last.signal_name, last.step or call, detail) from None


def _retry_forward_api(call: str, operation) -> dict[str, Any]:
    deadline = time.monotonic() + 30.0
    reserve = rt._CURL_REAP_RESERVE
    delay = 0.5
    last: rt.TransmissionError | None = None
    while True:
        if last is not None and deadline - time.monotonic() <= reserve:
            break
        try:
            return operation(deadline)
        except rt.TransmissionError as failure:
            last = failure
            transport = failure.detail.get("_transport")
            if (not isinstance(transport, Mapping)
                    or transport.get("class") != "pre-request-connection"):
                break
        except Exception:
            last = rt.TransmissionError("transmission-pia-call-failed", call)
            break
        remaining = deadline - time.monotonic()
        if remaining <= reserve:
            break
        sleep_for = min(delay, remaining - reserve)
        if sleep_for <= 0:
            break
        time.sleep(sleep_for)
        delay = min(delay * 2, 2.0)
    if last is None:
        last = rt.TransmissionError("transmission-pia-call-failed", call)
    detail = dict(last.detail)
    detail.pop("_transport", None)
    detail["call"] = call
    if "curlError" not in detail:
        detail["curlError"] = "PIA call failed after bounded retries"
    raise rt.TransmissionError(last.signal_name, last.step or call, detail) from None


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


def _valid_host(value: Any) -> bool:
    return isinstance(value, str) and bool(_HOST_RE.fullmatch(value))


def _valid_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _regions_from_serverlist() -> list[dict[str, Any]]:
    def fetch() -> list[dict[str, Any]]:
        status, _headers, raw = rt._curl_http(_SERVERLIST_URL, step="pia-serverlist")
        if status != 200:
            raise rt.TransmissionError("transmission-pia-serverlist-failed", "pia-serverlist",
                                       {"call": "serverlist", "curlError": f"HTTP status {status}"})
        try:
            data = json.loads(raw.splitlines()[0].decode("utf-8"))
        except (IndexError, UnicodeError, json.JSONDecodeError):
            raise rt.TransmissionError("transmission-pia-serverlist-invalid", "pia-serverlist",
                                       {"call": "serverlist", "curlError": "invalid serverlist JSON"}) from None
        regions = data.get("regions") if isinstance(data, Mapping) else None
        if not isinstance(regions, list):
            raise rt.TransmissionError("transmission-pia-serverlist-invalid", "pia-serverlist",
                                       {"call": "serverlist", "curlError": "regions missing"})
        groups = data.get("groups") if isinstance(data, Mapping) else None
        ovpn_groups = groups.get("ovpnudp") if isinstance(groups, Mapping) else None
        openvpn_port = None
        if isinstance(ovpn_groups, list):
            for group in ovpn_groups:
                ports = group.get("ports") if isinstance(group, Mapping) else None
                if not isinstance(ports, list):
                    continue
                openvpn_port = next((port for port in ports if _valid_port(port)), None)
                if openvpn_port is not None:
                    break
        regional_copies = []
        for item in regions:
            if not isinstance(item, dict):
                continue
            region = dict(item)
            if openvpn_port is not None:
                region["declaredOpenVPNPort"] = openvpn_port
            regional_copies.append(region)
        return regional_copies
    return _retry_pia_call("serverlist", fetch)


def _meta_candidates(region: Mapping[str, Any]) -> list[dict[str, str]]:
    servers = region.get("servers")
    metadata = servers.get("meta") if isinstance(servers, Mapping) else None
    if not isinstance(metadata, list):
        return []
    result = []
    for server in metadata:
        if not isinstance(server, Mapping):
            continue
        host, address = server.get("cn"), server.get("ip")
        if not _valid_host(host) or not isinstance(address, str):
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version == 4:
            result.append({"hostname": host, "address": parsed.compressed})
    return result


def _protocol_server(region: Mapping[str, Any], protocol: str,
                    preferred_hostname: str | None = None) -> dict[str, Any] | None:
    servers = region.get("servers")
    entries = servers.get("ovpnudp" if protocol == "openvpn" else "wg") if isinstance(servers, Mapping) else None
    if not isinstance(entries, list):
        return None
    first_eligible = None
    for server in entries:
        if not isinstance(server, Mapping):
            continue
        hostname, address = server.get("cn"), server.get("ip")
        if not _valid_host(hostname) or not isinstance(address, str):
            continue
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        candidate = {"hostname": hostname, "address": parsed.compressed}
        if protocol == "openvpn":
            port = region.get("declaredOpenVPNPort")
            if _valid_port(port):
                candidate["vpnPort"] = port
        if hostname == preferred_hostname:
            return candidate
        if first_eligible is None:
            first_eligible = candidate
    return first_eligible


def _is_forward_region(region: Mapping[str, Any]) -> bool:
    return region.get("port_forward") is True


def _meta_latency(meta: Mapping[str, str]) -> float | None:
    started = time.monotonic()
    try:
        with socket.create_connection((meta["address"], 443), timeout=0.1):
            latency = time.monotonic() - started
    except OSError:
        return None
    return latency if latency < 0.1 else None


def _latency_pick(regions: list[dict[str, Any]], protocol: str) -> tuple[dict[str, Any], dict[str, str]]:
    eligible: list[tuple[dict[str, Any], dict[str, str]]] = []
    for region in regions:
        if not _is_forward_region(region):
            continue
        region_id = region.get("id")
        server = _protocol_server(region, protocol)
        if not isinstance(region_id, str) or not region_id or server is None:
            continue
        eligible.extend((region, meta) for meta in _meta_candidates(region))
    candidates: list[tuple[float, int, dict[str, Any], dict[str, str]]] = []
    next_index = 0
    outstanding = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        while next_index < len(eligible) or outstanding:
            while next_index < len(eligible) and len(outstanding) < 10:
                region, meta = eligible[next_index]
                future = pool.submit(_meta_latency, meta)
                outstanding[future] = (next_index, region, meta)
                next_index += 1
            completed, _pending = wait(outstanding, return_when=FIRST_COMPLETED)
            for future in completed:
                index, region, meta = outstanding.pop(future)
                latency = future.result()
                if latency is not None:
                    candidates.append((latency, index, region, meta))
    if not candidates:
        raise rt.TransmissionError("transmission-pia-forward-region-unavailable", "region-latency",
                                   {"call": "serverlist", "curlError": "no meta endpoint below 0.1 seconds"})
    _latency, _index, region, meta = min(candidates, key=lambda item: (item[0], item[1]))
    return region, meta


def _select_region(regions: list[dict[str, Any]], options: Mapping[str, Any]
                   ) -> tuple[dict[str, Any], dict[str, str], dict[str, Any]]:
    protocol = options.get("protocol")
    preferred = options.get("region")
    if protocol not in _PROTOCOLS:
        raise rt.TransmissionError("transmission-vpn-protocol-unknown", "vpn-options", {"field": "protocol"})
    if preferred is None:
        region, meta = _latency_pick(regions, protocol)
    else:
        matching = [item for item in regions if item.get("id") == preferred and _is_forward_region(item)]
        if len(matching) != 1:
            raise rt.TransmissionError("transmission-vpn-region-unknown", "region-selection",
                                       {"field": "region"})
        region = matching[0]
        metas = _meta_candidates(region)
        if not metas:
            raise rt.TransmissionError("transmission-vpn-region-unknown", "region-selection",
                                       {"field": "region"})
        meta = metas[0]
    selected = _protocol_server(region, protocol, meta["hostname"])
    if selected is None:
        raise rt.TransmissionError("transmission-vpn-region-unknown", "region-selection",
                                   {"field": "region"})
    return region, meta, selected


def _read_endpoint() -> dict[str, Any] | None:
    try:
        _private_directory()
        raw, metadata = rt.read_regular(_ENDPOINT_PATH, 8192)
        if (stat.S_IMODE(metadata.st_mode) != 0o600
                or (rt._scratch_root() is None and metadata.st_uid != 0)):
            return None
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, rt.TransmissionError):
        return None
    if not isinstance(value, dict):
        return None
    if (not _valid_host(value.get("metaHostname")) or not _valid_host(value.get("vpnHostname"))
            or not isinstance(value.get("regionId"), str)
            or value.get("protocol") not in _PROTOCOLS):
        return None
    if "vpnPort" in value and not _valid_port(value.get("vpnPort")):
        return None
    for field in ("metaAddress", "vpnAddress"):
        try:
            parsed = ipaddress.ip_address(value.get(field))
        except (TypeError, ValueError):
            return None
        if parsed.version != 4:
            return None
        value[field] = parsed.compressed
    return value


def _endpoint_compatible(value: Mapping[str, Any], options: Mapping[str, Any]) -> bool:
    return (value.get("protocol") == options.get("protocol")
            and value.get("dip") is False
            and (options.get("region") is None or value.get("regionId") == options.get("region")))


def _endpoint_failure_diagnostic(failure: rt.TransmissionError) -> dict[str, str]:
    call = failure.detail.get("call", "serverlist")
    if not isinstance(call, str):
        call = "serverlist"
    call = re.sub(r"[^A-Za-z0-9_.-]", "_", call)[:64] or "serverlist"
    detail = rt._safe_diagnostic(failure.detail.get("curlError"))
    return {"call": call, "curlError": (detail or failure.signal_name)[:160]}


def _prepare_endpoint_record(options: Mapping[str, Any],
                             dip_info: Mapping[str, Any] | None = None
                             ) -> tuple[dict[str, Any], str, dict[str, str] | None]:
    protocol = options.get("protocol")
    if not isinstance(protocol, str) or protocol not in _PROTOCOLS:
        raise rt.TransmissionError("transmission-vpn-protocol-unknown", "vpn-options", {"field": "protocol"})
    dip = options.get("dip") is True
    if dip and dip_info is None:
        with rt.exported_credentials("pia") as (username, password):
            token = _token(username, password)
        with rt.exported_pia_dip_credentials() as credentials:
            dip_info = _dedicated_ip(token, credentials[1])
    selected_region = options.get("region")
    actual_region = dip_info.get("regionId") if dip and isinstance(dip_info, Mapping) else None
    if (isinstance(selected_region, str) and isinstance(actual_region, str)
            and selected_region != actual_region):
        raise rt.TransmissionError("transmission-vpn-region-unknown", "region-selection",
                                   {"field": "region"})
    cache_region = actual_region if isinstance(actual_region, str) else selected_region
    try:
        regions = _regions_from_serverlist()
    except rt.TransmissionError as failure:
        cached = _read_endpoint()
        cache_options = {"protocol": protocol, "dip": False, "region": cache_region}
        if cached is None or not _endpoint_compatible(cached, cache_options):
            raise failure
        record = dict(cached)
        if dip and isinstance(dip_info, Mapping):
            record.update({"vpnHostname": dip_info["hostname"],
                           "vpnAddress": dip_info["address"],
                           "regionId": actual_region or record["regionId"], "dip": True})
        return record, "cache-fallback", _endpoint_failure_diagnostic(failure)
    else:
        selection = dict(options)
        if dip and isinstance(actual_region, str):
            selection["region"] = actual_region
        region, meta, server = _select_region(regions, selection)
        vpn_server = ({"hostname": dip_info["hostname"], "address": dip_info["address"]}
                      if dip and isinstance(dip_info, Mapping) else server)
        record = {
            "metaHostname": meta["hostname"], "metaAddress": meta["address"],
            "vpnHostname": vpn_server["hostname"], "vpnAddress": vpn_server["address"],
            "regionId": region["id"], "protocol": protocol, "dip": dip,
            "preparedAt": time.time(),
        }
        if protocol == "openvpn":
            record["vpnPort"] = server.get("vpnPort", 1198)
        return record, "serverlist", None


def _persist_endpoint(record: Mapping[str, Any]) -> None:
    stable_fields = ("metaHostname", "metaAddress", "vpnHostname", "vpnAddress",
                     "regionId", "protocol", "dip", "vpnPort")
    existing = _read_endpoint()
    if existing is not None and all(existing.get(key) == record.get(key) for key in stable_fields):
        return
    _private_directory()
    try:
        rt.write_atomic(_ENDPOINT_PATH,
                        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8"), 0o600)
        observed = _read_endpoint()
        if observed is None or any(observed.get(key) != record.get(key) for key in stable_fields):
            raise OSError("endpoint-readback-mismatch")
    except (OSError, rt.TransmissionError):
        raise rt.TransmissionError("transmission-provider-endpoint-write-failed", "provider-endpoint-write") from None


def prepare_endpoint(options: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(options, Mapping):
        raise rt.TransmissionError("transmission-vpn-options-invalid", "provider-endpoint")
    protocol = options.get("protocol")
    if not isinstance(protocol, str) or protocol not in _PROTOCOLS:
        raise rt.TransmissionError("transmission-vpn-protocol-unknown", "vpn-options", {"field": "protocol"})
    record, source, diagnostic = _prepare_endpoint_record(options)
    if options.get("dip") is not True and source == "serverlist":
        _persist_endpoint(record)
    backend = select_protocol(protocol)
    return {
        "address": record["vpnAddress"],
        "protocol": "udp",
        "port": record.get("vpnPort", 1198) if protocol == "openvpn" else None,
        "tunnelInterface": backend.interface_name(),
        "regionId": record["regionId"],
        "provider": "pia",
        "endpointSource": source,
        "endpointDiagnostic": diagnostic,
    }


def _decode_json(raw: bytes, step: str, signal: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise rt.TransmissionError(signal, step, {"call": step, "curlError": "invalid JSON response"}) from None


def _token(username: str, password: str) -> str:
    def request() -> str:
        status, _headers, raw = rt._curl_http(
            _AUTH_URL, form={"username": username, "password": password}, step="pia-auth")
        if status != 200:
            raise rt.TransmissionError("transmission-pia-auth-failed", "pia-auth",
                                       {"call": "token", "curlError": f"HTTP status {status}"})
        result = _decode_json(raw, "pia-auth", "transmission-pia-auth-response-invalid")
        value = result.get("token") if isinstance(result, Mapping) else None
        if not isinstance(value, str) or not value or any(ch in value for ch in "\r\n\x00"):
            raise rt.TransmissionError("transmission-pia-auth-response-invalid", "pia-auth",
                                       {"call": "token", "curlError": "token missing from response"})
        return value
    return _retry_pia_call("token", request)


def _dedicated_ip(token: str, dip_token: str) -> dict[str, Any]:
    def request() -> dict[str, Any]:
        body = json.dumps({"tokens": [dip_token]}, separators=(",", ":"))
        status, _headers, raw = rt._curl_http(
            _DEDICATED_IP_URL, body=body,
            headers={"Authorization": "Token " + token}, method="POST",
            ca_file=str(_API_CA_FILE), step="pia-dedicated-ip")
        if status != 200:
            raise rt.TransmissionError("transmission-pia-dedicated-ip-failed", "pia-dedicated-ip",
                                       {"call": "dedicated_ip", "curlError": f"HTTP status {status}"})
        result = _decode_json(raw, "pia-dedicated-ip", "transmission-pia-dedicated-ip-response-invalid")
        item = result[0] if isinstance(result, list) and result else None
        if not isinstance(item, Mapping) or item.get("status") != "active":
            raise rt.TransmissionError("transmission-pia-dedicated-ip-rejected", "pia-dedicated-ip",
                                       {"call": "dedicated_ip", "curlError": "no active dedicated IP"})
        address, hostname, region_id = item.get("ip"), item.get("cn"), item.get("id")
        try:
            parsed = ipaddress.ip_address(address)
        except (TypeError, ValueError):
            raise rt.TransmissionError("transmission-pia-dedicated-ip-response-invalid", "pia-dedicated-ip",
                                       {"call": "dedicated_ip", "curlError": "invalid endpoint address"}) from None
        if (parsed.version != 4 or not _valid_host(hostname)
                or not isinstance(region_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", region_id)):
            raise rt.TransmissionError("transmission-pia-dedicated-ip-response-invalid", "pia-dedicated-ip",
                                       {"call": "dedicated_ip", "curlError": "invalid endpoint or region fields"})
        return {"address": parsed.compressed, "hostname": hostname, "regionId": region_id}
    return _retry_pia_call("dedicated_ip", request)


def connect(namespace: str, options: Mapping[str, Any]):
    backend = select_protocol(options.get("protocol"))
    with rt.exported_credentials("pia") as (username, password):
        token = _token(username, password)
    if options.get("dip") is True:
        with rt.exported_pia_dip_credentials() as dip_credentials:
            dip_info = _dedicated_ip(token, dip_credentials[1])
            active_endpoint, _source, _diagnostic = _prepare_endpoint_record(options, dip_info)
            tunnel = backend.connect(namespace, active_endpoint, token, options,
                                     dip_credentials=dip_credentials, dip_info=dip_info,
                                     retry_call=_retry_pia_call)
    else:
        active_endpoint = _read_endpoint()
        if active_endpoint is None or not _endpoint_compatible(active_endpoint, options):
            active_endpoint, source, _diagnostic = _prepare_endpoint_record(options)
            if source == "serverlist":
                _persist_endpoint(active_endpoint)
        tunnel = backend.connect(namespace, active_endpoint, token, options,
                                 dip_credentials=None, dip_info=None,
                                 retry_call=_retry_pia_call)
    _state.endpoint = active_endpoint
    _state.options = dict(options)
    _state.token = token
    _state.signed = None
    _state.tunnel = tunnel
    _state.tunnel_face = backend
    return tunnel


def _tunnel_gateway(namespace: str) -> str | None:
    result = rt.run([rt.IP, "-j", "-n", namespace, "-4", "route", "show"],
                    step="pia-gateway-readback")
    if result.returncode != 0:
        return None
    try:
        routes = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        return None
    interface = _state.tunnel_face.interface_name() if _state.tunnel_face else None
    if isinstance(routes, list):
        for row in routes:
            if not isinstance(row, dict) or row.get("dev") != interface:
                continue
            gateway = row.get("gateway")
            try:
                parsed = ipaddress.ip_address(gateway)
            except (TypeError, ValueError):
                continue
            if parsed.version == 4:
                return parsed.compressed
    if (_state.options is not None and _state.options.get("protocol") == "wireguard"
            and _state.tunnel is not None):
        for candidate in (getattr(_state.tunnel, "server_vip", None),
                          getattr(_state.tunnel, "peer_address", None)):
            if not isinstance(candidate, str):
                continue
            try:
                parsed = (ipaddress.ip_interface(candidate).ip if "/" in candidate
                          else ipaddress.ip_address(candidate))
            except (TypeError, ValueError):
                continue
            if parsed.version == 4:
                return parsed.compressed
    return None


def _api_json(path: str, query: Mapping[str, str], call: str, step: str) -> dict[str, Any]:
    endpoint = _state.endpoint
    token = _state.token
    if endpoint is None or token is None:
        raise rt.TransmissionError("transmission-pia-forward-state-missing", step)
    gateway = _tunnel_gateway(rt.VPN_NAMESPACE)
    host = endpoint["vpnHostname"] if gateway is not None else endpoint["metaHostname"]
    url = f"https://{host}:19999/{path}?{urlencode(query)}"
    if gateway is None and _state.options is not None \
            and _state.options.get("protocol") == "wireguard":
        raise rt.TransmissionError("transmission-pia-tunnel-gateway-unavailable", "pia-gateway",
                                   {"call": call, "curlError": "WireGuard server VIP and peer unavailable"})
    connect_target = gateway or endpoint["metaAddress"]

    def request(deadline: float | None = None) -> dict[str, Any]:
        curl_options = ({"deadline": deadline, "structured_transport_errors": True}
                        if deadline is not None else {})
        status, _headers, raw = rt._curl_http(
            url, namespace=rt.VPN_NAMESPACE, ca_file=str(_API_CA_FILE),
            connect_to=f"{host}:19999:{connect_target}:19999", step=step,
            **curl_options)
        if status != 200:
            raise rt.TransmissionError("transmission-pia-api-failed", step,
                                       {"call": call, "curlError": f"HTTP status {status}"})
        value = _decode_json(raw, call, "transmission-pia-api-response-invalid")
        if not isinstance(value, Mapping) or value.get("status") != "OK":
            raise rt.TransmissionError("transmission-pia-api-rejected", step,
                                       {"call": call, "curlError": "PIA rejected request"})
        return dict(value)
    if call in {"getSignature", "bindPort"}:
        return _retry_forward_api(call, request)
    return _retry_pia_call(call, request)


def _expiry(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError
    try:
        result = float(value)
    except (TypeError, ValueError):
        if not isinstance(value, str):
            raise ValueError from None
        result = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    if not math.isfinite(result) or result <= time.time():
        raise ValueError
    return result


def _get_signature() -> _Signature:
    result = _api_json("getSignature", {"token": _state.token or ""},
                       "getSignature", "pia-signature")
    payload, signature = result.get("payload"), result.get("signature")
    if not isinstance(payload, str) or not isinstance(signature, str) or not signature:
        raise rt.TransmissionError("transmission-pia-signature-invalid", "pia-signature",
                                   {"call": "getSignature", "curlError": "signature fields missing"})
    try:
        decoded = __import__("base64").b64decode(payload, validate=True).decode("utf-8")
        payload_data = json.loads(decoded)
        port = payload_data.get("port")
        expires_at = _expiry(payload_data.get("expires_at"))
    except (ValueError, UnicodeError, json.JSONDecodeError, AttributeError):
        raise rt.TransmissionError("transmission-pia-signature-invalid", "pia-signature",
                                   {"call": "getSignature", "curlError": "signature payload invalid"}) from None
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise rt.TransmissionError("transmission-pia-signature-invalid", "pia-signature",
                                   {"call": "getSignature", "curlError": "forward port invalid"})
    return _Signature(payload, signature, port, expires_at)


def _bind(signed: _Signature) -> None:
    _api_json("bindPort", {"payload": signed.payload, "signature": signed.signature},
              "bindPort", "pia-bind-port")


def _tunnel_diagnostic() -> dict[str, str]:
    diagnostic = getattr(_state.tunnel, "last_diagnostic", None)
    if isinstance(diagnostic, str) and diagnostic:
        return {"tunnelDiagnostic": rt._safe_diagnostic(diagnostic)[:160]}
    return {}


def forward() -> dict[str, int]:
    if _state.tunnel is None or _state.tunnel_face is None:
        raise rt.TransmissionError("transmission-pia-tunnel-unavailable", "pia-forward")
    try:
        alive = _state.tunnel_face.is_alive(_state.tunnel)
    except Exception:
        alive = False
    if not alive:
        raise rt.TransmissionError("transmission-vpn-tunnel-exited", "vpn-tunnel",
                                   _tunnel_diagnostic())
    signed = _get_signature()
    _bind(signed)
    _state.signed = signed
    return {"port": signed.port, "keepaliveInterval": 900}


def keepalive(current: dict[str, Any]) -> dict[str, int]:
    if _state.tunnel is None or _state.tunnel_face is None:
        raise rt.TransmissionError("transmission-pia-tunnel-unavailable", "pia-keepalive")
    try:
        alive = _state.tunnel_face.is_alive(_state.tunnel)
    except Exception:
        alive = False
    if not alive:
        raise rt.TransmissionError("transmission-vpn-tunnel-exited", "vpn-tunnel",
                                   _tunnel_diagnostic())
    signed = _state.signed
    endpoint = _state.endpoint
    if (not isinstance(current, dict) or endpoint is None or signed is None
            or current.get("port") != signed.port or current.get("keepaliveInterval") != 900):
        raise rt.TransmissionError("transmission-pia-forward-state-invalid", "pia-keepalive")
    if signed.expires_at <= time.time() + 960:
        with rt.exported_credentials("pia") as (username, password):
            _state.token = _token(username, password)
        signed = _get_signature()
    _bind(signed)
    _state.signed = signed
    return {"port": signed.port, "keepaliveInterval": 900}


def teardown() -> None:
    tunnel, backend = _state.tunnel, _state.tunnel_face
    try:
        if tunnel is not None and backend is not None:
            backend.teardown(tunnel)
    finally:
        _state.endpoint = None
        _state.options = None
        _state.token = None
        _state.signed = None
        _state.tunnel = None
        _state.tunnel_face = None

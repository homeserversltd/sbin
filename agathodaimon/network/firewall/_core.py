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

from agathodaimon._envelope import EnvelopeError
from agathodaimon.network.dhcp._manager import DhcpError, DhcpManager

DEFAULT_POLICY = Path("/etc/unbound/unbound.conf.d/agathodaimon-child-policy.conf")
DEFAULT_UNBOUND_CONFIG = Path("/etc/unbound/unbound.conf")
DEFAULT_NFT = Path("/etc/nftables.d/caduceus-child-filter.nft")
DEFAULT_NFTABLES_CONFIG = Path("/etc/nftables.conf")
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
WAN_DEFINE = re.compile(r'^\s*define\s+wan_if\s*=\s*(?:"([A-Za-z0-9_.-]{1,15})"|([A-Za-z0-9_.-]{1,15}))\s*(?:#.*)?$')


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


@dataclass(frozen=True)
class NftState:
    policies: dict[str, dict[str, Any]]
    doh_resolvers: tuple[str, ...]


def _receipt(action: str, ok: bool, changed: bool, message: str,
             revision: str | None, first_missing_signal: str = "none", **extra: Any) -> dict[str, Any]:
    return {
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


def _global_local_zones(path: Path, runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[str, ...]:
    ok, output, _error = runner([str(CHECKCONF), "-o", "local-zone", str(path)])
    if not ok or not isinstance(output, str) or len(output.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise FirewallRefused("firewall-operation-unavailable")
    zones: set[str] = set()
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("local-zone:"):
            line = line[len("local-zone:"):].strip()
        match = re.fullmatch(r'(?:"([^"\s]+)"|(\S+))\s+([A-Za-z][A-Za-z0-9_-]*)', line)
        if match is None:
            raise FirewallRefused("firewall-operation-unavailable")
        name = (match.group(1) or match.group(2)).lower()
        if name != "." and not name.endswith("."):
            name += "."
        if name == "." or not _valid_unbound_zone_name(name):
            raise FirewallRefused("firewall-operation-unavailable")
        zones.add(name)
    return tuple(sorted(zones))


def _wan_interface(path: Path) -> str:
    try:
        data = path.read_bytes()
        if len(data) > MAX_FILE_BYTES or b"\x00" in data:
            raise ValueError("unusable nftables config")
        text = data.decode("ascii")
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise FirewallRefused("firewall-operation-unavailable") from exc
    values: list[str] = []
    for line in text.splitlines():
        if not re.match(r"^\s*define\s+wan_if\b", line):
            continue
        match = WAN_DEFINE.fullmatch(line)
        if match is None:
            raise FirewallRefused("firewall-operation-unavailable")
        values.append(match.group(1) or match.group(2))
    if len(values) != 1:
        raise FirewallRefused("firewall-operation-unavailable")
    return values[0]


def _render_unbound(policies: dict[str, dict[str, Any]], global_zones: Sequence[str]) -> bytes | None:
    allowlisted = {mac: policy for mac, policy in policies.items()
                   if policy.get("way", "allowlist") == "allowlist"}
    if not allowlisted:
        return None
    normalized_global: set[str] = set()
    for raw in global_zones:
        if not isinstance(raw, str):
            raise FirewallRefused("firewall-operation-unavailable")
        name = raw.lower()
        if name != "." and not name.endswith("."):
            name += "."
        if name == "." or not _valid_unbound_zone_name(name):
            raise FirewallRefused("firewall-operation-unavailable")
        normalized_global.add(name)
    lines = ["server:"]
    for mac, policy in sorted(allowlisted.items()):
        lines.append(f'    access-control-view: {policy["ip"]}/32 "{view_name(mac)}"')
    for mac, policy in sorted(allowlisted.items()):
        lines.extend(("view:", f'    name: "{view_name(mac)}"', "    view-first: yes",
                      '    local-zone: "." refuse'))
        hostnames = canonical_fqdns(policy.get("hostnames", []))
        if set(hostnames) & normalized_global:
            raise FirewallRefused("firewall-hostname-global-zone-conflict")
        zones = normalized_global | set(hostnames)
        lines.extend(f'    local-zone: "{name}" transparent' for name in sorted(zones))
    return ("\n".join(lines) + "\n").encode("ascii")


def _parse_unbound(data: bytes, global_zones: Sequence[str]) -> dict[str, dict[str, Any]]:
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
    expected_global = set(global_zones)
    while cursor < len(lines):
        if lines[cursor] != "view:" or cursor + 3 >= len(lines):
            raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
        name_match = VIEW_NAME.fullmatch(lines[cursor + 1])
        root_match = ZONE.fullmatch(lines[cursor + 3])
        if (name_match is None or lines[cursor + 2] != "    view-first: yes"
                or root_match is None or root_match.groups() != (".", "refuse")):
            raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
        name = name_match.group(1)
        prefix = "agathodaimon-child-"
        if not name.startswith(prefix) or len(name) != len(prefix) + 12:
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        mac = canonical_mac(name[len(prefix):])
        if mac in parsed or access.get(mac) is None or name != view_name(mac):
            raise FirewallRefused("firewall-unbound-policy-mismatch")
        cursor += 4
        transparent: list[str] = []
        while cursor < len(lines) and lines[cursor] != "view:":
            zone = ZONE.fullmatch(lines[cursor])
            if zone is None or zone.group(2) != "transparent":
                raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
            zone_name = zone.group(1).lower()
            if not _valid_unbound_zone_name(zone_name) or zone_name in transparent:
                raise FirewallRefused("firewall-unbound-owned-file-invalid")
            transparent.append(zone_name)
            cursor += 1
        if not expected_global.issubset(set(transparent)):
            raise FirewallRefused("firewall-unbound-policy-mismatch")
        names = [zone for zone in transparent if zone not in expected_global]
        if len(names) > MAX_FQDNS:
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        canonical = canonical_fqdns(names)
        if canonical != sorted(names):
            raise FirewallRefused("firewall-unbound-owned-file-invalid")
        parsed[mac] = {"mac": mac, "ip": access[mac], "way": "allowlist", "hostnames": canonical}
    if set(parsed) != set(access):
        raise FirewallRefused("firewall-unbound-policy-mismatch")
    if _render_unbound(parsed, global_zones) != data:
        raise FirewallRefused("firewall-unbound-owned-file-foreign-content")
    return parsed


def _resolver_addresses() -> tuple[str, ...]:
    try:
        from agathodaimon.network.dns._resolver import ResolverControl
        presets = ResolverControl.PRESETS
        if not isinstance(presets, dict) or not presets:
            raise ValueError("resolver presets are unavailable")
        addresses: set[str] = set()
        for preset in presets.values():
            values = preset[0]
            if not isinstance(values, list) or not values:
                raise ValueError("resolver preset has no IPv4 addresses")
            for value in values:
                if not isinstance(value, str):
                    raise ValueError("resolver address is not text")
                address = ipaddress.ip_address(value)
                if not isinstance(address, ipaddress.IPv4Address):
                    raise ValueError("resolver address is not IPv4")
                addresses.add(str(address))
        return tuple(sorted(addresses))
    except Exception as exc:
        raise FirewallRefused("firewall-nft-resolver-presets-invalid") from exc


def _canonical_resolvers(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise FirewallRefused("firewall-nft-owned-file-invalid")
    addresses: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise FirewallRefused("firewall-nft-owned-file-invalid")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise FirewallRefused("firewall-nft-owned-file-invalid") from exc
        if not isinstance(address, ipaddress.IPv4Address):
            raise FirewallRefused("firewall-nft-owned-file-invalid")
        addresses.append(str(address))
    if len(addresses) != len(set(addresses)):
        raise FirewallRefused("firewall-nft-owned-file-invalid")
    return tuple(sorted(addresses))


def _nft_bytes(policies: dict[str, dict[str, Any]], wan_if: str,
               doh_resolvers: Sequence[str] | None = None) -> bytes:
    allowlisted = {mac: policy for mac, policy in policies.items()
                   if policy.get("way", "allowlist") == "allowlist"}
    if allowlisted:
        resolvers = _canonical_resolvers(doh_resolvers) if doh_resolvers is not None else _resolver_addresses()
        if not resolvers:
            raise FirewallRefused("firewall-nft-resolver-presets-invalid")
    else:
        resolvers = ()
    lines = ["table inet caduceus_child_filter {"]
    if allowlisted:
        lines.extend(("    set doh_resolvers {", "        type ipv4_addr",
                      "        elements = { " + ", ".join(resolvers) + " }", "    }"))
    lines.extend(("    chain forward {", "        type filter hook forward priority -5; policy accept;"))
    for mac, policy in sorted(policies.items()):
        way = policy.get("way", "allowlist")
        if way == "blocked":
            lines.append(f'        ether saddr {mac} oifname "{wan_if}" drop')
            continue
        if way != "allowlist":
            raise FirewallRefused("firewall-way-invalid")
        ip, router = policy["ip"], policy["router"]
        lines.append(f"        ether saddr {mac} ip saddr {ip} udp dport 53 ip daddr != {router} drop")
        lines.append(f"        ether saddr {mac} ip saddr {ip} tcp dport 53 ip daddr != {router} drop")
        lines.append(f'        ether saddr {mac} oifname "{wan_if}" udp dport 853 drop')
        lines.append(f'        ether saddr {mac} oifname "{wan_if}" tcp dport 853 drop')
        lines.append(f'        ether saddr {mac} oifname "{wan_if}" ip daddr @doh_resolvers tcp dport 443 drop')
        lines.append(f'        ether saddr {mac} oifname "{wan_if}" ip daddr @doh_resolvers udp dport 443 drop')
    lines.extend(("    }", "}"))
    return ("\n".join(lines) + "\n").encode("ascii")


def _nft_inert_bytes(data: bytes) -> bool:
    return all(not line.strip() or line.lstrip().startswith(b"#") for line in data.splitlines())


def _policy_state(rules: list[dict[str, Any]], doh_resolvers: tuple[str, ...],
                  *, signal: str) -> NftState:
    seen: set[tuple[tuple[str, Any], ...]] = set()
    grouped: dict[str, dict[str, Any]] = {}
    counts: dict[str, dict[str, set[str]]] = {}
    for rule in rules:
        key = tuple(sorted(rule.items()))
        if key in seen:
            raise FirewallRefused(signal)
        seen.add(key)
        mac = rule.get("mac")
        if not isinstance(mac, str):
            raise FirewallRefused(signal)
        prior = grouped.get(mac)
        keys = set(rule)
        if keys == {"mac", "oifname"} and rule.get("oifname") is not None:
            if prior is not None:
                raise FirewallRefused(signal)
            grouped[mac] = {"mac": mac, "way": "blocked", "ip": None,
                            "router": None, "hostnames": []}
            counts[mac] = {"blocked": {"one"}}
            continue
        if keys == {"mac", "ip", "protocol", "dport", "router"} and rule.get("dport") == 53:
            category = "dns"
        elif keys == {"mac", "oifname", "protocol", "dport"} and rule.get("dport") == 853:
            category = "dot"
        elif (keys == {"mac", "oifname", "protocol", "dport", "doh"}
              and rule.get("dport") == 443 and rule.get("doh") == "doh_resolvers"):
            category = "doh"
        else:
            raise FirewallRefused(signal)
        if prior is not None and prior.get("way") != "allowlist":
            raise FirewallRefused(signal)
        protocol = rule.get("protocol")
        if protocol not in {"tcp", "udp"}:
            raise FirewallRefused(signal)
        if category == "dns":
            ip = _admit_private(rule.get("ip"), signal)
            router = _admit_private(rule.get("router"), signal)
            if prior is None:
                grouped[mac] = {"mac": mac, "way": "allowlist", "ip": ip,
                                "router": router, "hostnames": []}
            elif prior["ip"] is None and prior["router"] is None:
                prior["ip"], prior["router"] = ip, router
            elif prior["ip"] != ip or prior["router"] != router:
                raise FirewallRefused(signal)
        else:
            if rule.get("oifname") is None:
                raise FirewallRefused(signal)
            if prior is None:
                grouped[mac] = {"mac": mac, "way": "allowlist", "ip": None,
                                "router": None, "hostnames": []}
        protocols = counts.setdefault(mac, {}).setdefault(category, set())
        if protocol in protocols:
            raise FirewallRefused(signal)
        protocols.add(protocol)
    for mac, policy in grouped.items():
        if policy["way"] == "blocked":
            if counts[mac] != {"blocked": {"one"}}:
                raise FirewallRefused(signal)
            continue
        expected = {"dns": {"tcp", "udp"}, "dot": {"tcp", "udp"}, "doh": {"tcp", "udp"}}
        if counts.get(mac) != expected or policy["ip"] is None or policy["router"] is None:
            raise FirewallRefused(signal)
    allowlisted = any(policy["way"] == "allowlist" for policy in grouped.values())
    if allowlisted != bool(doh_resolvers):
        raise FirewallRefused(signal)
    return NftState(grouped, doh_resolvers)


def _parse_nft(data: bytes, wan_if: str) -> NftState:
    if _nft_inert_bytes(data):
        return NftState({}, ())
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise FirewallRefused("firewall-nft-owned-file-invalid") from exc
    if not text.endswith("\n"):
        raise FirewallRefused("firewall-nft-owned-file-invalid")
    lines = text.splitlines()
    if len(lines) < 5 or lines[0] != "table inet caduceus_child_filter {" or lines[-1] != "}":
        raise FirewallRefused("firewall-nft-owned-file-foreign-content")
    cursor = 1
    resolvers: tuple[str, ...] = ()
    if cursor < len(lines) and lines[cursor] == "    set doh_resolvers {":
        if cursor + 3 >= len(lines) or lines[cursor + 1] != "        type ipv4_addr" or lines[cursor + 3] != "    }":
            raise FirewallRefused("firewall-nft-owned-file-foreign-content")
        element_match = re.fullmatch(r"        elements = \{ (.+) \}", lines[cursor + 2])
        if element_match is None:
            raise FirewallRefused("firewall-nft-owned-file-foreign-content")
        resolvers = _canonical_resolvers([part.strip() for part in element_match.group(1).split(",")])
        cursor += 4
    if (cursor + 3 > len(lines) or lines[cursor] != "    chain forward {"
            or lines[cursor + 1] != "        type filter hook forward priority -5; policy accept;"
            or lines[-2] != "    }"):
        raise FirewallRefused("firewall-nft-owned-file-foreign-content")
    rule_lines = lines[cursor + 2:-2]
    rules: list[dict[str, Any]] = []
    mac_pattern = r"([0-9a-f:]{17})"
    ip_pattern = r"([0-9.]+)"
    for line in rule_lines:
        match = re.fullmatch(rf'        ether saddr {mac_pattern} oifname "([A-Za-z0-9_.-]{{1,15}})" drop', line)
        if match:
            mac = canonical_mac(match.group(1))
            if match.group(2) != wan_if:
                raise FirewallRefused("firewall-nft-owned-file-foreign-content")
            rules.append({"mac": mac, "oifname": wan_if})
            continue
        match = re.fullmatch(rf"        ether saddr {mac_pattern} ip saddr {ip_pattern} (udp|tcp) dport 53 ip daddr != {ip_pattern} drop", line)
        if match:
            rules.append({"mac": canonical_mac(match.group(1)), "ip": _admit_private(match.group(2), "firewall-nft-owned-file-invalid"),
                          "protocol": match.group(3), "dport": 53,
                          "router": _admit_private(match.group(4), "firewall-nft-owned-file-invalid")})
            continue
        match = re.fullmatch(rf'        ether saddr {mac_pattern} oifname "([A-Za-z0-9_.-]{{1,15}})" (udp|tcp) dport 853 drop', line)
        if match:
            if match.group(2) != wan_if:
                raise FirewallRefused("firewall-nft-owned-file-foreign-content")
            rules.append({"mac": canonical_mac(match.group(1)), "oifname": wan_if,
                          "protocol": match.group(3), "dport": 853})
            continue
        match = re.fullmatch(rf'        ether saddr {mac_pattern} oifname "([A-Za-z0-9_.-]{{1,15}})" ip daddr @doh_resolvers (tcp|udp) dport 443 drop', line)
        if match:
            if match.group(2) != wan_if:
                raise FirewallRefused("firewall-nft-owned-file-foreign-content")
            rules.append({"mac": canonical_mac(match.group(1)), "oifname": wan_if,
                          "protocol": match.group(3), "dport": 443, "doh": "doh_resolvers"})
            continue
        raise FirewallRefused("firewall-nft-owned-file-foreign-content")
    state = _policy_state(rules, resolvers, signal="firewall-nft-owned-file-invalid")
    if _nft_bytes(state.policies, wan_if, state.doh_resolvers) != data:
        raise FirewallRefused("firewall-nft-owned-file-foreign-content")
    return state


def _parse_json_match(match: Any) -> tuple[str, Any]:
    if not isinstance(match, dict) or set(match) != {"left", "right", "op"}:
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    left, right, op = match["left"], match["right"], match["op"]
    if not isinstance(left, dict) or len(left) != 1:
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    if "payload" in left:
        payload = left["payload"]
        if not isinstance(payload, dict) or set(payload) != {"protocol", "field"}:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        protocol, field = payload["protocol"], payload["field"]
        if protocol == "ether" and field == "saddr" and op == "==" and isinstance(right, str):
            try:
                return "mac", canonical_mac(right)
            except FirewallRefused as exc:
                raise FirewallRefused("firewall-nft-live-rule-mismatch") from exc
        if protocol == "ip" and field == "saddr" and op == "==" and isinstance(right, str):
            return "ip", _admit_private(right, "firewall-nft-live-rule-mismatch")
        if protocol == "ip" and field == "daddr" and op == "!=" and isinstance(right, str):
            return "not-router", _admit_private(right, "firewall-nft-live-rule-mismatch")
        if (protocol == "ip" and field == "daddr" and op in {"in", "=="}
                and (right == "@doh_resolvers" or right == {"set": "doh_resolvers"})):
            return "doh", "doh_resolvers"
        if protocol in {"tcp", "udp"} and field == "dport" and op == "==" and type(right) is int:
            return "transport", (protocol, right)
    if "meta" in left:
        meta = left["meta"]
        if (isinstance(meta, dict) and set(meta) == {"key"} and meta["key"] == "oifname"
                and op == "==" and isinstance(right, str)):
            return "oifname", right
    raise FirewallRefused("firewall-nft-live-rule-mismatch")


def _parse_live_rule(rule: Any, wan_if: str) -> dict[str, Any]:
    if not isinstance(rule, dict) or set(rule) - {"family", "table", "chain", "handle", "expr"}:
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    if (rule.get("family") != "inet" or rule.get("table") != "caduceus_child_filter"
            or rule.get("chain") != "forward" or not isinstance(rule.get("expr"), list)):
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    expressions = rule["expr"]
    if not expressions or expressions[-1] != {"drop": None}:
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    fields: dict[str, Any] = {}
    for statement in expressions[:-1]:
        if not isinstance(statement, dict) or set(statement) != {"match"}:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        key, value = _parse_json_match(statement["match"])
        if key == "transport":
            protocol, port = value
            if "protocol" in fields or "dport" in fields:
                raise FirewallRefused("firewall-nft-live-rule-mismatch")
            fields["protocol"], fields["dport"] = protocol, port
        else:
            if key in fields:
                raise FirewallRefused("firewall-nft-live-rule-mismatch")
            fields[key] = value
    if "mac" not in fields:
        raise FirewallRefused("firewall-nft-live-rule-mismatch")
    if set(fields) == {"mac", "oifname"}:
        if fields["oifname"] != wan_if:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        return {"mac": fields["mac"], "oifname": wan_if}
    if set(fields) == {"mac", "ip", "protocol", "dport", "not-router"}:
        if fields["dport"] != 53:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        return {"mac": fields["mac"], "ip": fields["ip"], "protocol": fields["protocol"],
                "dport": 53, "router": fields["not-router"]}
    if set(fields) == {"mac", "oifname", "protocol", "dport"} and fields["dport"] == 853:
        if fields["oifname"] != wan_if:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        return {**fields, "dport": 853}
    if set(fields) == {"mac", "oifname", "protocol", "dport", "doh"} and fields["dport"] == 443:
        if fields["oifname"] != wan_if:
            raise FirewallRefused("firewall-nft-live-rule-mismatch")
        return fields
    raise FirewallRefused("firewall-nft-live-rule-mismatch")


def _json_resolver_elements(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    elements = value if isinstance(value, list) else [value]
    addresses: list[str] = []
    for item in elements:
        if isinstance(item, dict):
            if set(item) == {"elem"} and isinstance(item["elem"], dict) and set(item["elem"]) == {"val"}:
                item = item["elem"]["val"]
            elif set(item) == {"val"}:
                item = item["val"]
            else:
                raise FirewallRefused("firewall-nft-live-readback-invalid")
        if not isinstance(item, str):
            raise FirewallRefused("firewall-nft-live-readback-invalid")
        addresses.append(item)
    try:
        return _canonical_resolvers(addresses)
    except FirewallRefused as exc:
        raise FirewallRefused("firewall-nft-live-readback-invalid") from exc


def _parse_live_nft(text: str, wan_if: str) -> NftState:
    if len(text.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise FirewallRefused("firewall-nft-live-readback-invalid")
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise FirewallRefused("firewall-nft-live-readback-invalid") from exc
    if not isinstance(document, dict) or set(document) != {"nftables"} or not isinstance(document["nftables"], list):
        raise FirewallRefused("firewall-nft-live-readback-invalid")
    table_count = chain_count = set_count = metainfo_count = 0
    rules: list[dict[str, Any]] = []
    resolvers: tuple[str, ...] = ()
    for item in document["nftables"]:
        if not isinstance(item, dict) or len(item) != 1:
            raise FirewallRefused("firewall-nft-live-readback-invalid")
        kind, value = next(iter(item.items()))
        if kind == "metainfo":
            metainfo_count += 1
            if (not isinstance(value, dict) or set(value) != {"version", "release_name", "json_schema_version"}
                    or not isinstance(value["version"], str) or not isinstance(value["release_name"], str)
                    or type(value["json_schema_version"]) is not int or value["json_schema_version"] < 1):
                raise FirewallRefused("firewall-nft-live-readback-invalid")
            continue
        if not isinstance(value, dict):
            raise FirewallRefused("firewall-nft-live-readback-invalid")
        if kind == "table":
            table_count += 1
            if (value.get("family") != "inet" or value.get("name") != "caduceus_child_filter"
                    or set(value) - {"family", "name", "handle", "flags"}
                    or ("flags" in value and value["flags"] not in ([], None))):
                raise FirewallRefused("firewall-nft-live-table-mismatch")
        elif kind == "chain":
            chain_count += 1
            if (value.get("family") != "inet" or value.get("table") != "caduceus_child_filter"
                    or value.get("name") != "forward" or value.get("type") != "filter"
                    or value.get("hook") != "forward" or value.get("prio") != -5
                    or value.get("policy") != "accept"
                    or set(value) - {"family", "table", "name", "handle", "type", "hook", "prio", "policy"}):
                raise FirewallRefused("firewall-nft-live-hook-mismatch")
        elif kind == "set":
            set_count += 1
            if (value.get("family") != "inet" or value.get("table") != "caduceus_child_filter"
                    or value.get("name") != "doh_resolvers" or value.get("type") != "ipv4_addr"
                    or set(value) - {"family", "table", "name", "handle", "type", "elem", "flags"}
                    or ("flags" in value and value["flags"] not in ([], None))):
                raise FirewallRefused("firewall-nft-live-set-mismatch")
            resolvers = _json_resolver_elements(value.get("elem"))
        elif kind == "rule":
            rules.append(_parse_live_rule(value, wan_if))
        else:
            raise FirewallRefused("firewall-nft-live-table-mismatch")
    if table_count != 1 or chain_count != 1 or set_count > 1 or metainfo_count > 1:
        raise FirewallRefused("firewall-nft-live-table-mismatch")
    state = _policy_state(rules, resolvers, signal="firewall-nft-live-rule-mismatch")
    has_allowlist = any(policy["way"] == "allowlist" for policy in state.policies.values())
    if set_count != (1 if has_allowlist else 0):
        raise FirewallRefused("firewall-nft-live-set-mismatch")
    return state


def _nft_policy_key(policies: dict[str, dict[str, Any]]) -> tuple[tuple[Any, ...], ...]:
    values = []
    for mac, policy in policies.items():
        way = policy.get("way", "allowlist")
        if way == "blocked":
            values.append((mac, way, None, None))
        else:
            values.append((mac, way, policy.get("ip"), policy.get("router")))
    return tuple(sorted(values))


def _nft_state_key(state: NftState) -> tuple[tuple[tuple[Any, ...], ...], tuple[str, ...]]:
    return _nft_policy_key(state.policies), tuple(sorted(state.doh_resolvers))


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
    is_nft_table_query = argv[:5] == [str(NFT), "-j", "list", "table", "inet"]
    if is_nft_table_query and "no such file or directory" in detail:
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
    ok, output, error = runner([str(NFT), "-j", "list", "table", "inet", "caduceus_child_filter"])
    if ok:
        if not isinstance(output, str):
            raise FirewallRefused("firewall-nft-live-readback-invalid")
        return True, output
    if error == "not-found":
        return False, ""
    raise FirewallRefused(error if error != "none" else "firewall-nft-live-readback-unavailable")


def _prove_live_nft(expected: NftState, expected_exists: bool,
                    runner: Callable[[list[str]], tuple[bool, str, str]], wan_if: str) -> None:
    exists, output = _live_table(runner)
    if exists != expected_exists:
        raise FirewallRefused("firewall-nft-live-table-presence-mismatch")
    if not exists:
        if expected.policies or expected.doh_resolvers:
            raise FirewallRefused("firewall-nft-live-table-presence-mismatch")
        return
    actual = _parse_live_nft(output, wan_if)
    if _nft_state_key(actual) != _nft_state_key(expected):
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


def _prove_live_dns(mac: str, hostnames: list[str], global_zones: Sequence[str],
                    runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
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
        name = (match.group(1) or match.group(2)).lower()
        kind = match.group(3)
        if not _valid_unbound_zone_name(name) or kind not in {"refuse", "transparent"}:
            raise FirewallRefused("firewall-unbound-live-readback-invalid")
        if name != "." and not name.endswith("."):
            name += "."
        pair = (name, kind)
        if pair in zones:
            raise FirewallRefused("firewall-unbound-live-readback-invalid")
        zones.add(pair)
    expected = {(".", "refuse")}
    expected.update((name, "transparent") for name in global_zones)
    expected.update((name, "transparent") for name in hostnames)
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
        if len(rows) != 1:
            raise FirewallRefused("firewall-dhcp-binding-mismatch")
        way = policy.get("way", "allowlist")
        if way == "blocked":
            bound[mac] = {**policy, "ip": rows[0]["ip"], "router": None, "way": "blocked"}
            continue
        if way != "allowlist" or rows[0]["ip"] != policy["ip"]:
            raise FirewallRefused("firewall-dhcp-binding-mismatch")
        bound[mac] = {**policy, "router": _router_for_ip(manager, policy["ip"]), "way": "allowlist"}
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
    rows = []
    for mac, value in sorted(merged.items()):
        registered = mac in policies
        rows.append({**value, "registered": registered,
                     "way": policies[mac].get("way", "allowlist") if registered else None})
    return rows, leases


def _enforcement(mac: str, policy: dict[str, Any], leases: dict[str, dict[str, str]],
                 *, nft_proven: bool = True) -> str:
    if policy.get("way", "allowlist") == "blocked":
        return "applied" if nft_proven else "pending-renewal"
    lease = leases.get(mac)
    return "pending-renewal" if lease is None or lease["ip"] != policy["ip"] else "applied"


def _validate_intent(intent: Any) -> tuple[str, str | None, list[str] | None, str | None, str | None]:
    if not isinstance(intent, dict):
        raise FirewallRefused("firewall-intent-invalid")
    action = intent.get("action")
    if not isinstance(action, str) or action not in {
            "observed", "list", "register", "unregister", "whitelist-get", "whitelist-set", "way-set"}:
        raise FirewallRefused("firewall-action-invalid")
    keys = set(intent)
    if action in {"observed", "list"}:
        if keys & {"mac", "hostnames", "revision", "way"}:
            raise FirewallRefused("firewall-intent-shape-invalid")
        return action, None, None, None, None
    if action == "whitelist-get":
        if keys & {"hostnames", "revision", "way"}:
            raise FirewallRefused("firewall-intent-shape-invalid")
    elif action == "register":
        if "revision" in keys:
            raise FirewallRefused("firewall-intent-shape-invalid")
    elif action == "unregister":
        if keys & {"hostnames", "revision", "way"}:
            raise FirewallRefused("firewall-intent-shape-invalid")
    elif action == "whitelist-set":
        if "revision" not in keys or "hostnames" not in keys or "way" in keys:
            raise FirewallRefused("firewall-intent-shape-invalid")
    elif action == "way-set":
        if "revision" not in keys or "way" not in keys:
            raise FirewallRefused("firewall-intent-shape-invalid")
    way: str | None = None
    names: list[str] | None = None
    if action == "register":
        supplied_way = intent.get("way")
        has_names = "hostnames" in keys
        if supplied_way is None:
            if has_names:
                raise FirewallRefused("firewall-intent-shape-invalid")
            way, names = "allowlist", []
        elif supplied_way not in ("blocked", "allowlist"):
            raise FirewallRefused("firewall-way-invalid")
        elif supplied_way == "blocked":
            if has_names:
                raise FirewallRefused("firewall-way-hostnames-refused")
            way, names = "blocked", []
        else:
            if not has_names:
                raise FirewallRefused("firewall-allowlist-empty")
            names = canonical_fqdns(intent["hostnames"])
            if not names:
                raise FirewallRefused("firewall-allowlist-empty")
            way = "allowlist"
    elif action == "way-set":
        way = intent["way"]
        if way not in ("blocked", "allowlist"):
            raise FirewallRefused("firewall-way-invalid")
        if way == "blocked":
            if "hostnames" in keys:
                raise FirewallRefused("firewall-way-hostnames-refused")
            names = []
        else:
            if "hostnames" not in keys:
                raise FirewallRefused("firewall-allowlist-empty")
            names = canonical_fqdns(intent["hostnames"])
            if not names:
                raise FirewallRefused("firewall-allowlist-empty")
    elif action == "whitelist-set":
        names = canonical_fqdns(intent["hostnames"])
    mac = canonical_mac(intent.get("mac"))
    revision = intent.get("revision") if "revision" in keys else None
    if "revision" in keys and (not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision)):
        raise FirewallRefused("firewall-revision-invalid")
    if action in {"whitelist-set", "way-set"} and revision is None:
        raise FirewallRefused("firewall-revision-invalid")
    return action, mac, names, revision, way


def _live_state(policies: dict[str, dict[str, Any]], doh_resolvers: Sequence[str], expected_table: bool,
                global_zones: Sequence[str], wan_if: str,
                runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    expected = NftState(policies, tuple(doh_resolvers))
    _prove_live_nft(expected, expected_table, runner, wan_if)
    for mac, policy in policies.items():
        way = policy.get("way", "allowlist")
        if way == "blocked":
            _prove_live_dns_absent(mac, runner)
        elif way == "allowlist":
            _prove_live_dns(mac, policy["hostnames"], global_zones, runner)
        else:
            raise FirewallRefused("firewall-way-invalid")


def _read_images(policy_path: Path, nft_path: Path, parents: dict[str, int],
                 unbound_config_path: Path, wan_if: str,
                 runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[FileImage, FileImage, dict[str, dict[str, Any]], tuple[str, ...], tuple[str, ...], str]:
    policy_image = _snapshot(policy_path, parents[str(policy_path.parent)])
    nft_image = _snapshot(nft_path, parents[str(nft_path.parent)])
    global_zones = (_global_local_zones(unbound_config_path, runner)
                    if policy_image.exists and policy_image.data else ())
    unbound_policies = _parse_unbound(policy_image.data if policy_image.exists else b"", global_zones)
    nft_state = _parse_nft(nft_image.data, wan_if) if nft_image.exists else NftState({}, ())
    nft_allowlist = {mac for mac, item in nft_state.policies.items() if item["way"] == "allowlist"}
    if set(unbound_policies) != nft_allowlist:
        raise FirewallRefused("firewall-owned-policy-mismatch")
    policies: dict[str, dict[str, Any]] = {}
    for mac, item in nft_state.policies.items():
        if item["way"] == "blocked":
            policies[mac] = {**item, "hostnames": []}
            continue
        unbound = unbound_policies[mac]
        if unbound["ip"] != item["ip"]:
            raise FirewallRefused("firewall-owned-policy-mismatch")
        policies[mac] = {**item, "hostnames": list(unbound["hostnames"])}
    return (policy_image, nft_image, policies, nft_state.doh_resolvers, global_zones,
            _revision(policy_image, nft_image))


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
                       global_zones: Sequence[str], wan_if: str,
                       runner: Callable[[list[str]], tuple[bool, str, str]],
                       removed_mac: str | None = None) -> dict[str, Any]:
    policy_parent, nft_parent = parents[str(policy_path.parent)], parents[str(nft_path.parent)]
    expected_table = _expected_live_table(nft_source)
    old_nft_state = _parse_nft(nft_source.data, wan_if) if nft_source.exists else NftState({}, ())
    new_nft_state = _parse_nft(nft_candidate, wan_if)
    _stage_and_check(policy_path, nft_path, policy_parent, nft_parent, policy_source, nft_source,
                     policy_candidate, nft_candidate, runner)
    want_policy = policy_candidate is not None
    policy_same = policy_source.exists == want_policy and (not want_policy or policy_source.data == policy_candidate)
    nft_same = nft_source.exists and nft_source.data == nft_candidate
    if policy_same and nft_same:
        _live_state(new_policies, new_nft_state.doh_resolvers, expected_table,
                    global_zones, wan_if, runner)
        return {"ok": True, "changed": False, "revision": _revision(policy_source, nft_source),
                "rollback": "not-needed", "rollbackFiles": []}

    initial_live_exists, _initial_live_text = _live_table(runner)
    if initial_live_exists != expected_table:
        raise FirewallRefused("firewall-nft-live-table-presence-mismatch")
    if initial_live_exists:
        _prove_live_nft(old_nft_state, True, runner, wan_if)
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
        _live_state(new_policies, new_nft_state.doh_resolvers, True,
                    global_zones, wan_if, runner)
        old_allowlisted = {mac for mac, policy in old_policies.items()
                           if policy.get("way", "allowlist") == "allowlist"}
        new_allowlisted = {mac for mac, policy in new_policies.items()
                           if policy.get("way", "allowlist") == "allowlist"}
        for old_mac in sorted(old_allowlisted - new_allowlisted):
            _prove_live_dns_absent(old_mac, runner)
        if removed_mac is not None and removed_mac not in new_policies:
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
                current_state = _parse_live_nft(current_text, wan_if)
                current_is_candidate = _nft_state_key(current_state) == _nft_state_key(new_nft_state)
                current_is_old = initial_live_exists and _nft_state_key(current_state) == _nft_state_key(old_nft_state)
            else:
                current_is_old = not initial_live_exists and not old_nft_state.policies and not old_nft_state.doh_resolvers
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
                        _prove_live_nft(old_nft_state, True, runner, wan_if)
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
                    if old_policy.get("way", "allowlist") == "blocked":
                        _prove_live_dns_absent(old_mac, runner)
                    else:
                        _prove_live_dns(old_mac, old_policy["hostnames"], global_zones, runner)
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
                      policies: dict[str, dict[str, Any]], doh_resolvers: Sequence[str],
                      global_zones: Sequence[str], wan_if: str, revision: str, manager_factory: Any,
                      runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[Any | None, dict[str, dict[str, Any]], dict[str, dict[str, str]]]:
    expected_table = _expected_live_table(nft_image)
    if not policies:
        _live_state({}, doh_resolvers, expected_table, global_zones, wan_if, runner)
        return None, {}, {}
    manager = _dhcp_manager(manager_factory)
    bound = _bind_policies(policies, manager)
    disk_nft = _parse_nft(nft_image.data, wan_if) if nft_image.exists else NftState({}, ())
    for mac, policy in bound.items():
        if policy.get("way", "allowlist") == "allowlist" and disk_nft.policies[mac]["router"] != policy["router"]:
            raise FirewallRefused("firewall-dhcp-router-binding-mismatch")
    _live_state(bound, disk_nft.doh_resolvers, expected_table, global_zones, wan_if, runner)
    if any(policy.get("way", "allowlist") == "allowlist" for policy in bound.values()):
        _observed, leases = _lease_rows(manager)
    else:
        leases = {}
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
             unbound_config_path: Path = DEFAULT_UNBOUND_CONFIG,
             base_firewall_path: Path = DEFAULT_NFTABLES_CONFIG,
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
        action, mac, hostnames, supplied_revision, requested_way = _validate_intent(intent)
        policy_path, nft_path = Path(policy_path), Path(nft_path)
        unbound_config_path = Path(unbound_config_path)
        base_firewall_path = Path(base_firewall_path)
        if policy_path.name != "agathodaimon-child-policy.conf" or nft_path.name != "caduceus-child-filter.nft":
            raise FirewallRefused("firewall-owned-path-invalid")
        wan_if = _wan_interface(base_firewall_path)
        parents = _lock_parents([policy_path, nft_path])
        try:
            policy_image, nft_image, policies, doh_resolvers, global_zones, revision = _read_images(
                policy_path, nft_path, parents, unbound_config_path, wan_if, runner,
            )
            manager, bound, leases = _enforce_readback(
                policy_path, nft_path, policy_image, nft_image, policies, doh_resolvers,
                global_zones, wan_if, revision, dhcp_manager_factory, runner,
            )
            assert mac is None or isinstance(mac, str)
            if action == "register" and mac in bound:
                policy = bound[mac]
                pinned_ip = policy["ip"]
                return _receipt(action, True, False, "Child is already registered.", revision,
                                pinned={"ip": pinned_ip, "created": False}, mac=mac,
                                way=policy["way"], hostnames=list(policy["hostnames"]),
                                enforcement=_enforcement(mac, policy, leases or {}))
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
                    "way": bound[item_mac]["way"],
                    "hostnames": list(bound[item_mac]["hostnames"]),
                    "revision": revision,
                    "enforcement": _enforcement(item_mac, bound[item_mac], leases or {}),
                } for item_mac in sorted(bound)]
                return _receipt(action, True, False, "Registered firewall children.", revision, children=rows)

            assert mac is not None
            if supplied_revision is not None and supplied_revision != revision:
                raise FirewallRefused("firewall-revision-conflict")
            if action == "whitelist-get":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                policy = bound[mac]
                return _receipt(action, True, False, "Read the registered child whitelist.", revision,
                                mac=mac, way=policy["way"], hostnames=list(policy["hostnames"]),
                                enforcement=_enforcement(mac, policy, leases or {}))

            if action == "register":
                manager = manager or _dhcp_manager(dhcp_manager_factory)
                observed, leases = _observed_projection(manager, policies, runner)
                if mac not in {row["mac"] for row in observed}:
                    raise FirewallRefused("firewall-mac-not-observed")
                pinned_ip, created, reservation_error = _reservation_for(manager, mac)
                if reservation_error:
                    extra = {"pinned": {"ip": pinned_ip, "created": created}, "mac": mac}
                    if pinned_ip is not None:
                        extra["enforcement"] = "pending-renewal"
                    if requested_way is not None:
                        extra["way"] = requested_way
                    return _receipt(action, False, created, "Reservation readback failed.", revision,
                                    reservation_error, **extra)
                if pinned_ip is None:
                    raise FirewallRefused("firewall-dhcp-reservation-readback-mismatch")
                selected_way = requested_way or "allowlist"
                selected_names = list(hostnames or []) if selected_way == "allowlist" else []
                router = _router_for_ip(manager, pinned_ip) if selected_way == "allowlist" else None
                candidate = {key: dict(value) for key, value in bound.items()}
                selected = {"mac": mac, "ip": pinned_ip, "router": router,
                            "way": selected_way, "hostnames": selected_names}
                candidate[mac] = selected
                if any(item.get("way", "allowlist") == "allowlist" for item in candidate.values()):
                    global_zones = _global_local_zones(unbound_config_path, runner)
                candidate_unbound = _render_unbound(candidate, global_zones)
                candidate_nft = _nft_bytes(candidate, wan_if)
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, candidate_nft, candidate,
                                                 global_zones, wan_if, runner)
                if not transaction["ok"]:
                    enforcement = _enforcement(mac, selected, leases or {}, nft_proven=False)
                    return _receipt(action, False, bool(transaction["changed"] or created),
                                    "Firewall registration did not converge.",
                                    transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                    pinned={"ip": pinned_ip, "created": created}, mac=mac, way=selected_way,
                                    hostnames=selected_names, enforcement=enforcement,
                                    rollback=transaction.get("rollback", "failed"),
                                    **{key: value for key, value in transaction.items()
                                       if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})
                if selected_way == "blocked":
                    final_leases: dict[str, dict[str, str]] = {}
                else:
                    try:
                        _final_leases_observed, final_leases = _lease_rows(manager)
                    except FirewallRefused as exc:
                        return _receipt(action, False, bool(transaction["changed"] or created),
                                        "Firewall installed; lease enforcement readback is unavailable.",
                                        transaction.get("revision", revision), str(exc),
                                        pinned={"ip": pinned_ip, "created": created}, mac=mac,
                                        way=selected_way, hostnames=selected_names,
                                        enforcement="pending-renewal",
                                        rollback=transaction.get("rollback", "not-needed"))
                enforcement = _enforcement(mac, selected, final_leases)
                pending_message = enforcement == "pending-renewal"
                message = ("Firewall filter takes-hold-on-renewal when the device renews its lease."
                           if pending_message else "Child firewall registration is applied.")
                return _receipt(action, bool(transaction["ok"]), bool(transaction["changed"] or created), message,
                                transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                pinned={"ip": pinned_ip, "created": created}, mac=mac, way=selected_way,
                                hostnames=selected_names, enforcement=enforcement,
                                rollback=transaction.get("rollback", "not-needed"),
                                **{key: value for key, value in transaction.items()
                                   if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})

            if action == "unregister":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                enforcement = _enforcement(mac, bound[mac], leases or {})
                candidate = {key: dict(value) for key, value in bound.items() if key != mac}
                if any(item.get("way", "allowlist") == "allowlist" for item in candidate.values()):
                    global_zones = _global_local_zones(unbound_config_path, runner)
                candidate_unbound = _render_unbound(candidate, global_zones)
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, _nft_bytes(candidate, wan_if), candidate,
                                                 global_zones, wan_if, runner, removed_mac=mac)
                return _receipt(action, bool(transaction["ok"]), bool(transaction["changed"]),
                                "Child firewall registration removed; DHCP reservation retained.",
                                transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                mac=mac, enforcement=enforcement, rollback=transaction.get("rollback", "not-needed"),
                                **{key: value for key, value in transaction.items()
                                   if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})

            if action == "whitelist-set":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                if bound[mac]["way"] != "allowlist":
                    raise FirewallRefused("firewall-child-way-mismatch")
                candidate = {key: dict(value) for key, value in bound.items()}
                candidate[mac]["hostnames"] = list(hostnames or [])
                global_zones = _global_local_zones(unbound_config_path, runner)
                candidate_unbound = _render_unbound(candidate, global_zones)
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, _nft_bytes(candidate, wan_if), candidate,
                                                 global_zones, wan_if, runner)
                if not transaction["ok"]:
                    rollback_state = transaction.get("rollback", "failed")
                    fields = ({"hostnames": list(bound[mac]["hostnames"])} if rollback_state == "restored"
                              else {"attemptedHostnames": list(candidate[mac]["hostnames"])})
                    return _receipt(action, False, bool(transaction["changed"]), "Child whitelist update did not converge.",
                                    transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                    mac=mac, way=bound[mac]["way"], **fields,
                                    enforcement=_enforcement(mac, candidate[mac], leases or {}, nft_proven=False),
                                    rollback=transaction.get("rollback", "failed"),
                                    **{key: value for key, value in transaction.items()
                                       if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})
                try:
                    _observed_leases, final_leases = _lease_rows(manager)
                except FirewallRefused as exc:
                    return _receipt(action, False, bool(transaction["changed"]),
                                    "Whitelist installed; lease enforcement readback is unavailable.",
                                    transaction.get("revision", revision), str(exc), mac=mac,
                                    way=bound[mac]["way"], hostnames=list(candidate[mac]["hostnames"]),
                                    enforcement="pending-renewal",
                                    rollback=transaction.get("rollback", "not-needed"))
                enforcement = _enforcement(mac, candidate[mac], final_leases)
                return _receipt(action, bool(transaction["ok"]), bool(transaction["changed"]),
                                "Child whitelist updated.", transaction.get("revision", revision),
                                transaction.get("firstMissingSignal", "none"), mac=mac, way="allowlist",
                                hostnames=list(candidate[mac]["hostnames"]), enforcement=enforcement,
                                rollback=transaction.get("rollback", "not-needed"),
                                **{key: value for key, value in transaction.items()
                                   if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})

            if action == "way-set":
                if mac not in bound:
                    raise FirewallRefused("firewall-child-not-registered")
                candidate = {key: dict(value) for key, value in bound.items()}
                target = candidate[mac]
                target["way"] = requested_way
                target["hostnames"] = list(hostnames or []) if requested_way == "allowlist" else []
                if requested_way == "allowlist":
                    target["router"] = _router_for_ip(manager, target["ip"])
                    global_zones = _global_local_zones(unbound_config_path, runner)
                else:
                    target["router"] = None
                candidate_unbound = _render_unbound(candidate, global_zones)
                transaction = _apply_transaction(action, policy_path, nft_path, parents, policy_image, nft_image,
                                                 bound, candidate_unbound, _nft_bytes(candidate, wan_if), candidate,
                                                 global_zones, wan_if, runner)
                if not transaction["ok"]:
                    restored = transaction.get("rollback") == "restored"
                    actual = bound[mac] if restored else target
                    return _receipt(action, False, bool(transaction["changed"]),
                                    "Firewall way update did not converge.",
                                    transaction.get("revision", revision), transaction.get("firstMissingSignal", "none"),
                                    mac=mac, way=actual["way"], hostnames=list(actual["hostnames"]),
                                    enforcement=_enforcement(mac, actual, leases or {}, nft_proven=restored),
                                    rollback=transaction.get("rollback", "failed"),
                                    **{key: value for key, value in transaction.items()
                                       if key not in {"ok", "changed", "revision", "firstMissingSignal", "rollback"}})
                if requested_way == "blocked":
                    final_leases: dict[str, dict[str, str]] = {}
                else:
                    try:
                        _final_leases_observed, final_leases = _lease_rows(manager)
                    except FirewallRefused as exc:
                        return _receipt(action, False, bool(transaction["changed"]),
                                        "Firewall way installed; lease enforcement readback is unavailable.",
                                        transaction.get("revision", revision), str(exc), mac=mac,
                                        way=requested_way, hostnames=list(target["hostnames"]),
                                        enforcement="pending-renewal",
                                        rollback=transaction.get("rollback", "not-needed"))
                return _receipt(action, bool(transaction["ok"]), bool(transaction["changed"]),
                                "Child firewall way updated.", transaction.get("revision", revision),
                                transaction.get("firstMissingSignal", "none"), mac=mac,
                                way=requested_way, hostnames=list(target["hostnames"]),
                                enforcement=_enforcement(mac, target, final_leases),
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
                extra["way"] = bound[mac]["way"]
        if action == "register":
            extra["pinned"] = {"ip": pinned_ip, "created": created}
        return _receipt(action if isinstance(action, str) else "invalid", False, created,
                        "Firewall request refused.", revision, signal, **extra)

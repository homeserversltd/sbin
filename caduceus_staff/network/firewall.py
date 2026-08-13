"""Bounded Caduceus child DNS firewall staff actuator.

Caduceus owns only its two marked Unbound regions and the complete
``inet caduceus_child_filter`` table.  Kea remains read-only authority for
MAC reservations and router discovery.  Every reported enforcement receipt is
made from current command readback, never from the files we just wrote.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Sequence

from . import dns

SCHEMA = "caduceus.network.firewall.apply.v1"
DEFAULT_UNBOUND = Path("/etc/unbound/unbound.conf")
DEFAULT_NFT = Path("/etc/nftables.d/caduceus-child-filter.nft")
DEFAULT_KEA = Path("/etc/kea/kea-dhcp4.conf")
CHECKCONF = Path("/usr/sbin/unbound-checkconf")
NFT = Path("/usr/sbin/nft")
UNBOUND_CONTROL = Path("/usr/sbin/unbound-control")
SYSTEMCTL = Path("/bin/systemctl")
MAX_INPUT_BYTES = 8192
MAX_OUTPUT_BYTES = 131072
MAX_FQDNS = 64
BEGIN_ACCESS = b"# BEGIN CADUCEUS CHILD ACCESS"
END_ACCESS = b"# END CADUCEUS CHILD ACCESS"
BEGIN_VIEWS = b"# BEGIN CADUCEUS CHILD VIEWS"
END_VIEWS = b"# END CADUCEUS CHILD VIEWS"
BEGIN_NFT = b"# BEGIN CADUCEUS CHILD FILTER"
END_NFT = b"# END CADUCEUS CHILD FILTER"
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
FQDN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\.$")
TOP = re.compile(rb"^[A-Za-z][A-Za-z0-9-]*:[ \t]*(?:#.*)?$")
ACCESS_LINE = re.compile(rb'^\s*access-control-view:\s*([0-9.]+/32)\s+"([a-z0-9-]+)"\s*$')
VIEW_HEAD = re.compile(rb'^view:\s*$')
VIEW_NAME = re.compile(rb'^\s*name:\s*"([a-z0-9-]+)"\s*$')
ZONE = re.compile(rb'^\s*local-zone:\s*"([a-z0-9.-]+)"\s+(refuse|transparent)\s*$')
LIVE_ZONE = re.compile(r'^\s*(?:local-zone:\s*)?"?([a-z0-9.-]+)"?\s+(refuse|transparent)\s*$')
LIVE_RULE = re.compile(r"^ether saddr ([0-9a-f:]+) ip saddr ([0-9.]+) (udp|tcp) dport 53 ip daddr != ([0-9.]+) drop$")


class FirewallRefused(ValueError):
    pass


def _receipt(action: str, ok: bool, changed: bool, error: str = "none", **extra: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": ok, "action": action, "changed": changed,
            "serviceAction": "live-applied" if ok and action in {"put", "delete"} else "not-owned",
            "error": error, "firstMissingSignal": "none" if ok else error, **extra}


def canonical_mac(value: Any) -> str:
    if not isinstance(value, str):
        raise FirewallRefused("firewall-mac-invalid")
    compact = value.lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", compact):
        compact = ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    if not MAC.fullmatch(compact) or compact in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        raise FirewallRefused("firewall-mac-invalid")
    return compact


def canonical_fqdns(value: Any) -> list[str]:
    if not isinstance(value, list) or not (1 <= len(value) <= MAX_FQDNS):
        raise FirewallRefused("firewall-fqdns-invalid")
    names: set[str] = set()
    for raw in value:
        if not isinstance(raw, str) or len(raw) > 253:
            raise FirewallRefused("firewall-fqdn-invalid")
        name = raw.lower().rstrip(".") + "."
        if not FQDN.fullmatch(name) or name.endswith(".home.arpa."):
            raise FirewallRefused("firewall-fqdn-invalid")
        names.add(name)
    return sorted(names)


def view_name(mac: str) -> str:
    return "caduceus-child-" + mac.replace(":", "")


def _strip_kea_comments(text: str) -> str:
    """Remove #, // and /* */ comments without altering quoted JSON strings."""
    out: list[str] = []; i = 0; quoted = False; escape = False
    while i < len(text):
        c, n = text[i], text[i + 1] if i + 1 < len(text) else ""
        if quoted:
            out.append(c)
            if escape: escape = False
            elif c == "\\": escape = True
            elif c == '"': quoted = False
            i += 1; continue
        if c == '"': quoted = True; out.append(c); i += 1; continue
        if c == "#":
            while i < len(text) and text[i] not in "\r\n": i += 1
            continue
        if c == "/" and n == "/":
            i += 2
            while i < len(text) and text[i] not in "\r\n": i += 1
            continue
        if c == "/" and n == "*":
            end = text.find("*/", i + 2)
            if end < 0: raise FirewallRefused("firewall-kea-comments-invalid")
            i = end + 2; continue
        out.append(c); i += 1
    if quoted: raise FirewallRefused("firewall-kea-comments-invalid")
    return "".join(out)


def _admit_private(value: Any, error: str) -> str:
    try: ip = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError) as exc: raise FirewallRefused(error) from exc
    if not ip.is_private or ip.is_unspecified or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        raise FirewallRefused(error)
    return str(ip)


def _kea_bindings(path: Path) -> dict[str, tuple[str, str]]:
    try: payload = json.loads(_strip_kea_comments(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc: raise FirewallRefused("firewall-kea-readback-unavailable") from exc
    dhcp = payload.get("Dhcp4", payload)
    if not isinstance(dhcp, dict) or not isinstance(dhcp.get("subnet4"), list): raise FirewallRefused("firewall-kea-subnets-invalid")
    result: dict[str, tuple[str, str]] = {}
    for subnet in dhcp["subnet4"]:
        if not isinstance(subnet, dict) or not isinstance(subnet.get("subnet"), str): raise FirewallRefused("firewall-kea-subnets-invalid")
        try: network = ipaddress.IPv4Network(subnet["subnet"], strict=False)
        except ValueError as exc: raise FirewallRefused("firewall-kea-subnets-invalid") from exc
        routers = [x.get("data") for x in subnet.get("option-data", []) if isinstance(x, dict) and x.get("name") == "routers"]
        if len(routers) != 1 or not isinstance(routers[0], str): raise FirewallRefused("firewall-kea-router-ambiguous")
        values = [v.strip() for v in routers[0].split(",") if v.strip()]
        if len(values) != 1: raise FirewallRefused("firewall-kea-router-ambiguous")
        router = _admit_private(values[0], "firewall-kea-router-invalid")
        if ipaddress.IPv4Address(router) not in network: raise FirewallRefused("firewall-kea-router-invalid")
        reservations = subnet.get("reservations", [])
        if not isinstance(reservations, list): raise FirewallRefused("firewall-kea-reservations-invalid")
        for reservation in reservations:
            if not isinstance(reservation, dict) or "hw-address" not in reservation: continue
            mac = canonical_mac(reservation["hw-address"])
            ip = _admit_private(reservation.get("ip-address"), "firewall-kea-reservation-invalid")
            if ipaddress.IPv4Address(ip) not in network: raise FirewallRefused("firewall-kea-reservation-invalid")
            if mac in result: raise FirewallRefused("firewall-kea-reservation-ambiguous")
            result[mac] = (ip, router)
    return result


def _marker_spans(data: bytes) -> tuple[tuple[int, int] | None, tuple[int, int] | None]:
    lines = list(dns._segments(data)); locations: dict[bytes, list[int]] = {m: [] for m in (BEGIN_ACCESS, END_ACCESS, BEGIN_VIEWS, END_VIEWS)}
    for i, (_, _, raw) in enumerate(lines):
        if raw.rstrip(b"\r\n") in locations: locations[raw.rstrip(b"\r\n")].append(i)
    if any(len(v) > 1 for v in locations.values()): raise FirewallRefused("firewall-unbound-markers-duplicate")
    count = sum(bool(v) for v in locations.values())
    if count == 0: return None, None
    if count != 4: raise FirewallRefused("firewall-unbound-markers-missing")
    a0, a1 = locations[BEGIN_ACCESS][0], locations[END_ACCESS][0]; v0, v1 = locations[BEGIN_VIEWS][0], locations[END_VIEWS][0]
    if a0 >= a1 or v0 >= v1 or not (a1 < v0 or v1 < a0): raise FirewallRefused("firewall-unbound-markers-nested")
    return (lines[a0][0], lines[a1][1]), (lines[v0][0], lines[v1][1])


def _server_bounds(data: bytes) -> tuple[int, int]:
    sections = [(s, e, raw.split(b":", 1)[0]) for s, e, raw in dns._segments(data) if TOP.fullmatch(raw.rstrip(b"\r\n"))]
    servers = [(s, e) for s, e, name in sections if name == b"server"]
    if len(servers) != 1: raise FirewallRefused("firewall-unbound-server-ambiguous")
    start = servers[0][1]; later = [s for s, _, _ in sections if s >= start]
    return start, min(later) if later else len(data)


def _parse_regions(data: bytes) -> dict[str, dict[str, Any]]:
    access, views = _marker_spans(data)
    if access is None: return {}
    server_start, server_end = _server_bounds(data)
    if not (server_start <= access[0] and access[1] <= server_end): raise FirewallRefused("firewall-unbound-region-scope")
    ap = data[access[0]:access[1]].splitlines(); vp = data[views[0]:views[1]].splitlines()
    if ap[0] != BEGIN_ACCESS or ap[-1] != END_ACCESS or vp[0] != BEGIN_VIEWS or vp[-1] != END_VIEWS: raise FirewallRefused("firewall-unbound-region-foreign")
    policies: dict[str, dict[str, Any]] = {}
    for line in ap[1:-1]:
        match = ACCESS_LINE.fullmatch(line)
        if not match: raise FirewallRefused("firewall-unbound-access-foreign-directive")
        ip, name = match.group(1).decode(), match.group(2).decode()
        if name in policies: raise FirewallRefused("firewall-unbound-policy-duplicate")
        policies[name] = {"ip": _admit_private(ip.split("/")[0], "firewall-unbound-policy-invalid"), "fqdns": None}
    i = 1
    while i < len(vp) - 1:
        if not VIEW_HEAD.fullmatch(vp[i]) or i + 2 >= len(vp) - 1: raise FirewallRefused("firewall-unbound-views-foreign-directive")
        named, root = VIEW_NAME.fullmatch(vp[i + 1]), ZONE.fullmatch(vp[i + 2])
        if not named or not root or root.group(1) != b"." or root.group(2) != b"refuse": raise FirewallRefused("firewall-unbound-views-foreign-directive")
        name = named.group(1).decode()
        if name not in policies or policies[name]["fqdns"] is not None: raise FirewallRefused("firewall-unbound-policy-mismatch")
        i += 3; zones: list[str] = []
        while i < len(vp) - 1 and not VIEW_HEAD.fullmatch(vp[i]):
            zone = ZONE.fullmatch(vp[i])
            if not zone or zone.group(2) != b"transparent": raise FirewallRefused("firewall-unbound-views-foreign-directive")
            zones.append(zone.group(1).decode()); i += 1
        if not zones or len(zones) != len(set(zones)): raise FirewallRefused("firewall-unbound-policy-mismatch")
        policies[name]["fqdns"] = sorted(zones)
    if any(v["fqdns"] is None for v in policies.values()): raise FirewallRefused("firewall-unbound-policy-mismatch")
    out: dict[str, dict[str, Any]] = {}
    for name, value in policies.items():
        if not name.startswith("caduceus-child-") or len(name) != len("caduceus-child-") + 12: raise FirewallRefused("firewall-unbound-policy-mismatch")
        mac = canonical_mac(name.removeprefix("caduceus-child-"))
        if mac in out: raise FirewallRefused("firewall-unbound-policy-duplicate")
        out[mac] = {"mac": mac, **value}
    return out


def _render_access(policies: dict[str, dict[str, Any]], newline: bytes) -> bytes:
    out = bytearray(BEGIN_ACCESS + newline)
    for mac, policy in sorted(policies.items()): out.extend(f'    access-control-view: {policy["ip"]}/32 "{view_name(mac)}"'.encode() + newline)
    return bytes(out + END_ACCESS + newline)


def _render_views(policies: dict[str, dict[str, Any]], newline: bytes) -> bytes:
    out = bytearray(BEGIN_VIEWS + newline)
    for mac, policy in sorted(policies.items()):
        out.extend(b"view:" + newline + f'    name: "{view_name(mac)}"'.encode() + newline + b'    local-zone: "." refuse' + newline)
        for fqdn in policy["fqdns"]: out.extend(f'    local-zone: "{fqdn}" transparent'.encode() + newline)
    return bytes(out + END_VIEWS + newline)


def _unbound_candidate(data: bytes, policies: dict[str, dict[str, Any]]) -> bytes:
    newline = dns._newline_style(data); access, views = _marker_spans(data); _start, server_end = _server_bounds(data)
    ap, vp = _render_access(policies, newline), _render_views(policies, newline)
    if access is None:
        if data and not data.endswith((b"\n", b"\r")): raise FirewallRefused("firewall-unbound-final-newline-required")
        return data[:server_end] + ap + vp + data[server_end:]
    _parse_regions(data)
    for start, end, replacement in sorted(((access[0], access[1], ap), (views[0], views[1], vp)), reverse=True): data = data[:start] + replacement + data[end:]
    return data


def _nft_bytes(policies: dict[str, dict[str, Any]]) -> bytes:
    out = bytearray(BEGIN_NFT + b"\n# Caduceus owns this complete table only.\ntable inet caduceus_child_filter {\n    chain forward {\n        type filter hook forward priority -5; policy accept;\n")
    for mac, policy in sorted(policies.items()):
        ip, router = policy["ip"], policy["router"]
        out.extend(f"        ether saddr {mac} ip saddr {ip} udp dport 53 ip daddr != {router} drop\n".encode())
        out.extend(f"        ether saddr {mac} ip saddr {ip} tcp dport 53 ip daddr != {router} drop\n".encode())
    return bytes(out + b"    }\n}\n" + END_NFT + b"\n")


def _nft_batch(policies: dict[str, dict[str, Any]], replace_owned: bool) -> bytes:
    return (b"delete table inet caduceus_child_filter\n" if replace_owned else b"") + _nft_bytes(policies)


def _nft_absent_batch() -> bytes:
    return b"delete table inet caduceus_child_filter\n"


def _expected_rules(policies: dict[str, dict[str, Any]]) -> set[tuple[str, str, str, str]]:
    return {(mac, p["ip"], proto, p["router"]) for mac, p in policies.items() for proto in ("udp", "tcp")}


def _parse_nft(data: bytes) -> set[tuple[str, str]]:
    """Strictly validate the owned on-disk complete table and return identities."""
    text = data.decode("utf-8", "strict")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines: return set()
    if lines[:2] != ["table inet caduceus_child_filter {", "chain forward {"] or len(lines) < 5:
        raise FirewallRefused("firewall-nft-invalid")
    if lines[2] not in {"type filter hook forward priority -5; policy accept;", "type filter hook forward priority filter - 5; policy accept;"} or lines[-2:] != ["}", "}"]:
        raise FirewallRefused("firewall-nft-invalid")
    rules: set[tuple[str, str, str, str]] = set()
    for line in lines[3:-2]:
        match = LIVE_RULE.fullmatch(line)
        if not match: raise FirewallRefused("firewall-nft-invalid")
        mac, ip, proto, router = match.groups()
        rule = (canonical_mac(mac), _admit_private(ip, "firewall-nft-invalid"), proto, _admit_private(router, "firewall-nft-invalid"))
        if rule in rules: raise FirewallRefused("firewall-nft-invalid")
        rules.add(rule)
    identities = {(mac, ip) for mac, ip, _proto, _router in rules}
    if any(sum(1 for r in rules if r[:2] == identity) != 2 for identity in identities): raise FirewallRefused("firewall-nft-invalid")
    return identities


def _live_table(runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[bool, str]:
    ok, output, error = runner([str(NFT), "list", "table", "inet", "caduceus_child_filter"])
    if ok:
        if not isinstance(output, str) or len(output.encode()) > MAX_OUTPUT_BYTES: raise FirewallRefused("firewall-nft-live-readback-invalid")
        return True, output
    if error == "not-found": return False, ""
    raise FirewallRefused(error if error != "none" else "firewall-nft-live-readback-unavailable")


def _prove_live_nft(policies: dict[str, dict[str, Any]], runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    if not policies:
        return
    exists, live = _live_table(runner)
    if not exists: raise FirewallRefused("firewall-nft-live-table-missing")
    try:
        lines = [line.strip() for line in live.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        if lines[:2] != ["table inet caduceus_child_filter {", "chain forward {"] or len(lines) < 5:
            raise FirewallRefused("firewall-nft-live-table-mismatch")
        if lines[2] not in {"type filter hook forward priority -5; policy accept;", "type filter hook forward priority filter - 5; policy accept;"} or lines[-2:] != ["}", "}"]:
            raise FirewallRefused("firewall-nft-live-hook-mismatch")
        actual: set[tuple[str, str, str, str]] = set()
        for line in lines[3:-2]:
            match = LIVE_RULE.fullmatch(line)
            if not match: raise FirewallRefused("firewall-nft-live-rule-mismatch")
            mac, ip, proto, router = match.groups()
            rule = (canonical_mac(mac), _admit_private(ip, "firewall-nft-live-rule-mismatch"), proto, _admit_private(router, "firewall-nft-live-rule-mismatch"))
            if rule in actual: raise FirewallRefused("firewall-nft-live-rule-mismatch")
            actual.add(rule)
        if actual != _expected_rules(policies): raise FirewallRefused("firewall-nft-live-policy-mismatch")
    except UnicodeError as exc:
        raise FirewallRefused("firewall-nft-live-readback-invalid") from exc


def _prove_live_dns(mac: str, sites: list[str], runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    ok, output, error = runner([str(UNBOUND_CONTROL), "view_list_local_zones", view_name(mac)])
    if not ok: raise FirewallRefused(error if error != "none" else "firewall-unbound-live-readback-unavailable")
    if not isinstance(output, str) or len(output.encode()) > MAX_OUTPUT_BYTES: raise FirewallRefused("firewall-unbound-live-readback-invalid")
    zones: set[tuple[str, str]] = set()
    for line in output.splitlines():
        if not line.strip(): continue
        match = LIVE_ZONE.fullmatch(line)
        if not match: raise FirewallRefused("firewall-unbound-live-readback-invalid")
        zone, kind = match.groups(); zone = zone.lower()
        if zone != "." and not FQDN.fullmatch(zone): raise FirewallRefused("firewall-unbound-live-readback-invalid")
        entry = (zone, kind)
        if entry in zones: raise FirewallRefused("firewall-unbound-live-readback-invalid")
        zones.add(entry)
    expected = {(".", "refuse"), *((site, "transparent") for site in sites)}
    if zones != expected: raise FirewallRefused("firewall-unbound-live-zone-mismatch")


def _prove_live_dns_absent(mac: str, runner: Callable[[list[str]], tuple[bool, str, str]]) -> None:
    ok, output, error = runner([str(UNBOUND_CONTROL), "view_list_local_zones", view_name(mac)])
    if ok:
        raise FirewallRefused("firewall-unbound-live-view-extra")
    if error != "firewall-unbound-live-view-missing":
        raise FirewallRefused("firewall-unbound-live-view-absence-unproven")


def _digest(unbound: bytes, nft: bytes) -> str:
    access, views = _marker_spans(unbound)
    owned = b"" if access is None else unbound[access[0]:access[1]] + unbound[views[0]:views[1]]
    return hashlib.sha256(owned + nft).hexdigest()


def _run(argv: list[str]) -> tuple[bool, str, str]:
    try:
        p = subprocess.run(argv, text=True, capture_output=True, timeout=20, check=False)
        if p.returncode == 0:
            return True, p.stdout, "none"
        # Only this fixed Unbound query makes a missing view meaningful.  Every
        # other nonzero command result remains a refusal rather than absence.
        is_view_query = len(argv) == 3 and argv[:2] == [str(UNBOUND_CONTROL), "view_list_local_zones"]
        missing_view = re.search(
            r"(?:\b(?:unknown|missing|absent)\s+view\b|\bview\b[^\n]*(?:not\s+found|does\s+not\s+exist|unknown|missing|absent)|\b(?:no\s+such|not\s+found)\b[^\n]*\bview\b)",
            p.stderr.lower(),
        )
        if is_view_query and missing_view:
            return False, p.stdout, "firewall-unbound-live-view-missing"
        return False, p.stdout, "firewall-live-command-refused"
    except (OSError, subprocess.SubprocessError): return False, "", "firewall-live-command-unavailable"


def _validate_unbound(path: Path) -> tuple[bool, str]:
    ok, _out, err = _run([str(CHECKCONF), str(path)]); return ok, err.replace("live-command", "unbound-validator")


def _validate_nft(path: Path) -> tuple[bool, str]:
    ok, _out, err = _run([str(NFT), "-c", "-f", str(path)]); return ok, err.replace("live-command", "nft-validator")


def _locks(paths: Sequence[Path]) -> list[int]:
    unique = {str(p.parent.resolve()): p for p in paths}
    return [dns._open_locked_parent(unique[key]) for key in sorted(unique)]


def _restore(path: Path, original: bytes, metadata: os.stat_result, source: dns.FileSnapshot, installed: dns.FileSnapshot, validator: Callable[[Path], tuple[bool, str]]) -> str:
    return dns._rollback(path, original, metadata, source.xattrs, installed, source, validator)[0]


def _policy_public(policy: dict[str, Any], revision: str, receipt: dict[str, Any] | None = None) -> dict[str, Any]:
    value = {"mac": policy["mac"], "ip": policy["ip"], "sites": policy["fqdns"], "enabled": True, "revision": revision}
    if receipt is not None: value["receipt"] = receipt
    return value


def _policy_receipt(policy: dict[str, Any], runner: Callable[[list[str]], tuple[bool, str, str]], all_policies: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    try:
        _prove_live_nft(all_policies if all_policies is not None else {policy["mac"]: policy}, runner)
        _prove_live_dns(policy["mac"], policy["fqdns"], runner)
        return {"mac": policy["mac"], "bindingVerified": True, "nft": {"applied": True, "liveReadback": True}, "dns": {"required": True, "validated": True, "applied": True}, "firstMissingSignal": "none"}
    except FirewallRefused as exc:
        return {"mac": policy["mac"], "bindingVerified": True, "nft": {"applied": False, "liveReadback": False}, "dns": {"required": True, "validated": False, "applied": False}, "firstMissingSignal": str(exc)}


def _read_current(unbound_path: Path, nft_path: Path, kea_path: Path, checkconf: Callable[[Path], tuple[bool, str]], nft_check: Callable[[Path], tuple[bool, str]], runner: Callable[[list[str]], tuple[bool, str, str]]) -> tuple[bytes, os.stat_result, dns.FileSnapshot, bytes, os.stat_result, dns.FileSnapshot, dict[str, dict[str, Any]], str, list[dict[str, Any]], str]:
    unbound, umeta, us = dns._snapshot(unbound_path); nft, nmeta, ns = dns._snapshot(nft_path)
    valid, error = checkconf(unbound_path)
    if not valid: raise FirewallRefused(error or "firewall-unbound-validator-refused")
    valid, error = nft_check(nft_path)
    if not valid: raise FirewallRefused(error or "firewall-nft-validator-refused")
    policies = _parse_regions(unbound); on_disk = _parse_nft(nft)
    bindings = _kea_bindings(kea_path)
    for mac, policy in policies.items():
        binding = bindings.get(mac)
        if binding is None or binding[0] != policy["ip"]: raise FirewallRefused("firewall-kea-binding-mismatch")
        policy["router"] = binding[1]
    if on_disk != {(mac, p["ip"]) for mac, p in policies.items()}: raise FirewallRefused("firewall-nft-policy-mismatch")
    revision = _digest(unbound, nft)
    receipts = {mac: _policy_receipt(policy, runner, policies) for mac, policy in policies.items()}
    public = [_policy_public(policy, revision, receipts[mac]) for mac, policy in sorted(policies.items())]
    missing = next((r["firstMissingSignal"] for r in receipts.values() if r["firstMissingSignal"] != "none"), "none")
    return unbound, umeta, us, nft, nmeta, ns, policies, revision, public, missing


def dispatch(intent: Any, *, unbound_path: Path = DEFAULT_UNBOUND, nft_path: Path = DEFAULT_NFT, kea_path: Path = DEFAULT_KEA,
             checkconf: Callable[[Path], tuple[bool, str]] = _validate_unbound, nft_check: Callable[[Path], tuple[bool, str]] = _validate_nft,
             runner: Callable[[list[str]], tuple[bool, str, str]] = _run) -> dict[str, Any]:
    action = intent.get("action") if isinstance(intent, dict) else "invalid"; locks: list[int] = []
    try:
        if not isinstance(intent, dict) or not isinstance(action, str) or set(intent) - {"action", "mac", "fqdns", "revision"}: raise FirewallRefused("firewall-intent-invalid")
        if action not in {"status", "list", "get", "put", "delete"}: raise FirewallRefused("firewall-intent-action-invalid")
        if action in {"status", "list"} and set(intent) != {"action"}: raise FirewallRefused("firewall-intent-invalid")
        if action == "get" and set(intent) != {"action", "mac"}: raise FirewallRefused("firewall-intent-invalid")
        locks = _locks([Path(unbound_path), Path(nft_path)])
        unbound, umeta, us, nft, nmeta, ns, policies, revision, public, missing = _read_current(Path(unbound_path), Path(nft_path), Path(kea_path), checkconf, nft_check, runner)
        if action in {"status", "list"}:
            # `_read_current` parsed Kea and attended every existing binding.
            return _receipt(action, True, False, policies=public, revision=revision, available=True, stableBinding={"available": True}, validation="readback", firstMissingSignal=missing)
        mac = canonical_mac(intent.get("mac"))
        if action == "get":
            if mac not in policies: raise FirewallRefused("firewall-policy-not-found")
            return _receipt(action, True, False, policy=next(x for x in public if x["mac"] == mac), revision=revision, available=True, firstMissingSignal=next(x["receipt"]["firstMissingSignal"] for x in public if x["mac"] == mac))
        supplied = intent.get("revision")
        if not isinstance(supplied, str) or not re.fullmatch(r"[0-9a-f]{64}", supplied) or supplied != revision: raise FirewallRefused("firewall-revision-conflict")
        exists = mac in policies
        if action == "delete" and not exists: raise FirewallRefused("firewall-policy-not-found")
        candidate = dict(policies)
        if action == "put":
            if "fqdns" not in intent: raise FirewallRefused("firewall-intent-invalid")
            ip, router = _kea_bindings(Path(kea_path)).get(mac, (None, None))
            if not ip: raise FirewallRefused("firewall-kea-reservation-ambiguous")
            candidate[mac] = {"mac": mac, "ip": ip, "router": router, "fqdns": canonical_fqdns(intent["fqdns"])}
        else: candidate.pop(mac)
        cu, cn = _unbound_candidate(unbound, candidate), _nft_bytes(candidate)
        if cu == unbound and cn == nft:
            selected = _policy_receipt(candidate[mac], runner, candidate) if mac in candidate else {"mac": mac, "bindingVerified": True, "nft": {"applied": True, "liveReadback": True}, "dns": {"required": True, "validated": True, "applied": True}, "firstMissingSignal": "none"}
            if mac not in candidate:
                # No policy must also mean the live table proves that the selected identity is absent.
                _prove_live_nft(candidate, runner)
            return _receipt(action, selected["firstMissingSignal"] == "none", False, selected["firstMissingSignal"], policy={"mac": mac}, receipt=selected, revision=revision, validation="validated-noop", rollback="not-needed")
        for path, payload, meta, snap, validator in ((Path(unbound_path), cu, umeta, us, checkconf), (Path(nft_path), cn, nmeta, ns, nft_check)):
            valid, error = dns._stage_validate(path, payload, meta, snap.xattrs, validator)
            if not valid: return _receipt(action, False, False, error, validation="candidate-refused", rollback="not-needed")
        initial_live_exists, _initial_live = _live_table(runner)
        if policies: _prove_live_nft(policies, runner)
        installed: list[tuple[Path, bytes, os.stat_result, dns.FileSnapshot, dns.FileSnapshot, Callable[[Path], tuple[bool, str]]]] = []
        try:
            iu = dns._install(Path(unbound_path), cu, umeta, us.xattrs, us); installed.append((Path(unbound_path), unbound, umeta, us, iu, checkconf))
            inn = dns._install(Path(nft_path), cn, nmeta, ns.xattrs, ns); installed.append((Path(nft_path), nft, nmeta, ns, inn, nft_check))
            batch = dns._write_staged(Path(nft_path), ".caduceus-firewall-live-", _nft_batch(candidate, initial_live_exists), nmeta, ns.xattrs)
            try: ok, _out, error = runner([str(NFT), "-f", str(batch)])
            finally: batch.unlink(missing_ok=True)
            if not ok: raise FirewallRefused(error)
            ok, _out, error = runner([str(SYSTEMCTL), "reload", "unbound"])
            if not ok: raise FirewallRefused(error)
            final_u, _, _ = dns._snapshot(Path(unbound_path)); final_n, _, _ = dns._snapshot(Path(nft_path))
            valid, error = checkconf(Path(unbound_path))
            if not valid: raise FirewallRefused(error)
            valid, error = nft_check(Path(nft_path))
            if not valid: raise FirewallRefused(error)
            new = _parse_regions(final_u)
            for p in new.values(): p["router"] = _kea_bindings(Path(kea_path))[p["mac"]][1]
            if _parse_nft(final_n) != {(m, p["ip"]) for m, p in new.items()}: raise FirewallRefused("firewall-readback-mismatch")
            # For delete, this checks all survivors and the exact live absence of the selected identity.
            if new: _prove_live_nft(new, runner)
            else: _prove_live_nft({}, runner)
            if mac in new: selected = _policy_receipt(new[mac], runner, new)
            else:
                _prove_live_dns_absent(mac, runner)
                selected = {"mac": mac, "bindingVerified": True, "nft": {"applied": True, "liveReadback": True}, "dns": {"required": True, "validated": True, "applied": True}, "firstMissingSignal": "none"}
            if selected["firstMissingSignal"] != "none": raise FirewallRefused(selected["firstMissingSignal"])
            return _receipt(action, True, True, policy={"mac": mac}, receipt=selected, revision=_digest(final_u, final_n), validation="installed-validated", rollback="not-needed")
        except Exception as exc:
            rollback = [_restore(path, original, meta, source, installed_snapshot, validator) for path, original, meta, source, installed_snapshot, validator in reversed(installed)]
            live_ok = False; reload_ok = False
            try:
                current_exists, _current = _live_table(runner)
                # Never delete/recreate a live table unless it remains exactly our candidate.
                candidate_still_owned = (not candidate and not current_exists) or (bool(candidate) and current_exists and not _prove_live_nft(candidate, runner))
                if candidate_still_owned:
                    batch = _nft_batch(policies, initial_live_exists) if initial_live_exists else _nft_absent_batch()
                    staged = dns._write_staged(Path(nft_path), ".caduceus-firewall-live-rollback-", batch, nmeta, ns.xattrs)
                    try: live_ok, _, _ = runner([str(NFT), "-f", str(staged)])
                    finally: staged.unlink(missing_ok=True)
                    if live_ok and policies: _prove_live_nft(policies, runner)
                    elif live_ok and initial_live_exists: live_ok = False
                reload_ok, _, _ = runner([str(SYSTEMCTL), "reload", "unbound"])
            except Exception:
                live_ok = reload_ok = False
            state = "restored" if rollback and all(x == "restored" for x in rollback) and live_ok and reload_ok else "failed"
            return _receipt(action, False, False, str(exc), validation="installed-refused", rollback=state, rollbackFiles=rollback, rollbackLiveNft=bool(live_ok), rollbackUnboundReload=bool(reload_ok))
    except (FirewallRefused, dns.DnsRefused, OSError, KeyError) as exc:
        return _receipt(action if isinstance(action, str) else "invalid", False, False, str(exc), validation="not-run", rollback="not-needed")
    finally:
        for fd in reversed(locks): os.close(fd)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-network-firewall"); parser.parse_args(argv)
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    try: value = _receipt("invalid", False, False, "firewall-input-too-large") if len(raw) > MAX_INPUT_BYTES else dispatch(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError): value = _receipt("invalid", False, False, "firewall-input-invalid")
    print(json.dumps(value, sort_keys=True)); return 0 if value["ok"] else 1


if __name__ == "__main__": raise SystemExit(main())

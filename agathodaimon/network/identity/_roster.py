from __future__ import annotations

from typing import Any
from agathodaimon import _load_trace
from agathodaimon.network.dhcp._manager import DhcpManager
from agathodaimon.network.dns._manager import DnsManager
from agathodaimon.network.identity._claim import IdentityClaimCoordinator


def _device_projection() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Fuse the real roster once under one transient staff span."""
    with _load_trace.span(
        "agathodaimon.network.identity.roster_fusion",
        source_state="dhcp-dns-roster",
    ):
        return _device_projection_body()


def _device_projection_body() -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Separate device identities from DNS service names on infrastructure addresses."""
    dhcp = DhcpManager()
    dns = DnsManager().read()
    records: dict[str, dict[str, Any]] = {}
    for reservation in dhcp.reservations():
        item = records.setdefault(reservation["mac"], {"mac": reservation["mac"], "observed_lease": None, "declared_reservation": None, "dns_names": [], "dns_name_records": [], "mismatches": []})
        item["declared_reservation"] = {"ip": reservation["ip"], "hostname": reservation["hostname"], "provenance": "declared"}
    for lease in dhcp.leases():
        item = records.setdefault(lease["mac"], {"mac": lease["mac"], "observed_lease": None, "declared_reservation": None, "dns_names": [], "dns_name_records": [], "mismatches": []})
        item["observed_lease"] = {"ip": lease["ip"], "hostname": lease["hostname"], "last_activity": lease["last_activity"], "provenance": "observed"}
    dns_by_ip: dict[str, list[dict[str, str]]] = {}
    for record in dns["devices"]:
        for a_record in record.get("a_records", ({"address": address, "provenance": "owned"} for address in record["a"])):
            dns_by_ip.setdefault(a_record["address"], []).append({"name": record["name"], "provenance": a_record["provenance"]})
    for item in records.values():
        declared, observed = item["declared_reservation"], item["observed_lease"]
        ips = {value["ip"] for value in (declared, observed) if value}
        names = {(entry["name"], entry["provenance"]) for ip in ips for entry in dns_by_ip.get(ip, [])}
        item["dns_name_records"] = [{"name": name, "provenance": provenance} for name, provenance in sorted(names)]
        item["dns_names"] = sorted({name for name, _provenance in names})
        if declared and observed and declared["ip"] != observed["ip"]:
            item["mismatches"].append("reservation-ip-differs-from-observed-lease")
        declared_names = dns_by_ip.get(declared["ip"], []) if declared else []
        if declared and not declared_names:
            item["mismatches"].append("reservation-without-dns-record")
        has_declared_name = bool(declared_names)
        item["claim_state"] = "claimed" if declared and has_declared_name else "partial" if any((declared, item["dns_names"], observed)) else "unclaimed"
    known_ips = {
        value["ip"]
        for item in records.values()
        for value in (item["declared_reservation"], item["observed_lease"])
        if value
    }
    infrastructure_addresses = {IdentityClaimCoordinator.RESOLVER_GATEWAY_ADDRESS}
    infrastructure_addresses.update(address for kind, address in dhcp.address_parts(dhcp.get_config(), include_gateways=False) if kind == "subnet-router")
    service_names: list[dict[str, str]] = []
    for address, names in dns_by_ip.items():
        if address in known_ips:
            continue
        for entry in names:
            if address in infrastructure_addresses:
                service_names.append({"name": entry["name"], "address": address, "provenance": entry["provenance"]})
                continue
            key = f"dns:{entry['name']}:{address}:{entry['provenance']}"
            records[key] = {
                "mac": None, "observed_lease": None, "declared_reservation": None,
                "dns_names": [entry["name"]], "dns_name_records": [entry], "claim_state": "partial",
                "mismatches": ["dns-record-without-reservation"],
            }
    return [records[key] for key in sorted(records)], sorted(service_names, key=lambda item: (item["name"], item["address"], item["provenance"]))

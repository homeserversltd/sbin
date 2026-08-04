from __future__ import annotations

import argparse
from typing import Any, Sequence

from caduceus_staff.receipts import emit_actuator
from caduceus_staff.network.dhcp import DhcpError, DhcpReader
from caduceus_staff.network.dns import DnsError, DnsReader


def device_list() -> list[dict[str, Any]]:
    dhcp = DhcpReader()
    dns = DnsReader().read()
    records: dict[str, dict[str, Any]] = {}
    for reservation in dhcp.reservations():
        item = records.setdefault(reservation["mac"], {"mac": reservation["mac"], "observed_lease": None, "declared_reservation": None, "dns_names": [], "mismatches": []})
        item["declared_reservation"] = {"ip": reservation["ip"], "provenance": "declared"}
    for lease in dhcp.leases():
        item = records.setdefault(lease["mac"], {"mac": lease["mac"], "observed_lease": None, "declared_reservation": None, "dns_names": [], "mismatches": []})
        item["observed_lease"] = {"ip": lease["ip"], "last_activity": lease["last_activity"], "provenance": "observed"}
    dns_by_ip: dict[str, list[str]] = {}
    for record in dns["devices"]:
        for address in record["a"]:
            dns_by_ip.setdefault(address, []).append(record["name"])
    for item in records.values():
        declared = item["declared_reservation"]
        observed = item["observed_lease"]
        ips = {value["ip"] for value in (declared, observed) if value}
        item["dns_names"] = sorted({name for ip in ips for name in dns_by_ip.get(ip, [])})
        if declared and observed and declared["ip"] != observed["ip"]:
            item["mismatches"].append("reservation-ip-differs-from-observed-lease")
        if declared and not item["dns_names"]:
            item["mismatches"].append("reservation-without-dns-record")
        if declared and any(name not in item["dns_names"] for name in dns_by_ip.get(declared["ip"], [])):
            item["mismatches"].append("reservation-ip-differs-from-dns-a-target")
        item["claim_state"] = "claimed" if declared and item["dns_names"] else "partial" if declared or item["dns_names"] or observed else "unclaimed"
    declared_ips = {item["declared_reservation"]["ip"] for item in records.values() if item["declared_reservation"]}
    for record in dns["devices"]:
        for address in record["a"]:
            if address not in declared_ips:
                key = f"dns:{record['name']}:{address}"
                records[key] = {"mac": None, "observed_lease": None, "declared_reservation": None, "dns_names": [record["name"]], "claim_state": "partial", "mismatches": ["dns-record-without-reservation"]}
    return [records[key] for key in sorted(records)]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-network-identity")
    parser.add_argument("command", choices=("device-list",))
    args = parser.parse_args(argv)
    try:
        return emit_actuator("network.identity.device_list", "caduceus.staff.network.identity.v1", "device_list", device_list())
    except (DhcpError, DnsError) as exc:
        return emit_actuator("network.identity.device_list", "caduceus.staff.network.identity.v1", "device_list", None, ok=False, first_missing_signal=str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Sequence

from caduceus_staff.network.dhcp import DhcpError, DhcpManager, normalize_mac
from caduceus_staff.network.dns import DnsError, DnsManager
from caduceus_staff.receipts import emit


class IdentityError(RuntimeError):
    """A bounded identity-claim refusal."""


def device_list() -> list[dict[str, Any]]:
    """Fuse declared DHCP, observed leases, and owned DNS by normalized MAC."""
    dhcp = DhcpManager()
    dns = DnsManager().read()
    records: dict[str, dict[str, Any]] = {}
    for reservation in dhcp.reservations():
        item = records.setdefault(reservation["mac"], {"mac": reservation["mac"], "observed_lease": None, "declared_reservation": None, "dns_names": [], "mismatches": []})
        item["declared_reservation"] = {"ip": reservation["ip"], "hostname": reservation["hostname"], "provenance": "declared"}
    for lease in dhcp.leases():
        item = records.setdefault(lease["mac"], {"mac": lease["mac"], "observed_lease": None, "declared_reservation": None, "dns_names": [], "mismatches": []})
        item["observed_lease"] = {"ip": lease["ip"], "hostname": lease["hostname"], "last_activity": lease["last_activity"], "provenance": "observed"}
    dns_by_ip: dict[str, list[str]] = {}
    for record in dns["devices"]:
        for address in record["a"]:
            dns_by_ip.setdefault(address, []).append(record["name"])
    for item in records.values():
        declared, observed = item["declared_reservation"], item["observed_lease"]
        ips = {value["ip"] for value in (declared, observed) if value}
        item["dns_names"] = sorted({name for ip in ips for name in dns_by_ip.get(ip, [])})
        if declared and observed and declared["ip"] != observed["ip"]:
            item["mismatches"].append("reservation-ip-differs-from-observed-lease")
        if declared and not item["dns_names"]:
            item["mismatches"].append("reservation-without-dns-record")
        item["claim_state"] = "claimed" if declared and item["dns_names"] else "partial" if declared or item["dns_names"] or observed else "unclaimed"
    return [records[key] for key in sorted(records)]


class IdentityClaimCoordinator:
    """Lock-held, compensating composition of existing DHCP and DNS membranes."""

    LOCK_PATH = Path("/var/lib/caduceus/network-identity-claim.lock")
    JOURNAL_DIR = Path("/var/lib/caduceus/journals/network-identity")

    def __init__(self, dhcp: DhcpManager | None = None, dns: DnsManager | None = None, *, lock_path: str | Path | None = None, journal_dir: str | Path | None = None) -> None:
        self.dhcp = dhcp or DhcpManager()
        self.dns = dns or DnsManager()
        self.lock_path = Path(lock_path or os.environ.get("CADUCEUS_IDENTITY_LOCK", self.LOCK_PATH))
        self.journal_dir = Path(journal_dir or os.environ.get("CADUCEUS_IDENTITY_JOURNAL", self.JOURNAL_DIR))

    def _fresh_state(self) -> dict[str, Any]:
        return {"reservations": self.dhcp.reservations(), "leases": self.dhcp.leases(), "boundary": self.dhcp.boundary(), "dns": self.dns.read()}

    @staticmethod
    def _in_boundaries(address: str, boundaries: list[dict[str, str]]) -> bool:
        candidate = ipaddress.IPv4Address(address)
        return any(ipaddress.IPv4Address(boundary["start"]) <= candidate <= ipaddress.IPv4Address(boundary["end"]) for boundary in boundaries)

    @staticmethod
    def _infrastructure_addresses(config: dict[str, Any]) -> set[str]:
        result: set[str] = set()
        for subnet in config.get("Dhcp4", {}).get("subnet4", []):
            for option in subnet.get("option-data", []):
                if isinstance(option, dict) and option.get("name") == "routers":
                    result.update(value.strip() for value in str(option.get("data", "")).split(","))
        return result

    def _taken_addresses(self, fresh: dict[str, Any]) -> set[str]:
        taken = {item["ip"] for item in fresh["reservations"]} | {item["ip"] for item in fresh["leases"]}
        taken |= self._infrastructure_addresses(self.dhcp.get_config())
        taken |= {address for record in fresh["dns"]["devices"] for address in record["a"]}
        return taken

    def _resolve_ip(self, explicit: str | None, fresh: dict[str, Any]) -> str:
        boundaries, taken = fresh["boundary"], self._taken_addresses(fresh)
        if not boundaries:
            raise IdentityError("current-kea-boundary-unavailable")
        if explicit is not None:
            try:
                ipaddress.IPv4Address(explicit)
            except ipaddress.AddressValueError as exc:
                raise IdentityError("claim-ip-malformed") from exc
            if not self._in_boundaries(explicit, boundaries):
                raise IdentityError("claim-ip-outside-current-kea-boundary")
            if explicit in taken:
                raise IdentityError("claim-ip-taken")
            return explicit
        for boundary in boundaries:
            start, end = ipaddress.IPv4Address(boundary["start"]), ipaddress.IPv4Address(boundary["end"])
            for value in range(int(start), int(end) + 1):
                candidate = str(ipaddress.IPv4Address(value))
                if candidate not in taken:
                    return candidate
        raise IdentityError("current-kea-boundary-exhausted")

    def _validate_candidates(self, mac: str, address: str, hostname: str, fresh: dict[str, Any]) -> str:
        canonical = self.dns.canonical_name(hostname)
        if any(item["mac"] == mac for item in fresh["reservations"]):
            raise IdentityError("claim-mac-already-reserved")
        self.dns._validate_candidate(self.dns._owned_records() + [f"{canonical} IN A {address}", f"{self.dns._reverse_name(address)} IN PTR {canonical}"], {canonical.rstrip(".").lower(), self.dns._reverse_name(address).rstrip(".").lower()})
        return canonical

    def _journal(self, request_key: str, dhcp_preimage: dict[str, Any], dns_preimage: bytes | None) -> Path:
        self.journal_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.journal_dir / f"{request_key}.json"
        payload = {"schema": "caduceus.staff.network.identity.preimage.v1", "dhcp": dhcp_preimage, "dns_base64": base64.b64encode(dns_preimage).decode("ascii") if dns_preimage is not None else None}
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        os.replace(temporary, path)
        return path

    def _rollback(self, dhcp_preimage: dict[str, Any], dns_preimage: bytes | None) -> dict[str, Any]:
        receipt: dict[str, Any] = {}
        try:
            self.dhcp.update_config(dhcp_preimage)
            receipt["dhcp_restoration"] = {"verified": self.dhcp.get_config() == dhcp_preimage}
            if not receipt["dhcp_restoration"]["verified"]:
                raise IdentityError("dhcp-preimage-restoration-mismatch")
            receipt["dns_restoration"] = self.dns.restore_owned_preimage(dns_preimage)
            return receipt
        except (DhcpError, DnsError, IdentityError) as exc:
            receipt["error"] = str(exc)
            raise IdentityError(json.dumps(receipt, sort_keys=True)) from exc

    def claim(self, mac_value: str, hostname: str, *, ip: str | None = None, auto_ip: bool = False) -> dict[str, Any]:
        if (ip is None and not auto_ip) or (ip is not None and auto_ip):
            return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "blocked", "first_failing_boundary": "claim-requires-exactly-one-ip-mode", "mutationPerformed": False}
        try:
            mac = normalize_mac(mac_value)
            canonical = self.dns.canonical_name(hostname)
        except (DhcpError, DnsError) as exc:
            return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "blocked", "first_failing_boundary": str(exc), "mutationPerformed": False}
        request_key = hashlib.sha256(f"{mac}|{ip or 'auto'}|{canonical}".encode()).hexdigest()
        self.lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self.lock_path.open("a+") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            mutated = False
            dhcp_preimage: dict[str, Any] | None = None
            dns_preimage: bytes | None = None
            try:
                fresh = self._fresh_state()
                existing = next((item for item in fresh["reservations"] if item["mac"] == mac), None)
                if existing and existing["hostname"].lower() == hostname.lower() and any(record["name"] == canonical.rstrip(".") and existing["ip"] in record["a"] for record in fresh["dns"]["devices"]):
                    return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "noop", "request_id": request_key, "first_failing_boundary": "none", "mutationPerformed": False}
                address = self._resolve_ip(ip, fresh)
                self._validate_candidates(mac, address, hostname, fresh)
                dhcp_preimage, dns_preimage = self.dhcp.get_config(), self.dns.owned_preimage()
                journal = self._journal(request_key, dhcp_preimage, dns_preimage)
                dhcp_result = self.dhcp.add_reservation(mac, address, hostname.lower())
                mutated = True
                dhcp_verified = next((item for item in self.dhcp.reservations() if item["mac"] == mac and item["ip"] == address), None)
                if dhcp_verified is None:
                    raise IdentityError("dhcp-verification-failed")
                dns_result = self.dns.create_device_name(hostname, address)
                if dns_result["state"] not in {"applied", "noop"}:
                    raise IdentityError("dns-verification-failed")
                return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "applied", "request_id": request_key, "address": address, "canonical_name": canonical, "journal": str(journal), "dhcp_verified": {"reservation": dhcp_verified, "receipt": dhcp_result}, "dns_verified": dns_result, "first_failing_boundary": "none", "mutationPerformed": True}
            except (DhcpError, DnsError, IdentityError) as exc:
                if not mutated:
                    return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "blocked", "request_id": request_key, "first_failing_boundary": str(exc), "mutationPerformed": False}
                try:
                    if dhcp_preimage is None:
                        raise IdentityError("preimage-missing-after-mutation")
                    restored = self._rollback(dhcp_preimage, dns_preimage)
                    return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "rolled_back", "request_id": request_key, "first_failing_boundary": str(exc), "restoration": restored, "mutationPerformed": True}
                except IdentityError as rollback:
                    return {"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "rollback_failed", "request_id": request_key, "first_failing_boundary": str(exc), "rollback_error": str(rollback), "mutationPerformed": True}
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-network-identity")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("device-list")
    claim = commands.add_parser("claim")
    claim.add_argument("--mac", required=True)
    mode = claim.add_mutually_exclusive_group(required=True)
    mode.add_argument("--ip")
    mode.add_argument("--auto-ip", action="store_true")
    claim.add_argument("--hostname", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "device-list":
            return emit({"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.device_list", "action": "device_list", "result": device_list(), "mutationPerformed": False, "firstMissingSignal": "none"})
        receipt = IdentityClaimCoordinator().claim(args.mac, args.hostname, ip=args.ip, auto_ip=args.auto_ip)
        return emit(receipt)
    except (DhcpError, DnsError, IdentityError) as exc:
        return emit({"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "blocked", "ok": False, "mutationPerformed": False, "first_failing_boundary": str(exc)})


if __name__ == "__main__":
    raise SystemExit(main())

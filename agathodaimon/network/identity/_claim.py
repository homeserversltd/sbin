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

from agathodaimon import _load_trace
from agathodaimon.network.dhcp._manager import DhcpError, DhcpManager, normalize_mac
from agathodaimon.network.dns._manager import DnsError, DnsManager
from agathodaimon.lib.receipts import emit


class IdentityError(RuntimeError):
    """A bounded identity-claim refusal."""



class IdentityClaimCoordinator:
    """Lock-held, compensating composition of existing DHCP and DNS membranes."""

    LOCK_PATH = Path("/var/lib/caduceus/network-identity-claim.lock")
    JOURNAL_DIR = Path("/var/lib/caduceus/journals/network-identity")
    RESOLVER_GATEWAY_ADDRESS = "192.168.123.1"

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

    def _resolve_ip(self, explicit: str | None, fresh: dict[str, Any]) -> str:
        boundaries = fresh["boundary"]
        if not boundaries:
            raise IdentityError("current-kea-boundary-unavailable")
        if explicit is not None:
            try:
                ipaddress.IPv4Address(explicit)
            except ipaddress.AddressValueError as exc:
                raise IdentityError("claim-ip-malformed") from exc
            if not self._in_boundaries(explicit, boundaries):
                raise IdentityError("claim-ip-outside-current-kea-boundary")
            if explicit in self.dhcp.taken_addresses(self.dns):
                raise IdentityError("claim-ip-taken")
            return explicit
        return self.dhcp._get_next_available_reserved_ip(self.dns)

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

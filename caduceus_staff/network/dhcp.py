from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import time
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Sequence


class DhcpError(RuntimeError):
    """A bounded, operator-readable DHCP actuator failure."""


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class DhcpManager:
    """Read and mutate Kea DHCP state through the preserved atomic updater."""

    CONFIG_PATH = Path("/etc/kea/kea-dhcp4.conf")
    LEASE_DB_PATH = Path("/var/lib/kea/kea-leases4.csv")
    UPDATE_SCRIPT = Path("/usr/local/sbin/update-kea-dhcp.sh")
    SERVICE = "kea-dhcp4-server"

    def __init__(
        self,
        config_path: str | Path | None = None,
        lease_db_path: str | Path | None = None,
        update_script: str | Path | None = None,
        *,
        command_runner: CommandRunner | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.config_path = Path(config_path or os.environ.get("CADUCEUS_DHCP_CONFIG", self.CONFIG_PATH))
        self.lease_db_path = Path(lease_db_path or os.environ.get("CADUCEUS_DHCP_LEASES", self.LEASE_DB_PATH))
        self.update_script = Path(update_script or os.environ.get("CADUCEUS_DHCP_UPDATE_SCRIPT", self.UPDATE_SCRIPT))
        self._command_runner = command_runner or self._run
        self._now = now

    @staticmethod
    def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)

    def _command(self, command: Sequence[str], *, required: bool = True) -> subprocess.CompletedProcess[str]:
        try:
            result = self._command_runner(command)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DhcpError(f"command failed: {' '.join(command)}: {exc}") from exc
        if required and result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or f"exit {result.returncode}"
            raise DhcpError(f"command failed: {' '.join(command)}: {detail}")
        return result

    def get_service_status(self) -> dict[str, Any]:
        active_result = self._command(["systemctl", "is-active", self.SERVICE], required=False)
        details_result = self._command(["systemctl", "status", self.SERVICE, "--no-pager"], required=False)
        active = active_result.returncode == 0 and active_result.stdout.strip() == "active"
        return {
            "active": active,
            "status": "active" if active else "inactive",
            "details": (details_result.stdout + details_result.stderr).strip(),
        }

    def get_config(self) -> dict[str, Any]:
        try:
            raw = self.config_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise DhcpError(f"failed to read config {self.config_path}: {exc}") from exc
        start, end = raw.find("{"), raw.rfind("}")
        if start < 0 or end <= start:
            raise DhcpError("no JSON object found in DHCP config")
        try:
            value = json.loads(raw[start : end + 1])
        except json.JSONDecodeError as exc:
            raise DhcpError(f"invalid JSON in DHCP config: {exc}") from exc
        if not self._validate_config_structure(value):
            raise DhcpError("invalid DHCP configuration structure")
        return value

    @staticmethod
    def _validate_config_structure(config: Any) -> bool:
        return (
            isinstance(config, dict)
            and isinstance(config.get("Dhcp4"), dict)
            and isinstance(config["Dhcp4"].get("subnet4"), list)
        )

    def update_config(self, config: dict[str, Any]) -> dict[str, Any]:
        if not self._validate_config_structure(config):
            raise DhcpError("invalid DHCP configuration structure")
        if not self.update_script.is_file():
            raise DhcpError(f"atomic update script is missing: {self.update_script}")
        payload = json.dumps(config, indent=4) + "\n"
        temporary: str | None = None
        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as handle:
                handle.write(payload)
                temporary = handle.name
            self._command([str(self.update_script), temporary])
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)
        return self.get_config()

    def validate_config(self) -> bool:
        return self._command(["kea-dhcp4", "-t", str(self.config_path)], required=False).returncode == 0

    def _subnets(self, config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        value = (config or self.get_config())["Dhcp4"]["subnet4"]
        return [item for item in value if isinstance(item, dict)]

    def get_reservations(self) -> list[dict[str, Any]]:
        return [
            {
                "hw-address": str(item.get("hw-address", "")),
                "ip-address": str(item.get("ip-address", "")),
                "hostname": str(item.get("hostname", "")),
            }
            for subnet in self._subnets()
            for item in subnet.get("reservations", [])
            if isinstance(item, dict)
        ]

    @staticmethod
    def _validate_mac_address(mac: str) -> bool:
        return bool(re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", mac or ""))

    @staticmethod
    def _validate_ip_address(ip: str) -> bool:
        try:
            return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
        except ValueError:
            return False

    @staticmethod
    def _ip_to_int(ip: str) -> int | None:
        try:
            return int(ipaddress.IPv4Address(ip))
        except ValueError:
            return None

    def _get_pool_range(self) -> tuple[str | None, str | None]:
        subnets = self._subnets()
        pools = subnets[0].get("pools", []) if subnets else []
        pool = pools[0].get("pool", "") if pools and isinstance(pools[0], dict) else ""
        if " - " not in pool:
            return None, None
        start, end = (part.strip() for part in pool.split(" - ", 1))
        return (start, end) if self._validate_ip_address(start) and self._validate_ip_address(end) else (None, None)

    def _get_reserved_range(self) -> tuple[str, str]:
        subnets = self._subnets()
        if not subnets:
            return "192.168.123.2", "192.168.123.49"
        network = ipaddress.IPv4Network(str(subnets[0].get("subnet", "192.168.123.0/24")), strict=False)
        boundary = self.get_current_boundary()
        end = min(int(network.broadcast_address) - 1, int(network.network_address) + boundary + 1)
        return str(network.network_address + 2), str(ipaddress.IPv4Address(end))

    def _validate_ip_in_pool(self, ip: str) -> bool:
        value = self._ip_to_int(ip)
        start, end = self._get_pool_range()
        return value is not None and start is not None and end is not None and int(ipaddress.IPv4Address(start)) <= value <= int(ipaddress.IPv4Address(end))

    def _validate_ip_in_reserved_range(self, ip: str) -> bool:
        value = self._ip_to_int(ip)
        start, end = self._get_reserved_range()
        return value is not None and int(ipaddress.IPv4Address(start)) <= value <= int(ipaddress.IPv4Address(end))

    def _get_next_available_reserved_ip(self) -> str | None:
        start, end = self._get_reserved_range()
        used = {item["ip-address"] for item in self.get_reservations()}
        for value in range(int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end)) + 1):
            candidate = str(ipaddress.IPv4Address(value))
            if candidate not in used:
                return candidate
        return None

    def add_reservation(self, hw_address: str, ip_address: str | None = None, hostname: str | None = None) -> dict[str, Any]:
        if not self._validate_mac_address(hw_address):
            raise DhcpError(f"invalid MAC address: {hw_address}")
        config = self.get_config()
        existing = self.get_reservations()
        if any(item["hw-address"].lower() == hw_address.lower() for item in existing):
            raise DhcpError("reservation with this MAC address already exists")
        if ip_address is None or self._validate_ip_in_pool(ip_address):
            ip_address = self._get_next_available_reserved_ip()
        elif not self._validate_ip_address(ip_address) or not self._validate_ip_in_reserved_range(ip_address):
            start, end = self._get_reserved_range()
            raise DhcpError(f"IP address is outside the reserved range ({start} - {end})")
        if ip_address is None:
            raise DhcpError("no available IP address in reserved range")
        if any(item["ip-address"] == ip_address for item in existing):
            raise DhcpError("IP address is already assigned")
        subnets = self._subnets(config)
        if not subnets:
            raise DhcpError("no subnet4 configuration found")
        reservation: dict[str, Any] = {"hw-address": hw_address.lower().replace("-", ":"), "ip-address": ip_address}
        if hostname:
            reservation["hostname"] = hostname
        subnets[0].setdefault("reservations", []).append(reservation)
        self.update_config(config)
        return reservation

    def remove_reservation(self, identifier: str) -> bool:
        config = self.get_config()
        removed = False
        for subnet in self._subnets(config):
            before = subnet.get("reservations", [])
            after = [item for item in before if str(item.get("hw-address", "")).lower() != identifier.lower() and item.get("ip-address") != identifier]
            removed |= len(after) != len(before)
            subnet["reservations"] = after
        if removed:
            self.update_config(config)
        return removed

    def update_reservation_ip(self, identifier: str, new_ip: str) -> dict[str, Any]:
        if not self._validate_ip_in_reserved_range(new_ip):
            start, end = self._get_reserved_range()
            raise DhcpError(f"IP address is outside the reserved range ({start} - {end})")
        config = self.get_config()
        matches: dict[str, Any] | None = None
        for subnet in self._subnets(config):
            for item in subnet.get("reservations", []):
                is_target = str(item.get("hw-address", "")).lower() == identifier.lower() or item.get("ip-address") == identifier
                if not is_target and item.get("ip-address") == new_ip:
                    raise DhcpError("IP address is already assigned")
                if is_target:
                    matches = item
        if matches is None:
            raise DhcpError("reservation not found")
        matches["ip-address"] = new_ip
        self.update_config(config)
        return {"hw-address": matches.get("hw-address", ""), "ip-address": new_ip, "hostname": matches.get("hostname", "")}

    def get_leases(self) -> list[dict[str, Any]]:
        try:
            raw = self.lease_db_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise DhcpError(f"failed to read leases {self.lease_db_path}: {exc}") from exc
        latest: dict[str, dict[str, Any]] = {}
        for row in csv.DictReader(StringIO(raw)):
            try:
                expires, state = int(row.get("expire", "0")), int(row.get("state", "1"))
            except ValueError:
                continue
            mac = row.get("hwaddr", "").lower()
            if state == 0 and expires > int(self._now()) and mac and expires > latest.get(mac, {}).get("_expire", -1):
                latest[mac] = {"ip-address": row.get("address", ""), "hw-address": mac, "hostname": row.get("hostname", ""), "expire": str(expires), "state": str(state), "_expire": expires}
        return [{key: value for key, value in lease.items() if key != "_expire"} for lease in latest.values()]

    def get_current_boundary(self) -> int:
        start, _ = self._get_pool_range()
        if start is None:
            subnets = self._subnets()
            return 249 if subnets and not subnets[0].get("pools") else 48
        subnets = self._subnets()
        network = ipaddress.IPv4Network(str(subnets[0].get("subnet", "192.168.123.0/24")), strict=False)
        return max(0, min(249, int(ipaddress.IPv4Address(start)) - int(network.network_address) - 2))

    def get_statistics(self) -> dict[str, Any]:
        subnets = self._subnets()
        homeserver_ip = "192.168.123.1"
        if subnets:
            for option in subnets[0].get("option-data", []):
                if option.get("name") == "routers":
                    homeserver_ip = option.get("data", homeserver_ip)
        reservations, leases = self.get_reservations(), self.get_leases()
        reserved_macs = {item["hw-address"].lower() for item in reservations}
        active = [item for item in leases if item["hw-address"].lower() not in reserved_macs]
        start, end = self._get_pool_range()
        total = int(ipaddress.IPv4Address(end)) - int(ipaddress.IPv4Address(start)) + 1 if start and end else 0
        return {"homeserver_ip": homeserver_ip, "reservations_count": len(reservations), "reservations_total": self.get_current_boundary(), "leases_count": len(active), "leases_total": total}

    def update_pool_boundary(self, max_reservations: int) -> bool:
        if not 0 <= max_reservations <= 249:
            raise DhcpError("max reservations must be between 0 and 249")
        config = self.get_config()
        reservations, leases = self.get_reservations(), self.get_leases()
        if max_reservations < len(reservations):
            raise DhcpError(f"cannot set max reservations below current count ({len(reservations)})")
        if max_reservations > 249 - len([x for x in leases if x["hw-address"].lower() not in {r["hw-address"].lower() for r in reservations}]):
            raise DhcpError("new boundary cannot accommodate active leases")
        subnets = self._subnets(config)
        if not subnets:
            raise DhcpError("no subnet4 configuration found")
        network = ipaddress.IPv4Network(str(subnets[0].get("subnet", "192.168.123.0/24")), strict=False)
        end_reserved = int(network.network_address) + max_reservations + 1
        for item in reservations:
            if int(ipaddress.IPv4Address(item["ip-address"])) > end_reserved:
                raise DhcpError(f"existing reservation {item['ip-address']} is outside new reserved range")
        if max_reservations == 249:
            subnets[0]["pools"] = []
        else:
            start = network.network_address + max_reservations + 2
            end = network.broadcast_address - 5
            subnets[0]["pools"] = [{"pool": f"{start} - {end}"}]
        self.update_config(config)
        return True


def _receipt(action: str, result: Any) -> dict[str, Any]:
    return {"schema": "caduceus.staff.network.dhcp.v1", "action": action, "ok": True, "result": result, "firstMissingSignal": "none"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="caduceus-dhcp")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "config", "validate", "reservations", "leases", "statistics", "boundary"):
        commands.add_parser(name)
    add = commands.add_parser("add-reservation")
    add.add_argument("hw_address"); add.add_argument("--ip-address"); add.add_argument("--hostname")
    remove = commands.add_parser("remove-reservation"); remove.add_argument("identifier")
    update = commands.add_parser("update-reservation-ip"); update.add_argument("identifier"); update.add_argument("new_ip")
    pool = commands.add_parser("update-pool-boundary"); pool.add_argument("max_reservations", type=int)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manager = DhcpManager()
    methods: dict[str, Callable[[], Any]] = {
        "status": manager.get_service_status, "config": manager.get_config, "validate": manager.validate_config,
        "reservations": manager.get_reservations, "leases": manager.get_leases,
        "statistics": manager.get_statistics, "boundary": manager.get_current_boundary,
    }
    try:
        if args.command in methods:
            result = methods[args.command]()
        elif args.command == "add-reservation":
            result = manager.add_reservation(args.hw_address, args.ip_address, args.hostname)
        elif args.command == "remove-reservation":
            result = manager.remove_reservation(args.identifier)
        elif args.command == "update-reservation-ip":
            result = manager.update_reservation_ip(args.identifier, args.new_ip)
        else:
            result = manager.update_pool_boundary(args.max_reservations)
        print(json.dumps(_receipt(args.command, result), sort_keys=True))
        return 0
    except DhcpError as exc:
        print(json.dumps({"schema": "caduceus.staff.network.dhcp.v1", "action": args.command, "ok": False, "firstMissingSignal": str(exc)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

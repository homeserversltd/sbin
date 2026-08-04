from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import subprocess
import time
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Sequence

from caduceus_staff.receipts import emit_actuator


class DhcpError(RuntimeError):
    """A bounded, operator-readable Kea read failure."""


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]
MAC = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


def normalize_mac(value: str) -> str:
    mac = value.strip().lower().replace("-", ":")
    if not MAC.fullmatch(mac):
        raise DhcpError(f"invalid MAC address: {value}")
    return mac


class DhcpReader:
    CONFIG_PATH = Path("/etc/kea/kea-dhcp4.conf")
    LEASES_PATH = Path("/var/lib/kea/kea-leases4.csv")
    SERVICE = "kea-dhcp4-server"

    def __init__(self, config_path: str | Path | None = None, leases_path: str | Path | None = None, *, command_runner: CommandRunner | None = None, now: Callable[[], float] = time.time) -> None:
        self.config_path = Path(config_path or os.environ.get("CADUCEUS_DHCP_CONFIG", self.CONFIG_PATH))
        self.leases_path = Path(leases_path or os.environ.get("CADUCEUS_DHCP_LEASES", self.LEASES_PATH))
        self._command_runner = command_runner or self._run
        self._now = now

    @staticmethod
    def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)

    def _command(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            return self._command_runner(command)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DhcpError(f"command failed: {' '.join(command)}: {exc}") from exc

    def config(self) -> dict[str, Any]:
        try:
            raw = self.config_path.read_text(encoding="utf-8")
            value = json.loads(raw[raw.index("{") : raw.rindex("}") + 1])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise DhcpError(f"invalid Kea config {self.config_path}: {exc}") from exc
        if not isinstance(value.get("Dhcp4"), dict) or not isinstance(value["Dhcp4"].get("subnet4"), list):
            raise DhcpError("invalid DHCP configuration structure")
        return value

    def status(self) -> dict[str, Any]:
        active = self._command(["systemctl", "is-active", self.SERVICE])
        valid = self._command(["kea-dhcp4", "-t", str(self.config_path)])
        return {"service": {"name": self.SERVICE, "active": active.returncode == 0 and active.stdout.strip() == "active"}, "config_valid": valid.returncode == 0}

    def reservations(self) -> list[dict[str, str]]:
        values: list[dict[str, str]] = []
        for subnet in self.config()["Dhcp4"]["subnet4"]:
            if not isinstance(subnet, dict):
                continue
            for reservation in subnet.get("reservations", []):
                if not isinstance(reservation, dict):
                    continue
                try:
                    mac = normalize_mac(str(reservation.get("hw-address", "")))
                except DhcpError:
                    continue
                values.append({"mac": mac, "ip": str(reservation.get("ip-address", "")), "hostname": str(reservation.get("hostname", "")), "provenance": "declared"})
        return sorted(values, key=lambda item: (item["mac"], item["ip"]))

    def leases(self) -> list[dict[str, str]]:
        try:
            raw = self.leases_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise DhcpError(f"failed to read leases {self.leases_path}: {exc}") from exc
        latest: dict[str, dict[str, str | int]] = {}
        for row in csv.DictReader(StringIO(raw)):
            try:
                mac = normalize_mac(str(row.get("hwaddr", "")))
                expire = int(str(row.get("expire", "0")))
                state = int(str(row.get("state", "1")))
            except (DhcpError, ValueError):
                continue
            if state != 0 or expire <= int(self._now()):
                continue
            old = latest.get(mac)
            if old is None or expire > int(old["_expire"]):
                latest[mac] = {"mac": mac, "ip": str(row.get("address", "")), "hostname": str(row.get("hostname", "")), "last_activity": str(expire), "_expire": expire, "provenance": "observed"}
        return [{key: str(value) for key, value in lease.items() if key != "_expire"} for _, lease in sorted(latest.items())]

    def boundary(self) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        for subnet in self.config()["Dhcp4"]["subnet4"]:
            if not isinstance(subnet, dict):
                continue
            network = ipaddress.ip_network(str(subnet.get("subnet", "")), strict=False)
            pools = subnet.get("pools", [])
            pool_ranges: list[tuple[int, int]] = []
            for pool in pools if isinstance(pools, list) else []:
                text = str(pool.get("pool", "")) if isinstance(pool, dict) else ""
                if " - " in text:
                    start, end = (ipaddress.ip_address(part.strip()) for part in text.split(" - ", 1))
                    pool_ranges.append((int(start), int(end)))
            if not pool_ranges:
                continue
            low = int(network.network_address) + 1
            high = min(start for start, _ in pool_ranges) - 1
            if low <= high:
                result.append({"subnet": str(network), "start": str(ipaddress.ip_address(low)), "end": str(ipaddress.ip_address(high)), "discovery": "loaded-ke a-pool-boundary".replace(" ", "")})
        return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-dhcp")
    parser.add_argument("command", choices=("status", "leases", "reservations", "boundary"))
    args = parser.parse_args(argv)
    try:
        reader = DhcpReader()
        result = getattr(reader, args.command)()
        return emit_actuator("network.dhcp." + args.command, "caduceus.staff.network.dhcp.v1", args.command, result)
    except DhcpError as exc:
        return emit_actuator("network.dhcp." + args.command, "caduceus.staff.network.dhcp.v1", args.command, None, ok=False, first_missing_signal=str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

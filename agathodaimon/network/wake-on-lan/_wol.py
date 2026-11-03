"""Shared wake-on-LAN operations."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
from typing import Any

_MAC = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$|^[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}$")
_PING_RTT = re.compile(r"(?:time|rtt)=([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)


def _json(value: dict[str, Any]) -> int:
    print(json.dumps(value, separators=(",", ":")))
    return 0 if value.get("ok") is True else 1


def _ipv4(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"invalid {label}")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"invalid {label}") from exc
    if address.version != 4:
        raise ValueError(f"invalid {label}")
    return str(address)


def _mac(value: Any) -> tuple[str, bytes]:
    if not isinstance(value, str) or not _MAC.fullmatch(value):
        raise ValueError("invalid MAC")
    normalized = value.replace("-", ":").lower()
    return normalized, bytes.fromhex(normalized.replace(":", ""))


def send(mac_value: str, broadcast_value: str = "255.255.255.255") -> dict[str, Any]:
    mac, mac_bytes = _mac(mac_value)
    broadcast = _ipv4(broadcast_value, "broadcast")
    packet = b"\xff" * 6 + mac_bytes * 16
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, (broadcast, 9))
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "mac": mac, "broadcast": broadcast}


def probe(ip_value: str) -> dict[str, Any]:
    ip = _ipv4(ip_value, "IP")
    try:
        result = subprocess.run(
            ["/usr/bin/ping", "-c", "1", "-W", "1", ip],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    match = _PING_RTT.search(result.stdout)
    awake = result.returncode == 0 and match is not None
    rtt_ms = float(match.group(1)) if awake and match else None
    return {"ok": True, "ip": ip, "awake": awake, "rtt_ms": rtt_ms}

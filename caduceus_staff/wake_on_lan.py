"""Dependency-free Caduceus wake-on-LAN staff door."""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import subprocess
import sys
from typing import Any, Sequence

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


def _usage_error(message: str) -> int:
    return _json({"ok": False, "error": message})


def _dispatch(command: Any, values: dict[str, Any]) -> dict[str, Any]:
    if command == "send":
        if "mac" not in values or set(values) - {"mac", "broadcast"}:
            raise ValueError("send requires mac and accepts only broadcast")
        return send(values["mac"], values.get("broadcast", "255.255.255.255"))
    if command == "probe":
        if set(values) != {"ip"}:
            raise ValueError("probe requires ip")
        return probe(values["ip"])
    raise ValueError("expected send or probe")


def _envelope() -> tuple[Any, dict[str, Any]]:
    try:
        envelope = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"invalid JSON envelope: {exc}") from exc
    if not isinstance(envelope, dict) or envelope.get("actuator") != "wake-on-lan":
        raise ValueError("envelope actuator must be \"wake-on-lan\"")
    metadata = envelope.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("envelope metadata must be an object")
    return metadata.get("action"), {key: value for key, value in metadata.items() if key != "action"}


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        try:
            command, values = _envelope()
            return _json(_dispatch(command, values))
        except ValueError as exc:
            return _usage_error(str(exc))
    if args[0] not in {"send", "probe"}:
        return _usage_error("expected send or probe")
    command = args.pop(0)
    values: dict[str, str] = {}
    while args:
        flag = args.pop(0)
        if flag not in {"--mac", "--broadcast", "--ip"} or not args or args[0].startswith("--"):
            return _usage_error("invalid arguments")
        values[flag[2:]] = args.pop(0)
    try:
        return _json(_dispatch(command, values))
    except ValueError as exc:
        return _usage_error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

"""Child-device registry and gateway-policy renderer for Caduceus staff.

The registry is deliberately plain JSON.  `apply` is a render receipt: gateway
installation is an explicit, operator-witnessed follow-up rather than an
implicit side effect of a Crown request.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

SCHEMA = "caduceus.child-device.v1"
DEFAULT_STATE = Path("/var/lib/caduceus/child-devices.json")
DEFAULT_KEA_LEASES = Path("/var/lib/kea/kea-leases4.csv")
DEFAULT_KEA_CONFIG = Path("/etc/kea/kea-dhcp4.conf")
MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
HOST = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class Refused(ValueError):
    pass


def receipt(action: str, ok: bool = True, **extra: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": ok, "action": action,
            "message": extra.pop("message", "Child-device request completed." if ok else "Child-device request refused."),
            "firstMissingSignal": "none" if ok else extra.pop("error", "child-device-refused"), **extra}


def mac(value: str) -> str:
    normalized = value.lower().replace("-", ":")
    if re.fullmatch(r"[0-9a-f]{12}", normalized):
        normalized = ":".join(normalized[index:index + 2] for index in range(0, 12, 2))
    if not MAC.fullmatch(normalized) or normalized in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"}:
        raise Refused("child-device-mac-invalid")
    return normalized


def hosts(value: str) -> list[str]:
    result: set[str] = set()
    for raw in value.split(","):
        host = raw.strip().lower().rstrip(".")
        if not HOST.fullmatch(host) or host.endswith(".home.arpa"):
            raise Refused("child-device-host-invalid")
        result.add(host)
    if not result:
        raise Refused("child-device-whitelist-empty")
    return sorted(result)


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": SCHEMA, "devices": {}}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refused("child-device-registry-unreadable") from exc
    devices = value.get("devices") if isinstance(value, dict) else None
    if value.get("schema") != SCHEMA or not isinstance(devices, dict):
        raise Refused("child-device-registry-invalid")
    normalized: dict[str, Any] = {}
    for raw_mac, device in devices.items():
        device_mac = mac(raw_mac)
        if not isinstance(device, dict) or not isinstance(device.get("name"), str) or not isinstance(device.get("whitelist"), list):
            raise Refused("child-device-registry-invalid")
        name = device["name"].strip()
        if not name or len(name) > 80 or any(ord(char) < 32 for char in name):
            raise Refused("child-device-registry-invalid")
        listed = hosts(",".join(device["whitelist"])) if device["whitelist"] else []
        normalized[device_mac] = {"name": name, "whitelist": listed}
    return {"schema": SCHEMA, "devices": normalized}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
    payload = json.dumps(state, indent=2, sort_keys=True) + "\n"
    fd, temporary = tempfile.mkstemp(prefix=".child-devices-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o640)
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _csv_observed(path: Path) -> Iterable[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                raw_mac = row.get("hwaddr") or row.get("hw-address") or row.get("mac")
                if not raw_mac:
                    continue
                try:
                    item = {"mac": mac(raw_mac)}
                except Refused:
                    continue
                if row.get("address"):
                    item["ip"] = row["address"]
                if row.get("hostname"):
                    item["hostname"] = row["hostname"]
                yield item
    except OSError:
        return


def _neighbors() -> Iterable[dict[str, str]]:
    try:
        process = subprocess.run(["ip", "-j", "neigh", "show"], text=True, capture_output=True, timeout=5, check=False)
        values = json.loads(process.stdout) if process.returncode == 0 else []
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return
    if not isinstance(values, list):
        return
    for value in values:
        if not isinstance(value, dict) or not isinstance(value.get("lladdr"), str) or not isinstance(value.get("dst"), str):
            continue
        try:
            yield {"mac": mac(value["lladdr"]), "ip": str(ipaddress.ip_address(value["dst"]))}
        except (Refused, ValueError):
            continue


def observed(leases: Path) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in list(_csv_observed(leases)) + list(_neighbors()):
        prior = merged.setdefault(item["mac"], {"mac": item["mac"], "ip": None, "hostname": None, "sources": []})
        for field in ("ip", "hostname"):
            if item.get(field):
                prior[field] = item[field]
        prior["sources"].append("kea-lease" if item.get("hostname") else "neighbor")
    return [{**value, "sources": sorted(set(value["sources"]))} for _, value in sorted(merged.items())]


def _kea_networks(path: Path) -> list[str]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
    dhcp = config.get("Dhcp4", config) if isinstance(config, dict) else {}
    subnets = dhcp.get("subnet4", []) if isinstance(dhcp, dict) else []
    networks: list[str] = []
    for subnet in subnets if isinstance(subnets, list) else []:
        try:
            networks.append(str(ipaddress.ip_network(subnet["subnet"], strict=False)))
        except (KeyError, TypeError, ValueError):
            continue
    return sorted(set(networks)) or ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]


def render(state: dict[str, Any], kea_config: Path) -> dict[str, str]:
    devices = state["devices"]
    networks = _kea_networks(kea_config)
    nft = ["# Generated by caduceus child-device apply; do not edit.", "table inet caduceus_child_device {", "  chain forward {", "    type filter hook forward priority -5; policy accept;"]
    unbound = ["# Generated by caduceus child-device apply; install through the gateway actuator."]
    for device_mac, device in sorted(devices.items()):
        for network in networks:
            nft.append(f"    ether saddr {device_mac} ip daddr {network} accept")
        nft.append(f"    ether saddr {device_mac} udp dport 53 accept")
        nft.append(f"    ether saddr {device_mac} tcp dport 53 accept")
        nft.append(f"    ether saddr {device_mac} drop")
        view = "caduceus-child-" + device_mac.replace(":", "")
        unbound.extend(["view:", f'  name: "{view}"', '  local-zone: "." refuse'])
        unbound.extend(f'  local-zone: "{host}." transparent' for host in device["whitelist"])
    nft.extend(["  }", "}", ""])
    return {"nftables": "\n".join(nft), "unbound": "\n".join(unbound) + "\n"}


def _envelope() -> tuple[str, dict[str, Any]]:
    try:
        envelope = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        raise Refused("child-device-envelope-invalid") from exc
    if not isinstance(envelope, dict) or envelope.get("actuator") != "child-device":
        raise Refused("child-device-envelope-actuator-invalid")
    metadata = envelope.get("metadata")
    if not isinstance(metadata, dict) or not isinstance(metadata.get("action"), str):
        raise Refused("child-device-envelope-metadata-invalid")
    return metadata["action"], {key: value for key, value in metadata.items() if key != "action"}


def _hosts_value(values: dict[str, Any]) -> str:
    if "hosts" in values and "hostnames" in values:
        raise Refused("child-device-whitelist-hosts-invalid")
    value = values.get("hosts", values.get("hostnames"))
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return ",".join(value)
    if isinstance(value, str):
        return value
    raise Refused("child-device-whitelist-hosts-invalid")


def _dispatch(action: str, values: dict[str, Any], state_path: Path, kea_leases: Path, kea_config: Path) -> dict[str, Any]:
    if action == "observed":
        if values: raise Refused("child-device-request-invalid")
        devices = observed(kea_leases)
        return receipt("observed", devices=devices, count=len(devices), message="Observed MAC addresses from Kea leases and the neighbor table.")
    if action == "list":
        if values: raise Refused("child-device-request-invalid")
        state = load_state(state_path)
        return receipt("list", devices=[{"mac": item_mac, **item} for item_mac, item in sorted(state["devices"].items())], registry=str(state_path), message="Registered child devices and their website whitelists.")
    if action == "apply":
        if values: raise Refused("child-device-request-invalid")
        generated = render(load_state(state_path), kea_config)
        return receipt("apply", registry=str(state_path), mode="render-only", enforcement="registered MACs: LAN plus DNS; all other forwarded destinations blocked; website resolution limited by Unbound views", generated=generated, message="Rendered gateway nftables and Unbound policy. No live gateway change was made.")
    if action not in {"register", "unregister", "whitelist get", "whitelist set"}: raise Refused("child-device-action-invalid")
    value = values.get("mac")
    if not isinstance(value, str): raise Refused("child-device-mac-invalid")
    item_mac = mac(value)
    state = load_state(state_path); devices = state["devices"]
    if action == "register":
        if set(values) - {"mac", "name"}: raise Refused("child-device-request-invalid")
        name = values.get("name")
        if name is not None and not isinstance(name, str): raise Refused("child-device-name-invalid")
        label = (name or f"Child device {item_mac}").strip()
        if not label or len(label) > 80 or any(ord(char) < 32 for char in label): raise Refused("child-device-name-invalid")
        existing = devices.get(item_mac, {})
        devices[item_mac] = {"name": label, "whitelist": existing.get("whitelist", [])}
        save_state(state_path, state)
        return receipt("register", device={"mac": item_mac, **devices[item_mac]}, registry=str(state_path), message=f"Registered {item_mac} as a child device.")
    if action == "unregister":
        if set(values) != {"mac"}: raise Refused("child-device-request-invalid")
        if item_mac not in devices: raise Refused("child-device-not-registered")
        removed = devices.pop(item_mac); save_state(state_path, state)
        return receipt("unregister", device={"mac": item_mac, **removed}, registry=str(state_path), message=f"Removed {item_mac}; it is no longer subject to child-device enforcement.")
    if action == "whitelist get":
        if set(values) != {"mac"}: raise Refused("child-device-request-invalid")
        if item_mac not in devices: raise Refused("child-device-not-registered")
        return receipt("whitelist get", device={"mac": item_mac, **devices[item_mac]}, message=f"Website whitelist for {item_mac}.")
    if set(values) - {"mac", "hosts", "hostnames"}: raise Refused("child-device-request-invalid")
    if item_mac not in devices: raise Refused("child-device-not-registered")
    devices[item_mac]["whitelist"] = hosts(_hosts_value(values)); save_state(state_path, state)
    return receipt("whitelist set", device={"mac": item_mac, **devices[item_mac]}, registry=str(state_path), message=f"Updated website whitelist for {item_mac}.")


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if not raw_argv:
        try:
            action, values = _envelope()
            output = _dispatch(action, values, Path(os.environ.get("CADUCEUS_CHILD_DEVICE_STATE", DEFAULT_STATE)), Path(os.environ.get("CADUCEUS_KEA_LEASES", DEFAULT_KEA_LEASES)), Path(os.environ.get("CADUCEUS_KEA_CONFIG", DEFAULT_KEA_CONFIG)))
        except Refused as error:
            output = receipt("invalid", False, error=str(error))
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if output["ok"] else 1
    parser = argparse.ArgumentParser(prog="caduceus child-device", description="Caduceus child-device registry and policy renderer")
    parser.add_argument("--state", type=Path, default=Path(os.environ.get("CADUCEUS_CHILD_DEVICE_STATE", DEFAULT_STATE)))
    parser.add_argument("--kea-leases", type=Path, default=Path(os.environ.get("CADUCEUS_KEA_LEASES", DEFAULT_KEA_LEASES)))
    parser.add_argument("--kea-config", type=Path, default=Path(os.environ.get("CADUCEUS_KEA_CONFIG", DEFAULT_KEA_CONFIG)))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("observed"); commands.add_parser("list")
    register = commands.add_parser("register"); register.add_argument("mac"); register.add_argument("--name", default=None)
    unregister = commands.add_parser("unregister"); unregister.add_argument("mac")
    whitelist = commands.add_parser("whitelist"); whitelist_sub = whitelist.add_subparsers(dest="whitelist_command", required=True)
    whitelist_get = whitelist_sub.add_parser("get"); whitelist_get.add_argument("mac")
    whitelist_set = whitelist_sub.add_parser("set"); whitelist_set.add_argument("mac"); whitelist_set.add_argument("hosts")
    commands.add_parser("apply")
    args = parser.parse_args(raw_argv)
    try:
        action = args.command if args.command != "whitelist" else f"whitelist {args.whitelist_command}"
        values: dict[str, Any] = {}
        if hasattr(args, "mac"): values["mac"] = args.mac
        if args.command == "register" and args.name is not None: values["name"] = args.name
        if action == "whitelist set": values["hosts"] = args.hosts
        output = _dispatch(action, values, args.state, args.kea_leases, args.kea_config)
    except Refused as error:
        output = receipt(getattr(args, "command", "invalid"), False, error=str(error))
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

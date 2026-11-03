"""Child-device registry and gateway-policy renderer for Caduceus staff.

The registry is deliberately plain JSON.  `apply` is a render receipt: gateway
installation is an explicit, operator-witnessed follow-up rather than an
implicit side effect of a Crown request.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterable, Sequence

from agathodaimon.network.dhcp.index import DhcpError, DhcpManager

from importlib import import_module

_registry = import_module("agathodaimon.network.child-device._registry")
SCHEMA = _registry.SCHEMA
DEFAULT_STATE = _registry.DEFAULT_STATE
DEFAULT_KEA_CONFIG = _registry.DEFAULT_KEA_CONFIG
MAC = _registry.MAC
HOST = _registry.HOST
Refused = _registry.Refused
receipt = _registry.receipt
mac = _registry.mac
hosts = _registry.hosts
load_state = _registry.load_state
save_state = _registry.save_state
_neighbors = _registry._neighbors
observed = _registry.observed
_kea_networks = _registry._kea_networks
render = _registry.render
_hosts_value = _registry._hosts_value
_dispatch = _registry._dispatch


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


def main(argv: Sequence[str] | None = None) -> int:
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if not raw_argv:
        try:
            action, values = _envelope()
            output = _dispatch(action, values, Path(os.environ.get("CADUCEUS_CHILD_DEVICE_STATE", DEFAULT_STATE)), Path(os.environ.get("CADUCEUS_KEA_CONFIG", DEFAULT_KEA_CONFIG)))
        except Refused as error:
            output = receipt("invalid", False, error=str(error))
        print(json.dumps(output, indent=2, sort_keys=True))
        return 0 if output["ok"] else 1
    parser = argparse.ArgumentParser(prog="caduceus child-device", description="Caduceus child-device registry and policy renderer")
    parser.add_argument("--state", type=Path, default=Path(os.environ.get("CADUCEUS_CHILD_DEVICE_STATE", DEFAULT_STATE)))
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
        output = _dispatch(action, values, args.state, args.kea_config)
    except Refused as error:
        output = receipt(getattr(args, "command", "invalid"), False, error=str(error))
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

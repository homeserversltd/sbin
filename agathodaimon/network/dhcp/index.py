from __future__ import annotations

import argparse
import json
from typing import Any, Callable, Sequence

from agathodaimon.network.dhcp._manager import DhcpError, DhcpManager, normalize_mac


def _receipt(action: str, result: Any) -> dict[str, Any]:
    read_actions = {"status", "statistics", "health", "boundary"}
    receipt = {"schema": "caduceus.staff.network.dhcp.v1", "actuator": f"network.dhcp.{action}" if action in read_actions else action, "action": action, "ok": True, "result": result, "firstMissingSignal": "none"}
    if action in read_actions:
        receipt["mutationPerformed"] = False
    return receipt


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agathodaimon-dhcp")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("status", "config", "validate", "statistics", "health"):
        commands.add_parser(name)
    boundary = commands.add_parser("boundary")
    boundary.add_argument("boundary_action", nargs="?", choices=("show",), default="show")
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
        "status": manager.status, "config": manager.get_config, "validate": manager.validate_config,
        "statistics": manager.get_statistics, "health": manager.health, "boundary": manager.boundary,
    }
    try:
        active_leases_count = None
        if args.command in methods:
            result = methods[args.command]()
            active_leases_count = len(manager.get_leases()) if args.command == "boundary" else None
        elif args.command == "add-reservation":
            result = manager.add_reservation(args.hw_address, args.ip_address, args.hostname)
        elif args.command == "remove-reservation":
            result = manager.remove_reservation(args.identifier)
        elif args.command == "update-reservation-ip":
            result = manager.update_reservation_ip(args.identifier, args.new_ip)
        else:
            result = manager.update_pool_boundary(args.max_reservations)
        response = _receipt(args.command, result)
        if args.command == "boundary":
            response["active_leases_count"] = active_leases_count
        print(json.dumps(response, sort_keys=True))
        return 0
    except DhcpError as exc:
        print(json.dumps({"schema": "caduceus.staff.network.dhcp.v1", "actuator": f"network.dhcp.{args.command}", "action": args.command, "ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

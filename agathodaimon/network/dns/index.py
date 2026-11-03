"""DNS staff command dispatch."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Sequence

from agathodaimon.network.dns._manager import CommandRunner, DnsError, DnsManager, create_alias
from agathodaimon.network.dns._resolver import ResolverControl, resolver_control


def _failure(action: str, reason: str) -> dict[str, Any]:
    return {
        "schema": "caduceus.network.dns.v1",
        "action": action,
        "ok": False,
        "mutationPerformed": False,
        "firstMissingSignal": reason,
    }



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agathodaimon-network-dns")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("read")
    resolver = commands.add_parser("resolver")
    resolver.add_argument("action", choices=("status", "adblock", "blocklist-update", "upstream"))
    resolver.add_argument("--metadata-json")
    device = commands.add_parser("device-name")
    device.add_argument("action", choices=("create", "remove"))
    device.add_argument("--hostname", required=True)
    device.add_argument("--ip", required=True)
    alias = commands.add_parser("alias")
    alias.add_argument("action", choices=("create", "remove"))
    alias.add_argument("--label", required=True)
    alias.add_argument("--hostname", required=True)
    intent = commands.add_parser("intent")
    intent.add_argument("method")
    intent.add_argument("target")
    intent.add_argument("--metadata-json", required=True)
    return parser



def staff_main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manager = DnsManager()
    try:
        if args.command == "status":
            receipt = manager.read_status()
        elif args.command == "read":
            receipt = {"schema": "caduceus.network.dns.v1", "actuator": "network.dns.read", "action": "read", "ok": True, "result": manager.read(), "mutationPerformed": False, "firstMissingSignal": "none"}
        elif args.command == "resolver":
            metadata = None
            if args.metadata_json is not None:
                try:
                    metadata = json.loads(args.metadata_json)
                except json.JSONDecodeError as exc:
                    raise DnsError("resolver-metadata-invalid") from exc
            receipt = resolver_control(args.action, metadata)
        elif args.command == "device-name":
            receipt = manager.create_device_name(args.hostname, args.ip) if args.action == "create" else manager.remove_device_name(args.hostname, args.ip)
            receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.device_name.{args.action}", "ok": True, "firstMissingSignal": "none"}
        elif args.command == "alias":
            receipt = manager.create_alias(args.label, args.hostname) if args.action == "create" else manager.remove_alias(args.label, args.hostname)
            receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.alias.{args.action}", "ok": True, "firstMissingSignal": "none"}
        else:
            if args.method != "POST" or args.target != DnsManager.INTENT_TARGET:
                raise DnsError("dns-intent-not-admitted")
            try:
                metadata = json.loads(args.metadata_json)
            except json.JSONDecodeError as exc:
                raise DnsError("dns-metadata-invalid") from exc
            receipt = manager.apply(metadata)
    except DnsError as exc:
        receipt = _failure(args.command, str(exc))
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in {"status", "read", "resolver", "device-name", "alias", "intent"}:
        return staff_main(arguments)
    print(json.dumps(_failure(arguments[0] if arguments else "", "dns-verb-unknown"), sort_keys=True))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
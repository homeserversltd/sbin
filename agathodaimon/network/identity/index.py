from __future__ import annotations

import argparse
from typing import Sequence

from agathodaimon.network.dhcp.index import DhcpError, DhcpManager, normalize_mac
from agathodaimon.network.dns.index import DnsError, DnsManager
from agathodaimon.lib.receipts import emit
from agathodaimon.network.identity._claim import IdentityClaimCoordinator, IdentityError
from agathodaimon.network.identity._roster import _device_projection, device_list, service_names


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-network-identity")
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
            result, service_names = _device_projection()
            return emit({"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.device_list", "action": "device_list", "result": result, "service_names": service_names, "mutationPerformed": False, "firstMissingSignal": "none"})
        receipt = IdentityClaimCoordinator().claim(args.mac, args.hostname, ip=args.ip, auto_ip=args.auto_ip)
        return emit(receipt)
    except (DhcpError, DnsError, IdentityError) as exc:
        return emit({"schema": "caduceus.staff.network.identity.v1", "actuator": "network.identity.claim", "state": "blocked", "ok": False, "mutationPerformed": False, "first_failing_boundary": str(exc)})


if __name__ == "__main__":
    raise SystemExit(main())

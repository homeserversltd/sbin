from __future__ import annotations

import argparse
from typing import Sequence

from .actuators import ACTUATORS, get_actuator, list_actuators
from .receipts import emit
from .runner import run, status


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="caduceus-staff", description="Caduceus staff Python actuators for HOMESERVER sbin")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List additive staff actuators")

    status_p = sub.add_parser("status", help="Show actuator status receipt")
    status_p.add_argument("actuator", choices=sorted(ACTUATORS))

    run_p = sub.add_parser("run", help="Plan or apply an actuator")
    run_p.add_argument("actuator", choices=sorted(ACTUATORS))
    run_p.add_argument("--apply", action="store_true", help="Mutate; default is dry-run plan")
    run_p.add_argument("--legacy-bridge", action="store_true", help="With --apply, execute the preserved legacy script")
    run_p.add_argument("args", nargs=argparse.REMAINDER, help="Arguments forwarded after --")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "list":
        return emit({
            "schema": "caduceus.staff.library.list.v1",
            "actuators": [a.__dict__ | {"legacyPath": str(a.legacy_path)} for a in list_actuators()],
            "count": len(ACTUATORS),
            "ok": True,
            "firstMissingSignal": "none",
        })
    actuator = get_actuator(args.actuator)
    if args.command == "status":
        return status(actuator)
    if args.command == "run":
        forwarded = list(args.args)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        return run(actuator, forwarded, apply=args.apply, legacy_bridge=args.legacy_bridge)
    raise SystemExit("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())

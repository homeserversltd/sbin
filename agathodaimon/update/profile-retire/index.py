"""Retire the obsolete installed Rebis Harmonia profile."""
from __future__ import annotations
import argparse, json, os, sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

def root()->Path: return Path(os.environ.get("CADUCEUS_ROOT","/"))
def retire(plan:bool)->dict:
    profiles=root()/"etc/harmonia/profiles"; rebis=profiles/"rebis"; target=None
    if rebis.is_dir(): target=profiles/f"rebis.retired.{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}"
    if target and not plan: rebis.rename(target)
    names=sorted(p.name for p in profiles.iterdir() if p.is_dir()) if profiles.exists() else []
    return {"ok":plan or "rebis" not in names,"changed":bool(target),"planned":plan,"profiles":names,"retiredPath":str(target) if target else None,"firstMissingSignal":"none"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-rebis-profile-retire", exit_on_error=False)
    parser.add_argument("--plan", action="store_true")
    try:
        args, unknown = parser.parse_known_args(argv)
    except argparse.ArgumentError:
        args, unknown = None, []
    if args is None or unknown:
        parser.print_usage(sys.stderr)
        print(json.dumps({"ok": False, "firstMissingSignal": "update-profile-retire-arguments-invalid"}))
        return 2
    value = retire(args.plan)
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__=='__main__': raise SystemExit(main())

"""Harmonia/systemd-suitable private Caduceus staff socket launcher."""
from __future__ import annotations

import argparse

from .attendance import AttendanceStaff, KeymanAdapter, StaffSocketDaemon, redacted_journal_sink


def production_staff(keyman_module: str) -> AttendanceStaff:
    return AttendanceStaff(KeymanAdapter(keyman_module), audit_sink=redacted_journal_sink)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-staff-daemon")
    parser.add_argument("--socket", default="/run/caduceus/caduceus-staff.sock")
    parser.add_argument("--keyman-module", default="/opt/keyman/runtime/lib/keyman_caduceus_access.py")
    args = parser.parse_args(argv)
    StaffSocketDaemon(production_staff(args.keyman_module), args.socket).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

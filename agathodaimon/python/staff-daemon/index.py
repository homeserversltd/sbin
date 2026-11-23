"""Harmonia/systemd-suitable private Caduceus staff socket launcher."""
from __future__ import annotations

import argparse
import json

from agathodaimon.lib.attendance.index import AttendanceStaff, StaffSocketDaemon, redacted_journal_sink


def production_staff() -> AttendanceStaff:
    return AttendanceStaff(audit_sink=redacted_journal_sink)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-staff-daemon")
    parser.add_argument("--socket", default="/run/caduceus/agathodaimon-staff.sock")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code != 2:
            raise
        print(json.dumps({
            "ok": False,
            "firstMissingSignal": "agathodaimon-staff-daemon-arguments-invalid",
        }))
        return 2
    StaffSocketDaemon(production_staff(), args.socket).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Privileged root door for Harmonia's GTK update modal."""
from __future__ import annotations

import os
import sys
from typing import Sequence

TARGET = "/usr/local/sbin/agathodaimon/cli.py"
TARGET_ARGS = ("gui", "update-modal")
SESSION_ENVIRONMENT = (
    "WAYLAND_DISPLAY",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
    "XAUTHORITY",
    "DBUS_SESSION_BUS_ADDRESS",
)


def main(argv: Sequence[str] | None = None) -> int:
    if os.geteuid() != 0:
        print("agathodaimon-staff-root-required", file=sys.stderr)
        return 77

    environment = os.environ.copy()
    for name in SESSION_ENVIRONMENT:
        value = os.environ.get(name)
        if value is not None:
            environment[name] = value
    os.execvpe(TARGET, [TARGET, *TARGET_ARGS, *(argv if argv is not None else sys.argv[1:])], environment)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

"""Run the configured Sway screen-off timer in the owner session."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def read_seconds(home: Path) -> int:
    path = home / ".config/sway/screen-idle.json"
    try:
        with path.open(encoding="utf-8") as source:
            config = json.load(source)
    except FileNotFoundError:
        return 0
    except (OSError, ValueError) as error:
        raise ValueError("screen-idle-config-unreadable") from error
    value = config.get("screen_off_seconds") if isinstance(config, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 86400:
        raise ValueError("invalid:screen_off_seconds")
    return value


def main() -> int:
    try:
        seconds = read_seconds(Path.home())
        if seconds == 0:
            return 0
        argv = ["swayidle", "-w", "timeout", str(seconds), 'swaymsg "output * power off"', "resume", 'swaymsg "output * power on"']
        if os.environ.get("CADUCEUS_SCREEN_IDLE_DRY_RUN") == "1":
            print(json.dumps({"argv": argv}))
            return 0
        os.execvp(argv[0], argv)
    except (ValueError, OSError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

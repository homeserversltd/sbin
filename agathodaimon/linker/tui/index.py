"""Open the staff-owned Linker terminal browser; no HTTP crossing."""
from __future__ import annotations

import argparse
import json

from agathodaimon.linker.tui_browser import LinkerTUI


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agathodaimon linker tui")
    parser.add_argument("start_dir", nargs="?")
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as exc:
        if exc.code != 2:
            raise
        print(json.dumps({
            "ok": False,
            "firstMissingSignal": "agathodaimon-linker-tui-arguments-invalid",
        }))
        return 2
    LinkerTUI(start_dir=arguments.start_dir).run()
    return 0

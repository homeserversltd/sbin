"""Open the staff-owned Linker terminal browser; no HTTP crossing."""
from __future__ import annotations

import argparse

from agathodaimon.linker.tui_browser import LinkerTUI


def main(argv=None):
    parser = argparse.ArgumentParser(prog="agathodaimon linker tui")
    parser.add_argument("start_dir", nargs="?")
    arguments = parser.parse_args(argv)
    LinkerTUI(start_dir=arguments.start_dir).run()
    return 0

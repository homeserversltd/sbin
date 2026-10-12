"""Scan one NAS directory through retained link_index.scan_hardlinks."""
from agathodaimon.linker._common import main_for


def main(argv=None):
    return main_for("hardlink-scan", argv)

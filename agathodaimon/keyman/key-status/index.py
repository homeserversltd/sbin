"""Read Keyman crown key status without a device selector."""
from agathodaimon.keyman._common import main_for


def main(argv=None):
    return main_for("key-status", argv)

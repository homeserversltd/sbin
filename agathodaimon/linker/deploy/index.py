"""Deploy NAS hardlinks through retained Linker core.create_hardlink."""
from agathodaimon.linker._common import main_for


def main(argv=None):
    return main_for("deploy", argv)

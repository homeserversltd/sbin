"""Create a directory through retained Linker core.create_directory."""
from agathodaimon.linker._common import main_for


def main(argv=None):
    return main_for("mkdir", argv)

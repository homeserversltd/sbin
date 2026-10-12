"""Change the Keyman administrator password through the Rust crown."""
from agathodaimon.keyman._common import main_for


def main(argv=None):
    return main_for("admin-password", argv)

"""Update a Keyman device key through the Rust crown."""
from agathodaimon.keyman._common import main_for


def main(argv=None):
    return main_for("update-key", argv)

"""Read Woodpecker agent posture without exposing the token."""
from agathodaimon.woodpecker._common import main_for


def main(arguments=None):
    return main_for("agent", arguments)

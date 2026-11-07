"""Set the Woodpecker agent token from stdin."""
from agathodaimon.woodpecker._common import main_for


def main(arguments=None):
    return main_for("agent-token", arguments)

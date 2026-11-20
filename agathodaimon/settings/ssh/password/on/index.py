"""Allow SSH password authentication without changing SSH service state."""
from agathodaimon.settings.ssh.password._change import main as change


def main(argv=None):
    return change('yes')

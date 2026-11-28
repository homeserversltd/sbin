"""Firewall way-set stop."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/firewall/way/set", argv)

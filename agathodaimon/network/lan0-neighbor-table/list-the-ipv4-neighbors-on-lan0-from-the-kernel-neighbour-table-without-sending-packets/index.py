"""Read the IPv4 neighbor table on lan0. Fields: none."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/neighbor/read", argv)

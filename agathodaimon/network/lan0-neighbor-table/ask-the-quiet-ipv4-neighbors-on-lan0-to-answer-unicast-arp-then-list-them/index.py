"""Ask quiet lan0 IPv4 neighbors once by unicast ARP (CAP_NET_RAW), then read. Fields: none."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/neighbor/probe", argv)

"""Ask quiet lan0 IPv4 neighbors once by unicast ARP (CAP_NET_RAW), then read. Fields: none."""

from agathodaimon.network.neighbor import _table


def main(argv=None):
    return _table.answer(_table.probe)

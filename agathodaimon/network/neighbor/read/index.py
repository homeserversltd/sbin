"""Read the IPv4 neighbor table on lan0. Fields: none."""

from agathodaimon.network.neighbor import _table


def main(argv=None):
    return _table.answer(_table.read)

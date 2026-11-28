"""DHCP boundary show. Fields: none."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dhcp/boundary/show", argv)

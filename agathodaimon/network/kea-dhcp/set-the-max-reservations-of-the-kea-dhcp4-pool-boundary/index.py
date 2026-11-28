"""DHCP update-pool-boundary. Fields: max_reservations."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dhcp/update-pool-boundary", argv)

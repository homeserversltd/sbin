"""DHCP remove-reservation. Fields: identifier."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dhcp/remove-reservation", argv)

"""DHCP update-reservation-hostname. Fields: identifier, hostname."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dhcp/update-reservation-hostname", argv)

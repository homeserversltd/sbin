"""DHCP update-reservation-ip. Fields: identifier, new_ip."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dhcp/update-reservation-ip", argv)

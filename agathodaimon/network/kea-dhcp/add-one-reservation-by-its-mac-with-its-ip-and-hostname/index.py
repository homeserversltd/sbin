"""DHCP add-reservation. Fields: hw_address, ip_address, hostname."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dhcp/add-reservation", argv)

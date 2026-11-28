"""DNS device-name create: hostname, ip, move, adopt."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dns/device-name/create", argv)

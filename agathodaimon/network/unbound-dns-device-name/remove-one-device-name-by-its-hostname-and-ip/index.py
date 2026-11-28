"""DNS device-name remove: hostname, ip."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dns/device-name/remove", argv)

"""DNS alias create: label, hostname."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dns/alias/create", argv)

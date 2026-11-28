"""DNS read stop."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dns/read", argv)

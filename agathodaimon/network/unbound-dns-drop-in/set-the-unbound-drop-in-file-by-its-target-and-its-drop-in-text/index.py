"""DNS drop-in apply: target, dropIn, dry-run."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/dns/drop-in/apply", argv)

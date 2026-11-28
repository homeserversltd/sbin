"""House CA rotate-ca stop."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/cert/house-ca/rotate-ca", argv)

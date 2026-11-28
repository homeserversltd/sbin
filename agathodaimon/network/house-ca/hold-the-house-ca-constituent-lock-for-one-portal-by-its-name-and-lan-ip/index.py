"""House CA constituent-lock stop."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/cert/house-ca/constituent-lock", argv)

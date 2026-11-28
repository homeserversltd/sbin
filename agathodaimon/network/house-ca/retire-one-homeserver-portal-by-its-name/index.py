"""Retire a child's HomeServer portal using the house CA composite."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/cert/house-ca/portal-retire", argv)

"""Authenticate using key from the envelope payload; never place a secret in argv."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/tailscale/authkey", argv)

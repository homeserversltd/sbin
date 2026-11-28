"""Observe, compare and plan a device identity."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/identity/device/plan", argv)

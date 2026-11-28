"""Probe the IPv4 address ip for wake-on-LAN reachability."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/wake-on-lan/probe", argv)

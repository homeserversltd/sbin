"""Bring Tailscale up and offer the home network route."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/tailscale/up", argv)

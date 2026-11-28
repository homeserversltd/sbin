"""Read the live and declared Tailscale state."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/tailscale/status", argv)

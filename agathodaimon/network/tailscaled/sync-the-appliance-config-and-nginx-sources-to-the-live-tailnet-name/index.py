"""Change the tailnet name."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/tailscale/tailnet", argv)

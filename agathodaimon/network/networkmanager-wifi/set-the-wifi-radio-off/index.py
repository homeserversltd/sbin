"""One NetworkManager Wi-Fi operation."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/wifi/radio/set", argv, enabled=False)

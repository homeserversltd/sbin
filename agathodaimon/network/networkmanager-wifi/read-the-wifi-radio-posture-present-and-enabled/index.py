"""Read Wi-Fi device presence and the NetworkManager radio state."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/wifi/radio/get", argv)

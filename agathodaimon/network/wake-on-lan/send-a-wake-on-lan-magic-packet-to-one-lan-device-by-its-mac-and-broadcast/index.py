"""Send a wake-on-LAN packet to mac using broadcast (default 255.255.255.255)."""

from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("network/wake-on-lan/send", argv)

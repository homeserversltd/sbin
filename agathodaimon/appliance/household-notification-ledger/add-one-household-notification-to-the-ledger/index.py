"""Post one complete notification through the local Caduceus door."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("notify/post", argv)

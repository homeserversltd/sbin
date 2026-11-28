"""Schedule the restart of one currently listed name after two seconds."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("appliance/restart", argv)

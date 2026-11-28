from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("transmission/keys", argv, action="rotate", service="transmission")

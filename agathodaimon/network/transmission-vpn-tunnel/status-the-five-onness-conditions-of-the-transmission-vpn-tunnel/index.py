"""Read the single five-condition Transmission onness projection."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("transmission/status", argv)


if __name__ == "__main__":
    raise SystemExit(main())

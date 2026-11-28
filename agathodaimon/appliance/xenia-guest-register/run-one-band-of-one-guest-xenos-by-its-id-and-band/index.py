"""Thin Caduceus staff-envelope caller for caduceus-xenos-run."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("xenos/run", argv)


if __name__ == "__main__":
    raise SystemExit(main())

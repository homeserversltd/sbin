"""Stop the native Transmission unit and verify the VPN namespace and host veth are gone."""
from agathodaimon._nidus.alias import run_stop


def main(argv=None):
    return run_stop("transmission/down", argv)


if __name__ == "__main__":
    raise SystemExit(main())

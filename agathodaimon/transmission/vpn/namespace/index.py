"""VPN namespace route delegating to the private implementation."""
from agathodaimon.transmission.namespace.index import dispatch, main


if __name__ == "__main__":
    raise SystemExit(main())

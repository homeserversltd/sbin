"""Compatibility alias for the existing firewall staff actuator."""
from agathodaimon.network.firewall._core import main


if __name__ == "__main__":
    raise SystemExit(main())

"""Keyboard settings staff entry."""
from agathodaimon.settings._parity import main as _main

def main(argv=None):
    return _main("keyboard", argv)

if __name__ == "__main__":
    raise SystemExit(main())

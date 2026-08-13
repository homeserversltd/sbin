"""Reseed the appliance profile from the Harmonia-managed source map."""
from __future__ import annotations

from typing import Sequence

from agathodaimon.lib.source_map.index import main as source_map_main


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    return source_map_main(["reseed"])


if __name__ == "__main__":
    raise SystemExit(main())

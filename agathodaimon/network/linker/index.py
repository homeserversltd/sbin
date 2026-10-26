"""Run the staff-owned Linker JSON adapter."""
from __future__ import annotations

from typing import Sequence

from agathodaimon.linker.linker_json import main as json_main


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    return json_main()


if __name__ == "__main__":
    raise SystemExit(main())

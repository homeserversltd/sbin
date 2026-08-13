"""Run the Harmonia-managed Linker JSON read doors."""
from __future__ import annotations

import os
from typing import Sequence

_PYTHON = "/usr/local/lib/linker/venv/bin/python"
_SCRIPT = "/usr/local/lib/linker/linker_json.py"


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    os.execv(_PYTHON, [_PYTHON, _SCRIPT])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

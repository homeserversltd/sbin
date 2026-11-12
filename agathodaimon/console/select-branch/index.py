"""Expose the immutable stable branch result through the Arcadia OS console CLI."""
from __future__ import annotations

import json
import sys
from typing import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments not in (["-c"], ["-l"]):
        print("usage: console select-branch {-c|-l}", file=sys.stderr)
        print(json.dumps({"ok": False, "firstMissingSignal": "console-select-branch-arguments-invalid"}))
        return 2
    print("stable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

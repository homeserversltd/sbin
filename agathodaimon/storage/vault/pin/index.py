"""Caduceus Keyman legacy door caller."""
from __future__ import annotations

import json
import sys
from typing import Sequence

from agathodaimon.storage.vault.keyman._core import MAX_INPUT_BYTES, Refusal, _receipt, dispatch


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    try:
        if len(raw) > MAX_INPUT_BYTES:
            raise Refusal("agathodaimon-keyman-request-too-large")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise Refusal("agathodaimon-keyman-request-invalid")
        receipt = dispatch(value)
    except (UnicodeDecodeError, json.JSONDecodeError, Refusal):
        signal = "agathodaimon-keyman-request-invalid"
        if isinstance(sys.exc_info()[1], Refusal):
            signal = str(sys.exc_info()[1])
        receipt = _receipt("unknown", False, planned=False, commands=[], signal=signal)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

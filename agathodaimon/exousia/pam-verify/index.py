"""Silent root-only PAM verifier for the household PIN."""
from __future__ import annotations

import os
import sys
from typing import Sequence

from agathodaimon.lib.sacred_credential.index import verify_and_derive_caduceus


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args or os.geteuid() != 0 or os.environ.get("PAM_USER") != "owner":
        return 1
    try:
        raw = sys.stdin.buffer.read()
        pin = raw.decode("utf-8")
        if pin.endswith("\n"):
            pin = pin[:-1]
        signer = verify_and_derive_caduceus(pin)
        signer.close()
    except Exception:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

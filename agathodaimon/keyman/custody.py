"""One metadata-only deed for each native Keyman custody invocation."""
from __future__ import annotations

import time
import sys


def call(operation, runner, *args, **kwargs):
    """Call a backend without recording its arguments, payload, or output."""
    if operation not in ("newkey", "delete", "export", "crypto-create"):
        raise ValueError("unsupported Keyman custody operation")
    started = time.monotonic()
    ok = False
    try:
        result = runner(*args, **kwargs)
        rc = result.get("returncode") if isinstance(result, dict) else getattr(result, "returncode", None)
        ok = rc == 0
        return result
    finally:
        from agathodaimon._deed import send
        # Empty is deliberately used: even a valid service label could equal a secret.
        posted = send("keyman", operation, ok, target="", duration_ms=int((time.monotonic() - started) * 1000))
        if not posted and sys.exc_info()[0] is None:
            raise OSError("keyman-deed-unavailable")

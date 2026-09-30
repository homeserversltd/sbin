"""Bounded journal vacuum staff band."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Sequence

_SCHEMA = "agathodaimon.appliance.journal-vacuum.v1"
_MAX_REQUEST = 65536


def _receipt(ok: bool, signal: str) -> dict[str, object]:
    return {"schema": _SCHEMA, "ok": ok, "firstMissingSignal": signal}


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        raw = sys.stdin.read(_MAX_REQUEST + 1)
        if len(raw) > _MAX_REQUEST:
            raise ValueError
        envelope = json.loads(raw)
        payload = envelope.get("payload") if isinstance(envelope, dict) and "schema" in envelope else envelope
        if not isinstance(payload, dict) or payload:
            raise ValueError
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        print(json.dumps(_receipt(False, "journal-vacuum-payload-invalid"), separators=(",", ":")))
        return 1
    try:
        result = subprocess.run(
            ["/usr/bin/journalctl", "--vacuum-size=300M"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        print(json.dumps(_receipt(False, "journal-vacuum-command-failed"), separators=(",", ":")))
        return 1
    ok = result.returncode == 0
    print(json.dumps(_receipt(ok, "none" if ok else "journal-vacuum-command-failed"), separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

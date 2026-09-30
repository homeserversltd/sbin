"""Bounded journal vacuum staff band."""
from __future__ import annotations

import json
import os
import re
import selectors
import subprocess
import sys
import time
from decimal import Decimal, InvalidOperation
from typing import Sequence

_SCHEMA = "agathodaimon.appliance.journal-vacuum.v1"
_MAX_REQUEST = 65536
_MAX_LINE_BYTES = 8192
_TIMEOUT_SECONDS = 30
_FREED = re.compile(
    r"Vacuuming done,\s*freed\s+([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?i?B?)\s+of archived journals",
    re.IGNORECASE,
)
_SIZE_FACTORS = {"": 1, "B": 1, "K": 1024, "KB": 1024, "KIB": 1024,
                 "M": 1024**2, "MB": 1024**2, "MIB": 1024**2,
                 "G": 1024**3, "GB": 1024**3, "GIB": 1024**3,
                 "T": 1024**4, "TB": 1024**4, "TIB": 1024**4,
                 "P": 1024**5, "PB": 1024**5, "PIB": 1024**5,
                 "E": 1024**6, "EB": 1024**6, "EIB": 1024**6}


def _freed_bytes(output: str) -> int:
    total = 0
    for match in _FREED.finditer(output):
        try:
            amount = Decimal(match.group(1))
        except InvalidOperation:
            continue
        factor = _SIZE_FACTORS.get(match.group(2).upper())
        if factor is not None:
            total += int(amount * factor)
    return total


def _run_vacuum() -> tuple[int, int]:
    command = ["/usr/bin/journalctl", "--vacuum-size=300M"]
    freed_bytes = 0
    pending = bytearray()
    discarding_line = False

    def finish_line() -> None:
        nonlocal freed_bytes, discarding_line
        if not discarding_line:
            freed_bytes += _freed_bytes(pending.decode("utf-8", errors="replace"))
        pending.clear()
        discarding_line = False

    with subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    ) as process:
        if process.stdout is None:
            raise OSError("journalctl output pipe unavailable")
        deadline = time.monotonic() + _TIMEOUT_SECONDS
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise subprocess.TimeoutExpired(command, _TIMEOUT_SECONDS)
                    chunk = os.read(process.stdout.fileno(), 8192)
                    if not chunk:
                        break
                    start = 0
                    while True:
                        end = chunk.find(b"\n", start)
                        ended = end >= 0
                        segment = chunk[start:end] if ended else chunk[start:]
                        if segment and not discarding_line:
                            if len(pending) + len(segment) > _MAX_LINE_BYTES:
                                pending.clear()
                                discarding_line = True
                            else:
                                pending.extend(segment)
                        if ended:
                            finish_line()
                            start = end + 1
                        else:
                            break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command, _TIMEOUT_SECONDS)
            returncode = process.wait(timeout=remaining)
        except BaseException:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise

    if pending and not discarding_line:
        freed_bytes += _freed_bytes(pending.decode("utf-8", errors="replace"))
    return returncode, freed_bytes


def _receipt(ok: bool, signal: str, freed_bytes: int = 0) -> dict[str, object]:
    return {"schema": _SCHEMA, "ok": ok, "firstMissingSignal": signal, "freed_bytes": freed_bytes}


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
        returncode, freed_bytes = _run_vacuum()
    except (OSError, subprocess.SubprocessError):
        print(json.dumps(_receipt(False, "journal-vacuum-command-failed"), separators=(",", ":")))
        return 1
    ok = returncode == 0
    print(json.dumps(_receipt(ok, "none" if ok else "journal-vacuum-command-failed", freed_bytes), separators=(",", ":")))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

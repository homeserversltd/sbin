"""One redacted appliance deed for an attempted NAS integral mutation."""
from __future__ import annotations

import json
import os
import re
import time
import uuid

from agathodaimon.storage.nas import runtime


def record(verb: str, target: str, receipt: dict, started: float) -> None:
    # These values are internal labels, never envelope fields or key material.
    if verb not in {"sync-hold", "sync-release", "sync-schedule-disable", "partlabel-assign",
                    "nas-open", "nas-attach", "nas-detach", "nas-setup"}:
        raise ValueError("invalid NAS deed verb")
    if target not in {"nas-sync", "nas-partition", "nas-primary", "nas-backup", "nas-role"}:
        raise ValueError("invalid NAS deed target")
    signal = receipt.get("firstMissingSignal")
    if not isinstance(signal, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", signal):
        signal = "nas-operation-failed"
    step = receipt.get("failedStep")
    if not isinstance(step, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", step):
        step = None
    line = json.dumps({"who": "agathodaimon", "verb": verb, "target": target,
                       "outcome": "ok" if receipt.get("ok") is True else "failed",
                       "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
                       "id": uuid.uuid4().hex, "signal": signal,
                       "first_missing_field": step}, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(line) >= 1024:
        raise OSError("nas-deed-too-large")
    path = runtime.runtime_path("/var/log/appliance/appliance.log")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    try:
        if os.write(fd, line) != len(line):
            raise OSError("nas-deed-write-failed")
    finally:
        os.close(fd)


def finish(verb: str, target: str, receipt: dict, started: float) -> None:
    try:
        record(verb, target, receipt, started)
    except (OSError, ValueError, runtime.Refusal):
        receipt["deedLogSignal"] = "agathodaimon-nas-deed-log-unavailable"
        if receipt.get("ok") is True:
            receipt["mutationOutcome"] = "completed-deed-unrecorded"
            receipt["ok"] = False
            receipt["firstMissingSignal"] = receipt["deedLogSignal"]
            receipt["failedStep"] = "deed-log"
            runtime._record(receipt, "deed-log", False, recorded=False)

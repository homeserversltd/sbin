"""One redacted appliance deed for an attempted NAS integral mutation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
import os
import re
import time
import uuid

from agathodaimon.storage.nas import runtime


def record(verb: str, target: str, receipt: dict, started: float, *, request=None, transferred_bytes=None) -> None:
    # These values are internal labels, never envelope fields or key material.
    if verb not in {"nas-sync-mirror", "mirror-pull", "sync-hold", "sync-release", "sync-schedule-disable", "partlabel-assign",
                    "nas-open", "nas-attach", "nas-detach", "nas-setup", "nas-folders", "nas-seat"}:
        raise ValueError("invalid NAS deed verb")
    if target not in {"nas-sync", "nas-partition", "nas-primary", "nas-backup", "nas-role"}:
        raise ValueError("invalid NAS deed target")
    signal = receipt.get("firstMissingSignal")
    if not isinstance(signal, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", signal):
        signal = "nas-operation-failed"
    step = receipt.get("failedStep")
    if not isinstance(step, str) or not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", step):
        step = None
    fields = {"who": "agathodaimon", "verb": verb, "target": target,
                       "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "outcome": "ok" if receipt.get("ok") is True else "failed",
                       "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
                       "id": uuid.uuid4().hex, "signal": signal,
                       "first_missing_field": step}
    if verb == "nas-sync-mirror" and receipt.get("outcome") in {"ok", "failed", "refused"}:
        fields["outcome"] = receipt["outcome"]
    if verb == "nas-sync-mirror" and type(transferred_bytes) is int and transferred_bytes >= 0:
        fields["transferred_bytes"] = transferred_bytes
    if isinstance(request, str) and re.fullmatch(r"[A-Za-z0-9._/:+-]{1,160}", request):
        fields["request"] = request
    from agathodaimon._deed import send
    if not send("sbin", verb, receipt.get("ok") is True, target=target,
                duration_ms=fields["duration_ms"]):
        raise OSError("nas-deed-write-failed")


def finish(verb: str, target: str, receipt: dict, started: float, *, request=None) -> None:
    try:
        record(verb, target, receipt, started, request=request)
    except (OSError, ValueError, runtime.Refusal):
        receipt["deedLogSignal"] = "agathodaimon-nas-deed-log-unavailable"
        if receipt.get("ok") is True:
            receipt["mutationOutcome"] = "completed-deed-unrecorded"
            receipt["ok"] = False
            receipt["firstMissingSignal"] = receipt["deedLogSignal"]
            receipt["failedStep"] = "deed-log"
            runtime._record(receipt, "deed-log", False, recorded=False)

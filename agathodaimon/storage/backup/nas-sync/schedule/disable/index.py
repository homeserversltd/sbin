"""Disable the current NAS sync timer without altering legacy schedules."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import time
from pathlib import Path
from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.nas import deed, runtime

SCHEMA = "caduceus.nas-sync.schedule.disable.v1"


def perform(*, request=None):
    receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete", "steps": []}
    started = time.monotonic()
    attempted = False
    try:
        runtime._require_root(receipt)
        check = runtime._run([runtime.SYSTEMCTL, "show", "agathodaimon-nas-sync.timer",
                              "--property=LoadState", "--property=ActiveState", "--property=UnitFileState"],
                             step="schedule-readback")
        if check.returncode:
            raise runtime.Refusal("agathodaimon-nas-schedule-unobservable", "schedule-readback", check.returncode)
        values = dict(line.split("=", 1) for line in check.stdout.decode("utf-8").splitlines() if "=" in line)
        timer = runtime.runtime_path("/etc/systemd/system/agathodaimon-nas-sync.timer")
        state, load = values.get("ActiveState"), values.get("LoadState")
        if state not in {"active", "inactive", "failed"} or not load:
            raise runtime.Refusal("agathodaimon-nas-schedule-unobservable", "schedule-readback")
        absent = not timer.exists() and load == "not-found" and state == "inactive"
        runtime._record(receipt, "schedule-readback", True, timerPresent=not absent, active=state == "active")
        if absent:
            runtime._record(receipt, "schedule-disabled", True, noop=True, timerPresent=False, active=False)
        else:
            module_path = Path(__file__).resolve().parents[2] / "index.py"
            spec = importlib.util.spec_from_file_location("nas_sync_existing", module_path)
            if spec is None or spec.loader is None:
                raise runtime.Refusal("agathodaimon-nas-schedule-unavailable", "schedule-disable")
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.UNIT_DIR = runtime.runtime_path("/etc/systemd/system")
            def runner(argv):
                result = runtime._run(argv, step="schedule-disable", timeout=60)
                return subprocess.CompletedProcess(argv, result.returncode, result.stdout.decode("utf-8"), result.stderr.decode("utf-8"))
            attempted = True
            result = mod.schedule_update({"schedule": {"enabled": False}}, False, runner=runner, persist=False)
            state_after = result.get("timerState", {})
            okay = result.get("ok") is True and state_after.get("enabled") is False and state_after.get("active") is False and not timer.exists()
            runtime._record(receipt, "schedule-disabled", okay, noop=False, timerPresent=timer.exists(), timerState=state_after)
            if not okay:
                raise runtime.Refusal(result.get("firstMissingSignal", "agathodaimon-nas-schedule-disable-failed"), "schedule-disable")
        receipt.update(ok=True, firstMissingSignal="none", state="schedule-disabled")
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
    except (OSError, UnicodeError, ValueError):
        runtime._attach_failure(receipt, runtime.Refusal("agathodaimon-nas-schedule-unobservable", "schedule-readback"))
    if attempted or receipt.get("ok") is not True:
        deed.finish("sync-schedule-disable", "nas-sync", receipt, started, request=request)
    return receipt


def main(argv=None):
    request = None
    try:
        request = read()
        receipt = perform(request=request.intent_id)
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-request-invalid", "failedStep": "request", "steps": []}
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

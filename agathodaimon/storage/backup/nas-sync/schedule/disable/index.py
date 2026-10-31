"""Disable the current NAS sync timer without altering legacy schedules."""
from __future__ import annotations

import json
import time
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
            attempted = True
            service = runtime.runtime_path("/etc/systemd/system/agathodaimon-nas-sync.service")
            for command in ([runtime.SYSTEMCTL, "disable", "--now", "agathodaimon-nas-sync.timer"],
                            ["/usr/bin/rm", "-f", str(service), str(timer)],
                            [runtime.SYSTEMCTL, "daemon-reload"]):
                result = runtime._run(command, step="schedule-disable", timeout=60)
                if result.returncode:
                    raise runtime.Refusal("schedule-update-command-failed:" + command[1], "schedule-disable", result.returncode)
            active = runtime._run([runtime.SYSTEMCTL, "show", "agathodaimon-nas-sync.timer", "--property=ActiveState", "--value"], step="schedule-disable", timeout=60)
            enabled = runtime._run([runtime.SYSTEMCTL, "is-enabled", "agathodaimon-nas-sync.timer"], step="schedule-disable", timeout=60)
            if active.returncode != 0 or enabled.returncode not in {0, 1, 4}:
                raise runtime.Refusal("systemctl-readback-failed", "schedule-disable")
            okay = (active.stdout.decode("utf-8").strip() in {"inactive", "failed"}
                    and enabled.stdout.decode("utf-8").strip() in {"disabled", "not-found", "masked", "static"}
                    and not timer.exists())
            state_after = {"enabled": False, "active": False, "nextFire": None, "planned": False} if okay else {}
            runtime._record(receipt, "schedule-disabled", okay, noop=False, timerPresent=timer.exists(), timerState=state_after)
            if not okay:
                raise runtime.Refusal("schedule-update-readback-mismatch", "schedule-disable")
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

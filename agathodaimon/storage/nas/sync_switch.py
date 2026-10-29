"""The shared sync gate and its cross-process, PID-1-owned holder."""
from __future__ import annotations

import fcntl
import os
import re
import time
import uuid

from agathodaimon.storage.nas import deed, runtime

UNIT = "homeserver-nas-sync-hold.service"
SYSTEMD_RUN = "/usr/bin/systemd-run"


def _holder():
    result = runtime._run([runtime.SYSTEMCTL, "show", UNIT, "--property=ActiveState", "--property=MainPID", "--property=Description"], step="holder-readback")
    if result.returncode != 0:
        raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-readback", result.returncode)
    try:
        values = dict(line.split("=", 1) for line in result.stdout.decode("utf-8").splitlines() if "=" in line)
        state = values["ActiveState"]
        pid = int(values["MainPID"])
    except (ValueError, KeyError, UnicodeError):
        raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-readback") from None
    if state != "active":
        return {"active": False, "state": state, "pid": pid, "ownsLock": False}
    if pid <= 0:
        raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-readback")
    try:
        st = os.stat(runtime.sync_lock_path(), follow_symlinks=False)
        lock_id = f"{os.major(st.st_dev):02x}:{os.minor(st.st_dev):02x}:{st.st_ino}"
        with open("/proc/locks", encoding="ascii") as stream:
            rows = stream.read().splitlines()
    except OSError:
        raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-readback") from None
    owns = False
    for row in rows:
        fields = row.split()
        if len(fields) >= 6 and fields[1:4] == ["FLOCK", "ADVISORY", "READ"] and fields[4] == str(pid):
            raw = fields[5].split(":")
            try:
                actual = (int(raw[0], 16), int(raw[1], 16), int(raw[2]))
            except (IndexError, ValueError):
                continue
            if actual == (os.major(st.st_dev), os.minor(st.st_dev), st.st_ino):
                owns = True
                break
    return {"active": True, "state": state, "pid": pid, "ownsLock": owns, "lockIdentity": lock_id, "description": values.get("Description")}


def _exclusive_free():
    fd = None
    try:
        fd = os.open(runtime.sync_lock_path(), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    except OSError:
        raise runtime.Refusal("agathodaimon-nas-sync-lock-unobservable", "sync-lock-readback") from None
    finally:
        if fd is not None:
            os.close(fd)


def perform(action, hold_id=None, *, request=None):
    schema = f"caduceus.nas-sync.{action}.v1"
    receipt = {"schema": schema, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete", "steps": []}
    started = time.monotonic()
    attempted = False
    marker = None
    try:
        runtime._require_root(receipt)
        if action not in {"hold", "release"}:
            raise runtime.Refusal("agathodaimon-nas-sync-action-invalid", "request")
        if action == "release" and hold_id is not None and (not isinstance(hold_id, str) or not re.fullmatch(r"agathodaimon-nas-sync-hold-[0-9a-f]+", hold_id)):
            raise runtime.Refusal("agathodaimon-nas-request-invalid", "request")
        with runtime.drive_guard():
            before = _holder()
            runtime._record(receipt, "holder-before", True, **before)
            if before["active"] and not before["ownsLock"]:
                raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-readback")
            if action == "release" and hold_id is not None and before.get("description") != hold_id:
                raise runtime.Refusal("agathodaimon-nas-sync-hold-not-owned", "holder-readback")
            if action == "hold" and before["active"]:
                # A second transaction must not borrow the first transaction's
                # hold and later release it between that transaction's steps.
                raise runtime.Refusal("agathodaimon-nas-sync-hold-already-active", "holder-readback")
            if action == "hold" and not before["active"]:
                marker = "agathodaimon-nas-sync-hold-" + uuid.uuid4().hex
                try:
                    attempted = True
                    command = runtime._run([SYSTEMD_RUN, "--unit=homeserver-nas-sync-hold", "--property=Type=exec",
                                            "--property=Description=" + marker,
                                            "/usr/bin/flock", "--shared", "--nonblock", str(runtime.sync_lock_path()),
                                            "/usr/bin/sleep", "infinity"], step="holder-start", timeout=30)
                    runtime._record(receipt, "holder-start", command.returncode == 0, rc=command.returncode)
                    if command.returncode != 0:
                        raise runtime.Refusal("sync-hold-refused-running", "holder-start", command.returncode)
                    deadline = time.monotonic() + 3.0
                    while True:
                        after = _holder()
                        if after["active"] and after["ownsLock"] and after["description"] == marker:
                            break
                        if time.monotonic() >= deadline:
                            raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-readback")
                        time.sleep(0.25)
                    runtime._record(receipt, "holder-readback", True, **after)
                except runtime.Refusal as failure:
                    # A failed or timed-out start may still have reached PID 1.
                    # Stop only a unit bearing this request's unique marker.
                    try:
                        observed = runtime._run([runtime.SYSTEMCTL, "show", UNIT, "--property=Description", "--value"], step="holder-cleanup-owner", timeout=30)
                        description = runtime._decode_output(observed, "holder-cleanup-owner")
                        if observed.returncode != 0 or description != marker:
                            clean = False
                            runtime._record(receipt, "holder-cleanup", False, reason="unit-ownership-unproven")
                        else:
                            stopped = runtime._run([runtime.SYSTEMCTL, "stop", UNIT], step="holder-cleanup", timeout=30)
                            final = _holder()
                            clean = stopped.returncode == 0 and not final["active"]
                            runtime._record(receipt, "holder-cleanup", clean, rc=stopped.returncode, **final)
                    except runtime.Refusal:
                        clean = False
                        runtime._record(receipt, "holder-cleanup", False, reason="cleanup-unobservable")
                    if not clean:
                        raise runtime.Refusal("agathodaimon-nas-sync-holder-cleanup-failed", "holder-cleanup") from None
                    raise failure
            elif action == "release" and before["active"]:
                attempted = True
                command = runtime._run([runtime.SYSTEMCTL, "stop", UNIT], step="holder-stop", timeout=30)
                runtime._record(receipt, "holder-stop", command.returncode == 0, rc=command.returncode)
                if command.returncode != 0:
                    raise runtime.Refusal("agathodaimon-nas-sync-release-failed", "holder-stop", command.returncode)
                after = _holder()
                runtime._record(receipt, "holder-readback", not after["active"], **after)
                if after["active"]:
                    raise runtime.Refusal("agathodaimon-nas-sync-release-failed", "holder-readback")
        free = _exclusive_free()
        expected = action == "release"
        runtime._record(receipt, "sync-lock-readback", free == expected, lockFree=free)
        if free != expected:
            raise runtime.Refusal("agathodaimon-nas-sync-lock-readback-mismatch", "sync-lock-readback")
        if action == "hold":
            final_holder = _holder()
            valid_holder = final_holder["active"] and final_holder["ownsLock"] and final_holder["description"] == marker
            runtime._record(receipt, "holder-final-readback", valid_holder, **final_holder)
            if not valid_holder:
                raise runtime.Refusal("agathodaimon-nas-sync-holder-unobservable", "holder-final-readback")
            receipt["holdId"] = marker
        receipt.update(ok=True, firstMissingSignal="none", state="sync-held" if action == "hold" else "sync-released")
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
    if attempted or receipt.get("ok") is not True:
        deed.finish("sync-" + action, "nas-sync", receipt, started, request=request)
    return receipt

"""Door and detached worker for a NAS import."""
from __future__ import annotations

import contextlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from agathodaimon import _envelope
from agathodaimon._deed import send
from agathodaimon.storage.nas import runtime

SYSTEMD_RUN = "/usr/bin/systemd-run"
_DEVICE = re.compile(r"/dev/[A-Za-z0-9._-]+\Z")
_UNIT = re.compile(r"homeserver-nas-import-[0-9a-f]{32}\Z")


def _receipt():
    return {"ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete",
            "changed": False, "mutationPerformed": False, "steps": []}


def _deed(receipt, started):
    signal = receipt.get("firstMissingSignal")
    if not isinstance(signal, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", signal):
        signal = "nas-import-refused"
    step = receipt.get("failedStep")
    stages = [["failed-step", step]] if isinstance(step, str) and re.fullmatch(r"[A-Za-z0-9._-]{1,24}", step) else None
    ok = receipt.get("ok") is True
    outcome = "ok" if ok else "failed" if receipt.get("changed") else "refused"
    with contextlib.redirect_stderr(io.StringIO()):
        recorded = send("sbin", "nas-import", ok, target="nas-primary",
                        duration_ms=int((time.monotonic() - started) * 1000),
                        signal=signal, outcome=outcome, stages=stages)
    if not recorded:
        receipt["deedLogSignal"] = "agathodaimon-nas-deed-log-unavailable"
    return recorded


def _plan(receipt, device):
    return importlib.import_module("agathodaimon.storage.nas.import._plan").build(receipt, device)


def _device(value):
    if not isinstance(value, str) or not _DEVICE.fullmatch(value) or value in {"/dev/.", "/dev/.."}:
        raise runtime.Refusal("agathodaimon-nas-import-device-invalid", "request-device")
    return value


def _read_request():
    raw = sys.stdin.buffer.read(runtime.MAX_INPUT + 1)
    if not raw or len(raw) > runtime.MAX_INPUT:
        raise ValueError("request-size-invalid")
    prior = sys.stdin
    try:
        sys.stdin = io.StringIO(raw.decode("utf-8"))
        return _envelope.read(known_fields=("device",))
    finally:
        sys.stdin = prior


def dispatch(request):
    started = time.monotonic()
    receipt = _receipt()
    try:
        runtime._require_root(receipt)
        device = _device(request.payload.get("device"))
        with runtime.drive_guard():
            plan = _plan(receipt, device)
        unit = "homeserver-nas-import-" + uuid.uuid4().hex
        args = [SYSTEMD_RUN, "--quiet", f"--unit={unit}", "--collect",
                "--property=Type=exec", "--property=StandardOutput=null"]
        scratch = runtime._scratch_root()
        if scratch is not None:
            args.append("--setenv=AGATHODAIMON_SCRATCH_ROOT=" + str(scratch))
        args.extend(["--", sys.executable, "-I", str(Path(__file__).resolve()), "--worker", device, unit])
        result = runtime._run(args, step="import-launch", timeout=30)
        if result.returncode != 0:
            raise runtime.Refusal("agathodaimon-nas-import-launch-refused", "import-launch", result.returncode)
        runtime._record(receipt, "import-launch", True)
        receipt.update(ok=True, firstMissingSignal="none", started=True, unit=unit,
                       device=device, partition=plan["dataPath"], label=plan["label"],
                       destination=plan["destination"])
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
        _deed(receipt, started)
    except (OSError, KeyError, TypeError, ValueError):
        runtime._attach_failure(receipt, runtime.Refusal("agathodaimon-nas-import-plan-unavailable", "import-plan"))
        _deed(receipt, started)
    return _envelope.attach(receipt, request)


def main(argv=None):
    del argv
    try:
        receipt = dispatch(_read_request())
    except (ValueError, UnicodeError, json.JSONDecodeError, _envelope.EnvelopeError):
        receipt = _receipt()
        runtime._attach_failure(receipt, runtime.Refusal("agathodaimon-nas-request-invalid", "request"))
        _deed(receipt, time.monotonic())
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


def worker(args):
    if len(args) != 3 or args[0] != "--worker" or not _UNIT.fullmatch(args[2]):
        print("nas-import-worker-invalid", file=sys.stderr)
        return 1
    try:
        device = _device(args[1])
    except runtime.Refusal:
        print("nas-import-worker-invalid", file=sys.stderr)
        return 1
    if os.geteuid() != 0:
        print("nas-import-worker-root-required", file=sys.stderr)
        return 1
    started = time.monotonic()
    receipt = _receipt()
    try:
        with runtime.drive_guard():
            plan = _plan(receipt, device)
            try:
                act = importlib.import_module("agathodaimon.storage.nas.import._copy").act
            except (ImportError, AttributeError):
                raise runtime.Refusal("agathodaimon-nas-import-act-unavailable", "import-copy") from None
            receipt = act(plan, receipt)
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
    except Exception:
        runtime._attach_failure(receipt, runtime.Refusal("agathodaimon-nas-import-worker-failed", "import-worker"))
    recorded = _deed(receipt, started)
    print("nas-import-deed recorded" if recorded else "nas-import-deed unrecorded", file=sys.stderr)
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(worker(sys.argv[1:]))

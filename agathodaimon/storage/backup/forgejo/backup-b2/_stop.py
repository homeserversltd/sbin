"""Fixed Forgejo backup stops over the existing transient-unit launcher."""
import json
import os
import time
from importlib import import_module

from agathodaimon import _envelope

_backup = import_module("agathodaimon.storage.backup.forgejo.backup-b2.index")


def finish(act, result, request=None):
    result["schema"] = "caduceus.storage.backup.forgejo.backup-b2." + act + ".v1"
    if request is not None:
        result = _envelope.attach(result, request)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1


def dispatch(act, request):
    try:
        bucket = request.payload.get("bucket")
        if not _backup.backblaze.valid_bucket(bucket):
            _backup.refuse("shape", "bucket-invalid")
        # The existing worker reads its skip policy from config and has no
        # per-request retention input. Never claim to apply ignored options.
        for field in ("exclude", "days"):
            if field in request.payload:
                _backup.refuse("shape", field + "-unsupported")
        scratch_markers = ("AGATHODAIMON_SCRATCH_ROOT", "BACKBLAZE_SCRATCH_ROOT",
                           "FORGEJO_BACKUP_CONFIG", "FORGEJO_BACKUP_APP_INI", "FORGEJO_BACKUP_WORK")
        if act == "run" and any(key in os.environ for key in scratch_markers):
            _backup.refuse("launch", "scratch-run-refused")
        config = _envelope.appliance_runtime_path("config")
        _backup.read_config(bucket, config)
        if act == "plan":
            unit = _backup.UNIT_PREFIX + str(int(time.time()))
            # The run checks systemd only while holding an exclusive lock and
            # performs that read by spawning systemctl. A read-only plan may
            # construct the command, but cannot claim those checks succeeded.
            result = {"ok": False, "step": "launch",
                      "reason": "launch-state-requires-lock-and-spawn",
                      "unit": unit, "argv": _backup.launch_command(bucket, unit)}
        else:
            result = _backup.launch(bucket)
    except (_backup.Refusal, _backup.backblaze.Refusal) as error:
        result = {"ok": False, "step": error.step, "reason": error.reason}
    except ValueError:
        result = {"ok": False, "step": "shape", "reason": "scratch-root-invalid"}
    result["firstMissingSignal"] = "none" if result["ok"] else "forgejo-backup-b2-" + act + "-" + result["reason"]
    return finish(act, result, request)

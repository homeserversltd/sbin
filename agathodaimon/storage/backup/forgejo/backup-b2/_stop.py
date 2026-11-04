"""Envelope-facing Forgejo backup stops over the existing implementation."""
import json
import os
import signal
from pathlib import Path
from importlib import import_module

from agathodaimon import _envelope

_backup = import_module("agathodaimon.storage.backup.forgejo.backup-b2._backup")


def finish(act, result, request=None):
    result["schema"] = "caduceus.storage.backup.forgejo.backup-b2." + act + ".v1"
    if request is not None:
        result = _envelope.attach(result, request)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("ok") else 1


def invoke(act, read_request):
    def deadline(_signum, _frame):
        _backup.refuse("request", "request-deadline-exceeded")
    previous_handler = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(24)
    try:
        try:
            request = read_request()
        except _envelope.EnvelopeError:
            return finish(act, {"ok": False, "firstMissingSignal": "forgejo-backup-b2-" + act + "-envelope-invalid"})
        return dispatch(act, request)
    except _backup.Refusal as error:
        return finish(act, {"ok": False, "step": error.step, "reason": error.reason,
                            "firstMissingSignal": "forgejo-backup-b2-" + act + "-" + error.reason})
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous_handler)


def dispatch(act, request):
    try:
        bucket = request.payload.get("bucket")
        if not _backup.backblaze.valid_bucket(bucket):
            _backup.refuse("shape", "bucket-invalid")
        if act == "plan":
            overrides = {k: os.environ[k] for k in ('FORGEJO_BACKUP_CONFIG', 'FORGEJO_BACKUP_APP_INI', 'FORGEJO_BACKUP_WORK') if k in os.environ}
            if overrides:
                root = _backup.backblaze.scratch_root()
                if root is None or any(not value or not Path(value).resolve().is_relative_to(root) for value in overrides.values()):
                    _backup.refuse('shape', 'scratch-root-invalid')
            config = Path(os.environ.get("FORGEJO_BACKUP_CONFIG", str(_backup.CONFIG)))
            ini = Path(os.environ.get("FORGEJO_BACKUP_APP_INI", str(_backup.APP_INI)))
            work = Path(os.environ.get("FORGEJO_BACKUP_WORK", str(_backup.WORK)))
            row, paths, included, excluded, uuids, lfs_oids, shared = _backup.plan(bucket, config, ini, work)
            found = 0
            for u in uuids:
                try:
                    (paths['attachments'] / u[0] / u[1] / u).stat()
                    found += 1
                except FileNotFoundError:
                    pass
                except OSError:
                    _backup.refuse('attachments', 'attachment-stat-unavailable')
            result = {"ok": True, "plan": {"included": included, "excluded": len(excluded),
                      "excludedNames": [owner + "/" + repo for owner, repo in excluded],
                      "excludedAttachments": len(uuids), "excludedAttachmentsPresent": found,
                      "excludedLfs": len(lfs_oids), "sharedLfsKept": shared, "repo": _backup.restic_repo(row)}}
        else:
            if any(k in os.environ for k in ("BACKBLAZE_SCRATCH_ROOT", "FORGEJO_BACKUP_CONFIG", "FORGEJO_BACKUP_APP_INI", "FORGEJO_BACKUP_WORK")):
                _backup.refuse("launch", "scratch-overrides-plan-only")
            _backup.read_config(bucket, _backup.CONFIG)
            result = _backup.launch(bucket)
    except (_backup.Refusal, _backup.backblaze.Refusal) as error:
        result = {"ok": False, "step": error.step, "reason": error.reason}
    result["firstMissingSignal"] = "none" if result["ok"] else "forgejo-backup-b2-" + act + "-" + result["reason"]
    return finish(act, result, request)

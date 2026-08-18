from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

FAMILY = "caduceus.staff.force_permissions.v1"
ROOT_PREFIX = "/mnt/nas"


def receipt(ok, action, planned=False, mutation=False, commands=None, signal=None, **facts):
    value = {"schema": FAMILY, "receiptFamily": FAMILY, "ok": ok, "action": action,
             "planned": planned, "mutationPerformed": mutation, "commands": commands or [],
             "firstMissingSignal": "none" if ok else (signal or "force_permissions.refused")}
    value.update(facts)
    print(json.dumps(value, sort_keys=True))
    return 0 if ok else 1


def nas_root() -> Path:
    return Path(os.environ.get("CADUCEUS_NAS_ROOT", ROOT_PREFIX)).resolve()


def admitted_target(raw) -> Path:
    if not isinstance(raw, str) or not raw.startswith(ROOT_PREFIX + "/"):
        raise ValueError("target must be below /mnt/nas")
    relative = raw[len(ROOT_PREFIX) + 1:]
    if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError("target path is not admitted")
    base = nas_root()
    target = (base / relative).resolve(strict=True)
    if target != base and base not in target.parents:
        raise ValueError("target escapes NAS root")
    return target


def requested_mode(metadata: dict) -> str:
    value = metadata.get("mode", 0o775)
    if value == 0o775 or value in {"0775", "775", "0o775"}:
        return "0775"
    raise ValueError("mode is not admitted")


def main(_argv=None):
    action = "force-permissions"
    try:
        envelope = json.load(sys.stdin)
        metadata = envelope.get("metadata") if isinstance(envelope, dict) else None
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        raw = next((metadata.get(k) for k in ("destination", "directory", "path") if k in metadata), None)
        target = admitted_target(raw)
        if not target.is_dir() or target.is_symlink():
            raise ValueError("target is not a directory")
        mode = requested_mode(metadata)
        planned = bool(metadata.get("planned", metadata.get("dryRun", False)))
        commands = [["chmod", mode, str(target)]]
        if planned:
            return receipt(True, action, True, False, commands, None, target=str(target), mode=mode, requestedMode=mode, appliedMode=mode)
        os.chmod(target, 0o775, follow_symlinks=False)
        mode = stat.S_IMODE(target.stat(follow_symlinks=False).st_mode)
        if mode != 0o775:
            return receipt(False, action, False, True, commands, "force_permissions.readback_mismatch", target=str(target), mode=oct(mode))
        return receipt(True, action, False, True, commands, None, target=str(target), mode="0775", requestedMode="0775", appliedMode="0775")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return receipt(False, action, False, False, [], "force_permissions.validation", error=str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

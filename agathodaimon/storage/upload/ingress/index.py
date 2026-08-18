from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path

FAMILY = "caduceus.staff.file_ingress.v1"
ROOT_PREFIX = "/mnt/nas"


def receipt(ok, action, planned=False, mutation=False, commands=None, signal=None, **facts):
    value = {"schema": FAMILY, "receiptFamily": FAMILY, "ok": ok, "action": action,
             "planned": planned, "mutationPerformed": mutation, "commands": commands or [],
             "firstMissingSignal": "none" if ok else (signal or "file_ingress.refused")}
    value.update(facts)
    print(json.dumps(value, sort_keys=True))
    return 0 if ok else 1


def nas_root() -> Path:
    return Path(os.environ.get("CADUCEUS_NAS_ROOT", ROOT_PREFIX)).resolve()


def target_path(metadata: dict) -> Path:
    raw = metadata.get("path", metadata.get("targetPath"))
    if raw is None and isinstance(metadata.get("destination"), str) and isinstance(metadata.get("filename"), str):
        destination, filename = metadata["destination"], metadata["filename"]
        if "/" in filename or filename in {"", ".", ".."}:
            raise ValueError("filename is not admitted")
        raw = destination.rstrip("/") + "/" + filename
    if not isinstance(raw, str) or not raw.startswith(ROOT_PREFIX + "/"):
        raise ValueError("target must be below /mnt/nas")
    relative = raw[len(ROOT_PREFIX) + 1:]
    if not relative or any(part in {"", ".", ".."} for part in relative.split("/")):
        raise ValueError("target path is not admitted")
    base = nas_root()
    parent = (base / relative).parent.resolve(strict=True)
    if parent != base and base not in parent.parents:
        raise ValueError("target parent escapes NAS root")
    target = parent / Path(relative).name
    if os.path.lexists(target) and target.is_symlink():
        raise ValueError("target must not be a symlink")
    return target


def source_path(metadata: dict) -> Path:
    raw = metadata.get("spoolPath", metadata.get("sourcePath"))
    if not isinstance(raw, str) or not raw.startswith("/"):
        raise ValueError("spool path must be absolute")
    if any(part in {".", ".."} for part in raw.split("/") if part):
        raise ValueError("spool path is not admitted")
    source = Path(raw)
    if source.is_symlink():
        raise ValueError("spool path must not be a symlink")
    source = source.resolve(strict=True)
    if not source.is_file() or not stat.S_ISREG(source.stat(follow_symlinks=False).st_mode):
        raise ValueError("spool path is not a regular file")
    return source


def numeric(metadata, key, default):
    value = metadata.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{key} must be numeric")
    return value


def main(_argv=None):
    action = "file-ingress"
    try:
        envelope = json.load(sys.stdin)
        metadata = envelope.get("metadata") if isinstance(envelope, dict) else None
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        target = target_path(metadata)
        source = source_path(metadata)
        mode = numeric(metadata, "mode", 0o664)
        if mode > 0o7777:
            raise ValueError("mode is not admitted")
        parent_stat = target.parent.stat(follow_symlinks=False)
        uid = numeric(metadata, "uid", parent_stat.st_uid)
        gid = numeric(metadata, "gid", parent_stat.st_gid)
        planned = bool(metadata.get("planned", metadata.get("dryRun", False)))
        commands = [["copy", str(source), str(target)], ["chmod", oct(mode), str(target)], ["chown", f"{uid}:{gid}", str(target)]]
        if planned:
            return receipt(True, action, True, False, commands, None, target=str(target), spoolPath=str(source), mode=oct(mode), uid=uid, gid=gid)
        fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
        temp = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as out, source.open("rb") as inp:
                shutil.copyfileobj(inp, out)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temp, mode, follow_symlinks=False)
            os.chown(temp, uid, gid, follow_symlinks=False)
            os.replace(temp, target)
            dirfd = os.open(target.parent, os.O_DIRECTORY)
            try:
                os.fsync(dirfd)
            finally:
                os.close(dirfd)
        finally:
            try:
                temp.unlink()
            except FileNotFoundError:
                pass
        final = target.stat(follow_symlinks=False)
        if not stat.S_ISREG(final.st_mode) or stat.S_IMODE(final.st_mode) != mode or final.st_uid != uid or final.st_gid != gid:
            return receipt(False, action, False, True, commands, "file_ingress.readback_mismatch", target=str(target), mode=oct(stat.S_IMODE(final.st_mode)), uid=final.st_uid, gid=final.st_gid)
        return receipt(True, action, False, True, commands, None, target=str(target), mode=oct(mode), uid=uid, gid=gid, size=final.st_size)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        return receipt(False, action, False, False, [], "file_ingress.validation", error=str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

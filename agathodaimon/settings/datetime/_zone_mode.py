"""The owner's household-zone following preference in appliance config."""
from importlib import import_module
import fcntl
import json
import os
import stat
from pathlib import Path

# Reuse the existing appliance-config member splicer and atomic writer.
_writer = import_module("agathodaimon.update.module-toggle.index")


def _config_path():
    root = os.environ.get("CADUCEUS_ROOT")
    if root is not None:
        return Path(root) / "etc/appliance/config.json"
    from agathodaimon._envelope import appliance_runtime_path
    return appliance_runtime_path("config")


def _load():
    path = _config_path()
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("agathodaimon-zone-mode-config-invalid")
    raw = path.read_text(encoding="utf-8")
    document = _writer._load(raw)
    section = document.get("time", {})
    if not isinstance(section, dict):
        raise ValueError("agathodaimon-zone-mode-config-invalid")
    mode = section.get("zone_mode", "follow")
    if mode not in ("follow", "manual"):
        raise ValueError("agathodaimon-zone-mode-invalid")
    return path, metadata, raw, document, mode


def read_mode():
    return _load()[-1]


def set_mode(mode):
    if mode not in ("follow", "manual"):
        raise ValueError("agathodaimon-zone-mode-invalid")
    directory = os.open(_config_path().parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        return _set_mode_locked(mode)
    finally:
        os.close(directory)


def _set_mode_locked(mode):
    path, metadata, raw, document, previous = _load()
    if previous == mode and "zone_mode" in document.get("time", {}):
        return False
    start, end, members = _writer._object_members(raw)
    encoded = json.dumps(mode)
    if "time" not in members:
        updated = _writer._insert_member(raw, start, end, "time", json.dumps({"zone_mode": mode}))
    else:
        section_start, _ = members["time"]
        section_start, section_end, section_members = _writer._object_members(raw, section_start)
        if "zone_mode" in section_members:
            a, b = section_members["zone_mode"]
            updated = raw[:a] + encoded + raw[b:]
        else:
            updated = _writer._insert_member(raw, section_start, section_end, "zone_mode", encoded)
    current = path.lstat()
    if (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_size) != (metadata.st_dev, metadata.st_ino, metadata.st_mtime_ns, metadata.st_size) or path.read_text(encoding="utf-8") != raw:
        raise ValueError("agathodaimon-zone-mode-config-concurrent-update")
    _writer._atomic_write(path, updated.encode("utf-8"), stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, ".config.")
    return True

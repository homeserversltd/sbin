"""List one level of directories beneath the mounted primary NAS."""
from __future__ import annotations

import heapq
import json
import os
import stat

from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.nas import runtime

FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def listing(path):
    result = {"ok": False, "path": path if isinstance(path, str) else None,
              "folders": [], "truncated": False, "firstMissingSignal": "agathodaimon-nas-list-not-complete"}
    fd = None
    try:
        if (not isinstance(path, str) or path.startswith("/") or "\x00" in path
                or (path and any(part in ("", ".", "..") for part in path.split("/")))):
            raise runtime.Refusal("agathodaimon-nas-list-path-invalid", "path")
        runtime._require_root({})
        info = runtime._role_info("primary")
        mounts = runtime._mountinfo()
        mount = runtime._mount_for_target(mounts, info["mountpoint"])
        if mount is None:
            raise runtime.Refusal("agathodaimon-nas-list-mount-absent", "mount")
        partition = runtime.role_partition("primary")
        partition_id = runtime._device_identity(partition, "partition")
        graph, _ = runtime._block_graph()
        if mount["dev"] not in runtime._component(graph, partition_id):
            raise runtime.Refusal("agathodaimon-nas-list-mount-mismatch", "mount")
        absolute = runtime.runtime_path(info["mountpoint"])
        fd = os.open("/", FLAGS)
        for part in absolute.parts[1:]:
            next_fd = os.open(part, FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        root_dev = os.fstat(fd).st_dev
        if runtime._scratch_root() is None and f"{os.major(root_dev)}:{os.minor(root_dev)}" != mount["dev"]:
            raise runtime.Refusal("agathodaimon-nas-list-mount-mismatch", "mount")
        current = info["mountpoint"]
        nested = {entry["target"] for entry in mounts if entry["target"].startswith(current + "/")}
        for part in path.split("/") if path else []:
            current += "/" + part
            if current in nested:
                raise runtime.Refusal("agathodaimon-nas-list-cross-device", "path")
            try:
                metadata = os.stat(part, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise runtime.Refusal("agathodaimon-nas-list-symlink", "path")
                next_fd = os.open(part, FLAGS, dir_fd=fd)
            except runtime.Refusal:
                raise
            except OSError:
                raise runtime.Refusal("agathodaimon-nas-list-path-unavailable", "path") from None
            os.close(fd)
            fd = next_fd
            if os.fstat(fd).st_dev != root_dev:
                raise runtime.Refusal("agathodaimon-nas-list-cross-device", "path")
        def names():
            with os.scandir(fd) as entries:
                for entry in entries:
                    if entry.name.startswith(".") or entry.name == "lost+found" or current + "/" + entry.name in nested:
                        continue
                    meta = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(meta.st_mode) and meta.st_dev == root_dev:
                        yield entry.name
        values = heapq.nsmallest(501, names())
        result.update(ok=True, folders=values[:500], truncated=len(values) > 500, firstMissingSignal="none")
    except runtime.Refusal as failure:
        result["firstMissingSignal"] = failure.signal_name
    except OSError:
        result["firstMissingSignal"] = "agathodaimon-nas-list-unavailable"
    finally:
        if fd is not None:
            os.close(fd)
    return result


def main(argv=None):
    del argv
    request = None
    try:
        request = read(known_fields=("path",))
        result = listing(request.payload.get("path", ""))
    except (EnvelopeError, ValueError, UnicodeError):
        result = {"ok": False, "path": None, "folders": [], "truncated": False,
                  "firstMissingSignal": "agathodaimon-nas-request-invalid"}
    if request is not None:
        result = attach(result, request)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1

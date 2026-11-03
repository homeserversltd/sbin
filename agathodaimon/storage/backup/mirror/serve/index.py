"""Serve the primary NAS as a restricted, read-only rsync sender."""
from __future__ import annotations

import errno
import fcntl
import json
import os
import re
import select
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


class Refusal(Exception):
    pass


def _paths():
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    if root is None:
        return Path("/mnt/nas/"), Path("/run/homeserver-nas-sync.lock"), Path("/var/log/appliance/appliance.log")
    # Proof only: the scratch root and AGATHODAIMON_MIRROR_SOURCE isolate source, lock, and log.
    base = Path(root)
    try:
        if not base.is_absolute():
            raise ValueError("relative scratch root")
        base = base.resolve(strict=True)
        if base == Path("/"):
            raise ValueError("root scratch")
        source = Path(os.environ.get("AGATHODAIMON_MIRROR_SOURCE", str(base / "mnt/nas")))
        lock = Path(os.environ.get("CADUCEUS_NAS_LOCK", str(base / "run/homeserver-nas-sync.lock")))
        if any(not p.is_absolute() or not p.resolve(strict=False).is_relative_to(base) for p in (source, lock)):
            raise ValueError("outside scratch")
        return source, lock, base / "var/log/appliance/appliance.log"
    except (OSError, RuntimeError, ValueError) as exc:
        raise Refusal("mirror-serve-scratch-invalid") from exc


def _refuse(signal, started, log):
    deed = {"who": "agathodaimon", "verb": "mirror-serve", "target": "nas-sync",
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "outcome": "refused", "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
            "signal": signal, "first_missing_field": "mirror-serve"}
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        try:
            os.write(fd, (json.dumps(deed, separators=(",", ":")) + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        deed["deedLogSignal"] = "agathodaimon-nas-deed-log-unavailable"
    print(json.dumps({"schema": "caduceus.nas.mirror-serve.v1", "ok": False,
                      "firstMissingSignal": signal, **({"deedLogSignal": deed["deedLogSignal"]} if "deedLogSignal" in deed else {})}, separators=(",", ":")), file=sys.stderr, flush=True)
    return 1


def main():
    started = time.monotonic()
    log = Path("/var/log/appliance/appliance.log")
    fd = None
    try:
        if os.geteuid() != 0:
            raise Refusal("mirror-serve-root-required")
        source, lock, log = _paths()
        lock.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            raise Refusal("mirror-serve-lock-invalid")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                raise Refusal("mirror-serve-lock-busy") from exc
            raise
        # ismount misses bind mounts on the same filesystem; mountinfo names them.
        with open("/proc/self/mountinfo", encoding="utf-8") as mounts:
            mounted = any(
                re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), row.split()[4]) == str(source.resolve())
                for row in mounts if len(row.split()) >= 5
            )
        if not mounted:
            raise Refusal("mirror-serve-source-not-mounted")
        command = bytearray()
        deadline = time.monotonic() + 30
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
                raise Refusal("mirror-serve-command-timeout")
            byte = os.read(0, 1)
            if not byte:
                raise Refusal("mirror-serve-command-incomplete")
            if byte == b"\n":
                break
            command.extend(byte)
            if len(command) > 4096:
                raise Refusal("mirror-serve-command-too-long")
        try:
            text = command.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Refusal("mirror-serve-command-invalid") from exc
        if not text.startswith("rsync --server --sender ") or "\x00" in text or "\r" in text:
            raise Refusal("mirror-serve-sender-required")
        # rrsync -ro on some versions permits sender-side file removal; never permit it.
        if re.search(r"(?:^|\s)--remove-(?:source|sent)-files(?:=|\s|$)", text):
            raise Refusal("mirror-serve-source-removal-refused")
        os.set_inheritable(fd, True)
        env = os.environ.copy()
        env["SSH_ORIGINAL_COMMAND"] = text
        # rrsync opens an existing rrsync.log in its initial cwd before chdir.
        os.chdir("/proc/self")
        os.execve("/usr/bin/rrsync", ["/usr/bin/rrsync", "-ro", str(source) + "/"], env)
    except Refusal as exc:
        return _refuse(str(exc), started, log)
    except OSError:
        return _refuse("mirror-serve-system-error", started, log)
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == "__main__":
    sys.exit(main())

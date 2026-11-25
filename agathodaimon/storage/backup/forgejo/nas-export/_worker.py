"""Forgejo NAS export worker. Production inputs come from the running unit."""
from __future__ import annotations

import configparser
import ctypes
import fcntl
import grp
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import ProxyHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
from agathodaimon import _deed

PREFIX = "forgejo-nas-export-"
PROOF = ("DESTINATION", "MOUNT", "UNIT", "WORK", "PG_HOST", "PG_PORT")


class Failure(Exception):
    def __init__(self, reason, outcome="failed"):
        self.reason, self.outcome = reason, outcome


def deed(outcome, reason, files, size):
    # An incomplete proof selection must never fall through to the live ledger.
    if not os.environ.get("AGATHODAIMON_SCRATCH_ROOT") and any(
        k.startswith("FORGEJO_NAS_EXPORT_PROOF_") or k == "CADUCEUS_NAS_LOCK" for k in os.environ
    ):
        return False
    return _deed.send("sbin", "forgejo-nas-export", outcome == "ok", target="forgejo",
                      outcome=outcome, signal=reason, counts={"file_count": files, "total_bytes": size})


def settings():
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    values = {k: os.environ.get("FORGEJO_NAS_EXPORT_PROOF_" + k) for k in PROOF}
    lock = os.environ.get("CADUCEUS_NAS_LOCK")
    if root is None and not any(v is not None for v in values.values()) and lock is None:
        return {"destination": Path("/mnt/nas/backups/forgejo"), "mount": Path("/mnt/nas"),
                "unit": "forgejo.service", "lock": Path("/run/homeserver-nas-sync.lock"), "proof": False}
    if not root or not lock or not all(values.values()):
        raise Failure("launch-failed", "refused")
    base = Path(root).resolve(strict=True)
    if not Path(root).is_absolute() or base == Path("/"):
        raise Failure("launch-failed", "refused")
    def inside(value):
        p = Path(value)
        if not p.is_absolute() or not p.resolve().is_relative_to(base):
            raise Failure("launch-failed", "refused")
        return p
    if not re.fullmatch(r"forgejo-export-proof-[a-z0-9-]+\.service", values["UNIT"]):
        raise Failure("launch-failed", "refused")
    if values["PG_HOST"] != "127.0.0.1" or not values["PG_PORT"].isdigit() or not 1024 <= int(values["PG_PORT"]) <= 65535:
        raise Failure("launch-failed", "refused")
    return {"destination": inside(values["DESTINATION"]), "mount": inside(values["MOUNT"]),
            "work": inside(values["WORK"]), "unit": values["UNIT"], "lock": inside(lock),
            "pg_host": values["PG_HOST"], "pg_port": values["PG_PORT"], "proof": True, "base": base}


def acquire(cfg):
    if os.geteuid() != 0:
        raise Failure("launch-failed", "refused")
    cfg["lock"].parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(cfg["lock"], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
    s = os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0:
        os.close(fd)
        raise Failure("launch-failed", "refused")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Failure("busy", "refused")
    return fd


def mounted(path):
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        return any(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), line.split()[4]) == str(path.resolve())
                   for line in stream if len(line.split()) >= 5)


def call(args, failure, timeout=None, **kwargs):
    try:
        p = subprocess.run(args, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=False, **kwargs)
        if p.returncode:
            raise Failure(failure)
        return p
    except (OSError, subprocess.TimeoutExpired):
        raise Failure(failure)


def launch():
    try:
        cfg = settings()
        fd = acquire(cfg)
        try:
            if not mounted(cfg["mount"]):
                raise Failure("nas-not-mounted", "refused")
        finally:
            os.close(fd)
        unit = PREFIX + uuid.uuid4().hex
        cmd = ["/usr/bin/systemd-run", "--quiet", "--unit=" + unit, "--property=Type=exec"]
        if cfg["proof"]:
            for key in ("AGATHODAIMON_SCRATCH_ROOT", "CADUCEUS_NAS_LOCK", *("FORGEJO_NAS_EXPORT_PROOF_" + k for k in PROOF)):
                cmd.append("--setenv=" + key + "=" + os.environ[key])
        cmd += ["--", sys.executable, str(Path(__file__).resolve()), "--worker"]
        call(cmd, "launch-failed", timeout=15, stdout=subprocess.DEVNULL)
        return {"ok": True, "status": "accepted", "unit": unit, "firstMissingSignal": "none"}
    except Failure as e:
        deed(e.outcome, PREFIX + e.reason, 0, 0)
        return {"ok": False, "step": "launch", "reason": e.reason, "firstMissingSignal": PREFIX + e.reason}


def config(cfg):
    if cfg["proof"]:
        fragment = call(["/usr/bin/systemctl", "show", cfg["unit"], "--property=FragmentPath", "--value"],
                        "copy-failed", timeout=10, stdout=subprocess.PIPE).stdout.decode().strip()
        if not fragment or not Path(fragment).is_absolute() or not Path(fragment).resolve().is_relative_to(cfg["base"]):
            raise Failure("copy-failed")
        work = cfg["work"]
        ini_path = work / "custom/conf/app.ini"
    else:
        raw = call(["/usr/bin/systemctl", "show", "forgejo.service", "--property=WorkingDirectory", "--property=ExecStart"],
                   "copy-failed", timeout=10, stdout=subprocess.PIPE).stdout.decode()
        match_work = re.search(r"^WorkingDirectory=(.+)$", raw, re.M)
        match_ini = re.search(r"--config\s+([^ ;}]+)", raw)
        if not match_work or not match_ini:
            raise Failure("copy-failed")
        work, ini_path = Path(match_work.group(1)), Path(match_ini.group(1))
    ini = configparser.ConfigParser(interpolation=None, strict=False)
    ini.read_string("[__top__]\n" + ini_path.read_text(encoding="utf-8"))
    configured_work = Path(ini.get("__top__", "WORK_PATH", fallback=str(work)).strip().strip('"'))
    if configured_work != work:
        raise Failure("copy-failed")
    repo = Path(ini.get("repository", "ROOT").strip().strip('"'))
    db = ini.get("database", "NAME").strip()
    kind = ini.get("database", "DB_TYPE").strip().lower()
    host = ini.get("database", "HOST", fallback="127.0.0.1:5432").strip()
    if kind not in ("postgres", "postgresql") or not re.fullmatch(r"[A-Za-z0-9_.-]+", db) or not repo.is_absolute():
        raise Failure("copy-failed")
    if cfg["proof"]:
        if not repo.resolve().is_relative_to(cfg["base"]):
            raise Failure("copy-failed")
        host, port = cfg["pg_host"], cfg["pg_port"]
        data_dir = call(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql",
                         "-X", "-At", "--host", host, "--port", port, "--dbname", db,
                         "--command", "SHOW data_directory"], "copy-failed", timeout=10,
                        stdout=subprocess.PIPE).stdout.decode().strip()
        if not Path(data_dir).is_absolute() or not Path(data_dir).resolve().is_relative_to(cfg["base"]):
            raise Failure("copy-failed")
    else:
        if host not in ("127.0.0.1:5432", "localhost:5432", "/var/run/postgresql", ""):
            raise Failure("copy-failed")
        host, port = "/var/run/postgresql", "5432"
    url = ini.get("server", "ROOT_URL", fallback="http://127.0.0.1:3000/").strip()
    return work, repo, db, host, port, url


def exchange(a, b):
    libc = ctypes.CDLL(None, use_errno=True)
    fn = libc.renameat2
    fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    if fn(-100, os.fsencode(a), -100, os.fsencode(b), 2):
        raise OSError(ctypes.get_errno(), "rename exchange failed")


def worker():
    outcome, reason, files, size = "failed", PREFIX + "launch-failed", 0, 0
    fd, stopped, cfg = None, False, None
    def interrupted(*_):
        raise Failure("copy-failed")
    for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(s, interrupted)
    try:
        cfg = settings()
        fd = acquire(cfg)
        if not mounted(cfg["mount"]):
            raise Failure("nas-not-mounted", "refused")
        work, repo, db, host, port, url = config(cfg)
        base = cfg["destination"]
        base.mkdir(parents=True, exist_ok=True, mode=0o750)
        gid = 0 if cfg["proof"] else grp.getgrnam("git").gr_gid
        os.chown(base, 0, gid)
        os.chmod(base, 0o750)
        old, new = base / "export", base / "export.new"
        if new.exists():
            if new.is_symlink() or not new.is_dir():
                raise Failure("copy-failed")
            shutil.rmtree(new)
        new.mkdir(mode=0o750)
        os.chown(new, 0, gid)
        # The stop may take effect before its caller receives a signal or reply.
        # Arm the restart before asking systemd so that ambiguous stop failures
        # also leave the forge started.
        stopped = True
        call(["/usr/bin/systemctl", "stop", cfg["unit"]], "stop-failed", timeout=60, stdout=subprocess.DEVNULL)
        dump = new / "forgejo.sql"
        with dump.open("xb") as output:
            os.fchmod(output.fileno(), 0o640)
            os.fchown(output.fileno(), 0, gid)
            call(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/pg_dump", "--no-owner", "--format=plain",
                  "--host", host, "--port", port, "--dbname", db], "dump-failed", stdout=output)
        for name, source in (("repositories", repo), ("data", work / "data"), ("custom", work / "custom")):
            if not source.is_dir():
                raise Failure("copy-failed")
            target = new / name
            target.mkdir(mode=0o750)
            args = ["/usr/bin/rsync", "-rlptog", "--chmod=Du=rwx,Dg=rx,Do=,Fu=rw,Fg=r,Fo=", "--chown=0:" + str(gid)]
            reference = old / name
            if reference.is_dir():
                args.append("--link-dest=" + str(reference))
            args += [str(source) + "/", str(target) + "/"]
            call(args, "copy-failed", stdout=subprocess.DEVNULL)
        for path in new.rglob("*"):
            if path.is_file() and not path.is_symlink():
                files += 1
                size += path.stat().st_size
        # Only a successful restart may promote this generation.
        call(["/usr/bin/systemctl", "start", cfg["unit"]], "start-failed", timeout=120, stdout=subprocess.DEVNULL)
        call(["/usr/bin/systemctl", "is-active", "--quiet", cfg["unit"]], "start-failed", timeout=10)
        stopped = False
        if not cfg["proof"]:
            try:
                with build_opener(ProxyHandler({})).open(url, timeout=15) as response:
                    if not 200 <= response.status < 400:
                        raise Failure("start-failed")
            except Exception:
                raise Failure("start-failed")
        marker = new / "complete"
        with marker.open("x", encoding="ascii") as stream:
            os.fchmod(stream.fileno(), 0o640)
            os.fchown(stream.fileno(), 0, gid)
            stream.write(datetime.now(timezone.utc).isoformat().replace("+00:00", "Z") + "\n")
        if old.exists():
            exchange(new, old)
        else:
            os.rename(new, old)
        outcome, reason = "ok", "none"
    except Failure as e:
        outcome, reason = e.outcome, PREFIX + e.reason
    except Exception:
        outcome, reason = "failed", PREFIX + "copy-failed"
    finally:
        if stopped:
            try:
                call(["/usr/bin/systemctl", "start", cfg["unit"]], "start-failed", timeout=120, stdout=subprocess.DEVNULL)
                call(["/usr/bin/systemctl", "is-active", "--quiet", cfg["unit"]], "start-failed", timeout=10)
                if not cfg["proof"]:
                    with build_opener(ProxyHandler({})).open(url, timeout=15) as response:
                        if not 200 <= response.status < 400:
                            raise Failure("start-failed")
            except Exception:
                outcome, reason = "failed", PREFIX + "start-failed"
        deed(outcome, reason, files, size)
        if fd is not None:
            os.close(fd)
    return 0 if outcome == "ok" else 1


if __name__ == "__main__":
    sys.exit(worker())

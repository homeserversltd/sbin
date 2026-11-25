"""Forgejo NAS restore preflight and R3a worker.

This section stops after the second no-stomp gate. It is not a full restore;
it must not be admitted without the remaining restore sections.
"""
from __future__ import annotations

import configparser
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
from agathodaimon import _deed, _envelope, _seat


class SourceError(Exception):
    """A source is absent or cannot be safely interpreted."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _mount_id(fd: int) -> str:
    try:
        with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as stream:
            return next(line.split()[1] for line in stream if line.startswith("mnt_id:"))
    except (OSError, StopIteration, IndexError) as error:
        raise SourceError("source-missing") from error


def _directory(parent: int, name: str, mount_id: str | None = None) -> int:
    """Open the observed directory, not a link substituted after observation."""
    try:
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            raise SourceError("source-missing")
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent)
        after = os.fstat(fd)
        try:
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or (mount_id is not None and _mount_id(fd) != mount_id)):
                raise SourceError("source-missing")
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError as error:
        raise SourceError("source-missing") from error


def _regular(parent: int, name: str, mount_id: str | None = None) -> int:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent)
        try:
            if (not stat.S_ISREG(os.fstat(fd).st_mode)
                    or (mount_id is not None and _mount_id(fd) != mount_id)):
                raise SourceError("source-missing")
            return fd
        except BaseException:
            os.close(fd)
            raise
    except OSError as error:
        raise SourceError("source-missing") from error


def _dump_trailer(fd: int) -> None:
    """Validate pg_dump 17's optional restrict pair and completion trailer.

    The token stays in memory and neither the source nor any output is changed.
    """
    token = None
    unrestrict = 0
    completed = False
    first_content = True
    try:
        with os.fdopen(os.dup(fd), "rb") as stream:
            for raw in stream:
                line = raw.rstrip(b"\r\n")
                stripped = line.strip()
                if first_content and stripped and not stripped.startswith(b"--"):
                    first_content = False
                    match = re.fullmatch(rb"\\restrict[ \t]+([^\s]+)", stripped)
                    if match:
                        token = match.group(1)
                if not completed:
                    if line == b"-- PostgreSQL database dump complete":
                        completed = True
                    continue
                if not stripped or stripped.startswith(b"--"):
                    continue
                match = re.fullmatch(rb"\\unrestrict[ \t]+([^\s]+)", stripped)
                if not match or token is None or match.group(1) != token:
                    raise SourceError("source-invalid")
                unrestrict += 1
                if unrestrict != 1:
                    raise SourceError("source-invalid")
    except OSError as error:
        raise SourceError("source-invalid") from error
    if not completed or (token is not None and unrestrict != 1):
        raise SourceError("source-invalid")


def _database_config(fd: int) -> None:
    try:
        with os.fdopen(os.dup(fd), encoding="utf-8", newline="") as stream:
            text = stream.read()
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.read_string("[__top__]\n" + text)
        section = getattr(parser, "_sections", {}).get("database", {})
        if section.get("user", "").strip().strip('"') != "git" or "passwd" not in section:
            raise SourceError("source-invalid")
    except (OSError, UnicodeError, configparser.Error) as error:
        raise SourceError("source-invalid") from error


def validate_source(mount: str) -> None:
    """Validate the fixed export using only no-follow directory descriptors.

    Caller must retain source descriptors or repeat this validation under the
    synchronization lock before using the source for a destructive restore.
    """
    opened = []
    try:
        if not os.path.isabs(mount) or ".." in mount.split(os.sep):
            raise SourceError("source-missing")
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        opened.append(root)
        for name in [part for part in mount.split(os.sep) if part]:
            root = _directory(root, name)
            opened.append(root)
        mount_id = _mount_id(root)
        # The selected root must itself be a mount, not merely a child of one.
        with open("/proc/self/mountinfo", encoding="utf-8") as mounts:
            if not any(line.split()[0] == mount_id for line in mounts):
                raise SourceError("source-missing")
        parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=root)
        opened.append(parent)
        if _mount_id(parent) == mount_id:
            raise SourceError("source-missing")
        for name in ("backups", "forgejo", "nas", "export"):
            root = _directory(root, name, mount_id)
            opened.append(root)
            if name == "nas":
                info = os.fstat(root)
                if info.st_uid != 0 or info.st_mode & 0o022:
                    raise SourceError("source-missing")
        for name in ("complete", "forgejo.sql"):
            fd = _regular(root, name, mount_id)
            opened.append(fd)
            if name == "forgejo.sql":
                _dump_trailer(fd)
        for name in ("repositories", "data", "custom"):
            child = _directory(root, name, mount_id)
            opened.append(child)
            if name == "custom":
                conf = _directory(child, "conf", mount_id)
                opened.append(conf)
                ini = _regular(conf, "app.ini", mount_id)
                opened.append(ini)
                _database_config(ini)
    except OSError as error:
        raise SourceError("source-missing") from error
    finally:
        for fd in reversed(opened):
            os.close(fd)


PREFIX = "forgejo-nas-restore-"
# Values are read only after the scratch root is present and validated.
PROOF_KEYS = ("MOUNT", "WORK", "LOCK", "UNIT", "PG_PORT", "OS_USER")
INTENT = "storage/backup/forgejo/nas-restore"


class Failure(Exception):
    def __init__(self, reason, count=None):
        self.reason, self.count = reason, count
        super().__init__(reason)


def _inside(base, value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or not path.resolve().is_relative_to(base):
        raise Failure("launch-failed")
    return path


def settings():
    if os.geteuid() != 0:
        raise Failure("launch-failed")
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    if root is None:
        if any(k.startswith("FORGEJO_NAS_RESTORE_PROOF_") for k in os.environ):
            raise Failure("launch-failed")
        return {"proof": False, "mount": Path("/mnt/nas"), "work": Path("/opt/forgejo"),
                "lock": Path("/run/homeserver-nas-sync.lock"), "unit": "forgejo.service",
                "host": "/var/run/postgresql", "port": "5432", "os_user": "postgres",
                "psql": "/opt/homeserver/postgresql/bin/psql"}
    try:
        base = Path(root).resolve(strict=True)
        if not Path(root).is_absolute() or base == Path("/") or ".." in Path(root).parts:
            raise Failure("launch-failed")
        values = {key: os.environ["FORGEJO_NAS_RESTORE_PROOF_" + key] for key in PROOF_KEYS}
        if not re.fullmatch(r"forgejo-restore-proof-[a-z0-9-]+\.service", values["UNIT"]):
            raise Failure("launch-failed")
        if not values["PG_PORT"].isdigit() or not 1024 <= int(values["PG_PORT"]) <= 65535 or int(values["PG_PORT"]) == 5432:
            raise Failure("launch-failed")
        if values["OS_USER"] != "owner":
            raise Failure("launch-failed")
        return {"proof": True, "base": base, "mount": _inside(base, values["MOUNT"]),
                "work": _inside(base, values["WORK"]), "lock": _inside(base, values["LOCK"]),
                "unit": values["UNIT"], "host": "127.0.0.1", "port": values["PG_PORT"],
                "os_user": values["OS_USER"], "psql": "/usr/bin/psql"}
    except (OSError, KeyError, ValueError) as error:
        raise Failure("launch-failed") from error


def acquire(cfg):
    try:
        fd = os.open(cfg["lock"], os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o640)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0:
            os.close(fd)
            raise Failure("launch-failed")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(fd)
            raise Failure("busy") from error
        return fd
    except OSError as error:
        raise Failure("launch-failed") from error


def _run(args, reason, timeout=15):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C", "PGCONNECT_TIMEOUT": "3"})
        if result.returncode:
            raise Failure(reason)
        return result.stdout.decode("utf-8", errors="strict")
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise Failure(reason) from error


def _sql(cfg, database, statement):
    return _run(["/usr/sbin/runuser", "-u", cfg["os_user"], "--", cfg["psql"],
                 "-X", "-qAt", "--no-password", "--host", cfg["host"], "--port", cfg["port"],
                 "--username", "postgres", "--dbname", database, "--command", statement],
                "forge-unobserved")


def _expand_ini_value(parser, section, raw):
    pattern = re.compile(r"%\(([^)]+)\)s")
    value = raw
    for _ in range(10):
        matches = list(pattern.finditer(value))
        if not matches:
            return value
        def replace(match):
            key = match.group(1)
            for candidate in [section, "server", "DEFAULT", *parser.sections()]:
                if candidate == "DEFAULT":
                    found = parser.defaults().get(parser.optionxform(key))
                    if found is not None:
                        return found
                elif parser.has_section(candidate) and parser.has_option(candidate, key):
                    return parser.get(candidate, key, raw=True)
            raise Failure("forge-unobserved")
        value = pattern.sub(replace, value)
    raise Failure("forge-unobserved")


def forge_config(cfg):
    try:
        ini = configparser.ConfigParser(interpolation=None, strict=False)
        ini.read_string("[__top__]\n" + (cfg["work"] / "custom/conf/app.ini").read_text(encoding="utf-8"))
        raw = ini.get("repository", "ROOT", raw=True).strip().strip('"')
        repo = Path(_expand_ini_value(ini, "repository", raw))
        db = ini.get("database", "NAME").strip()
        kind = ini.get("database", "DB_TYPE").strip().lower()
        if not repo.is_absolute() or ".." in repo.parts or kind not in ("postgres", "postgresql") or not re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", db):
            raise Failure("forge-unobserved")
        if cfg["proof"]:
            repo = _inside(cfg["base"], str(repo))
            data_dir = _sql(cfg, "postgres", "SHOW data_directory").strip()
            if not Path(data_dir).is_absolute() or not Path(data_dir).resolve().is_relative_to(cfg["base"]):
                raise Failure("forge-unobserved")
        protocol = ini.get("server", "PROTOCOL", fallback="http").strip().lower()
        address = ini.get("server", "HTTP_ADDR", fallback="0.0.0.0").strip()
        port = ini.get("server", "HTTP_PORT", fallback="3000").strip()
        address = "127.0.0.1" if address in ("", "0.0.0.0", "localhost") else "::1" if address == "::" else address
        ip = ipaddress.ip_address(address)
        if protocol != "http" or not ip.is_loopback or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise Failure("forge-unobserved")
        authority = "[" + str(ip) + "]" if ip.version == 6 else str(ip)
        return repo, db, "http://" + authority + ":" + port + "/api/healthz"
    except Failure:
        raise
    except (OSError, ValueError, configparser.Error, UnicodeError) as error:
        raise Failure("forge-unobserved") from error


def _safe_names():
    try:
        catalogue = _seat.read_intent_seats(_envelope.appliance_runtime_path("seats"))
        if catalogue is None:
            raise Failure("forge-unobserved")
        seat = catalogue[0].get(INTENT)
        if not isinstance(seat, dict):
            raise Failure("forge-unobserved")
        values = seat["known_safe"]["repositories"]
        if not isinstance(values, list) or not values or any(not isinstance(x, str) or x.count("/") != 1 or not all(x.split("/")) or x != x.lower() for x in values):
            raise Failure("forge-unobserved")
        return set(values)
    except (KeyError, TypeError, ValueError, OSError) as error:
        raise Failure("forge-unobserved") from error


def _disk_names(root):
    names = set()
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for part in root.parts[1:]:
                next_fd = _directory(fd, part)
                os.close(fd)
                fd = next_fd
            with os.scandir(fd) as owners:
                for owner in owners:
                    if owner.is_symlink():
                        raise Failure("forge-unobserved")
                    if not owner.is_dir(follow_symlinks=False):
                        continue
                    owner_fd = _directory(fd, owner.name)
                    try:
                        with os.scandir(owner_fd) as repos:
                            for repo in repos:
                                if not repo.name.endswith(".git"):
                                    continue
                                if repo.is_symlink() or not repo.is_dir(follow_symlinks=False):
                                    raise Failure("forge-unobserved")
                                name = repo.name[:-9] if repo.name.endswith(".wiki.git") else repo.name[:-4]
                                if not name:
                                    raise Failure("forge-unobserved")
                                names.add(owner.name.lower() + "/" + name.lower())
                    finally:
                        os.close(owner_fd)
        finally:
            os.close(fd)
        return names
    except (OSError, SourceError, UnicodeError) as error:
        raise Failure("forge-unobserved") from error


def gate(cfg, repo, database):
    safe = _safe_names()
    output = _sql(cfg, database, 'SELECT json_build_array(u.lower_name,r.lower_name)::text FROM repository r LEFT JOIN "user" u ON u.id=r.owner_id')
    names = _disk_names(repo)
    try:
        for line in output.splitlines():
            pair = json.loads(line)
            if not isinstance(pair, list) or len(pair) != 2 or any(not isinstance(x, str) or not x or "/" in x for x in pair):
                raise ValueError("unreadable repository identity")
            names.add(pair[0].lower() + "/" + pair[1].lower())
    except (ValueError, TypeError) as error:
        raise Failure("forge-unobserved") from error
    foreign = names - safe
    if foreign:
        raise Failure("forge-holds-own-work", len(foreign))


def _unit_checked(cfg):
    if not cfg["proof"]:
        return
    info = _run(["/usr/bin/systemctl", "show", cfg["unit"], "--property=FragmentPath",
                 "--property=WorkingDirectory", "--property=ExecStart"], "launch-failed")
    rows = dict(line.split("=", 1) for line in info.splitlines() if "=" in line)
    match = re.search(r"(?:^|[ {;])path=([^ ;}]+)", rows.get("ExecStart", ""))
    if not match:
        raise Failure("launch-failed")
    for value in (rows.get("FragmentPath", ""), rows.get("WorkingDirectory", ""), match.group(1)):
        _inside(cfg["base"], value)


def _systemctl(cfg, action, reason):
    _unit_checked(cfg)
    return _run(["/usr/bin/systemctl", action, cfg["unit"]], reason, timeout=120)


def _active_state(cfg, reason):
    _unit_checked(cfg)
    return _run(["/usr/bin/systemctl", "show", cfg["unit"], "--property=ActiveState", "--value"], reason).strip()


def _proof_listener(cfg, url):
    if not cfg["proof"]:
        return
    _unit_checked(cfg)
    pid = _run(["/usr/bin/systemctl", "show", cfg["unit"], "--property=MainPID", "--value"], "start-failed").strip()
    if not pid.isdigit() or int(pid) <= 1:
        raise Failure("start-failed")
    try:
        inodes = set()
        for fd in Path("/proc", pid, "fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            match = re.fullmatch(r"socket:\[(\d+)\]", target)
            if match:
                inodes.add(match.group(1))
        port = urlsplit(url).port
        for name in ("tcp", "tcp6"):
            with open("/proc/net/" + name, encoding="ascii") as stream:
                next(stream)
                for line in stream:
                    fields = line.split()
                    if len(fields) >= 10 and fields[3] == "0A" and int(fields[1].rsplit(":", 1)[1], 16) == port and fields[9] in inodes:
                        return
    except (OSError, ValueError, IndexError):
        pass
    raise Failure("start-failed")


def _healthy(cfg, url):
    class LocalOnly(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = build_opener(ProxyHandler({}), LocalOnly())
    deadline = time.monotonic() + 15
    while True:
        try:
            _proof_listener(cfg, url)
            with opener.open(url, timeout=2) as response:
                if 200 <= response.status < 300:
                    return
        except (Failure, HTTPError, URLError, OSError, TimeoutError):
            pass
        if time.monotonic() >= deadline:
            raise Failure("start-failed")
        time.sleep(0.1)


def _deed_once(reason, stage=None):
    if not os.environ.get("AGATHODAIMON_SCRATCH_ROOT") and any(k.startswith("FORGEJO_NAS_RESTORE_PROOF_") for k in os.environ):
        return False
    return _deed.send("sbin", "forgejo-nas-restore", reason == "none", target="forgejo",
                      outcome="ok" if reason == "none" else "failed",
                      signal="none" if reason == "none" else PREFIX + reason,
                      stages=[["forge", stage]] if stage else None)


def _answer(error, step):
    result = {"ok": False, "step": step, "reason": error.reason,
              "firstMissingSignal": PREFIX + error.reason}
    if error.reason in ("forge-holds-own-work", "forge-unobserved"):
        result["foreignCount"] = error.count
    return result


def launch():
    cfg = None
    try:
        cfg = settings()
        fd = acquire(cfg)
        try:
            validate_source(str(cfg["mount"]))
            repo, database, _ = forge_config(cfg)
            gate(cfg, repo, database)
            _unit_checked(cfg)
        finally:
            os.close(fd)
        unit = PREFIX + uuid.uuid4().hex
        args = ["/usr/bin/systemd-run", "--quiet", "--unit=" + unit, "--property=Type=exec"]
        if cfg["proof"]:
            for name in ("AGATHODAIMON_SCRATCH_ROOT", *("FORGEJO_NAS_RESTORE_PROOF_" + key for key in PROOF_KEYS)):
                args.append("--setenv=" + name + "=" + os.environ[name])
        args += ["--", sys.executable, str(Path(__file__).resolve()), "--worker"]
        try:
            _run(args, "launch-failed")
        except Failure as error:
            try:
                state = _run(["/usr/bin/systemctl", "show", unit, "--property=LoadState", "--value"], "launch-failed").strip()
            except Failure:
                state = "unknown"
            if state == "not-found":
                _deed_once(error.reason)
            return _answer(error, "launch")
        return {"ok": True, "status": "accepted", "unit": unit, "firstMissingSignal": "none"}
    except SourceError as exc:
        failure = Failure(exc.reason)
    except Failure as exc:
        failure = exc
    except Exception:
        failure = Failure("launch-failed")
    _deed_once(failure.reason)
    return _answer(failure, "preflight")


def worker():
    reason, stage, fd, stopped, cfg, url = "launch-failed", None, None, False, None, None
    try:
        cfg = settings()
        fd = acquire(cfg)
        validate_source(str(cfg["mount"]))
        repo, database, url = forge_config(cfg)
        _unit_checked(cfg)
        stopped = True  # a timed-out stop can have taken effect
        _systemctl(cfg, "stop", "stop-failed")
        if _active_state(cfg, "stop-failed") != "inactive":
            raise Failure("stop-failed")
        gate(cfg, repo, database)
        reason = "none"
        # R3a ends here, deliberately before staging. Do not admit this section alone.
        stopped = False
    except SourceError as error:
        reason = error.reason
    except Failure as error:
        reason = error.reason
    except Exception:
        reason = "launch-failed"
    finally:
        if stopped and cfg is not None and url:
            try:
                _systemctl(cfg, "start", "start-failed")
                if _active_state(cfg, "start-failed") != "active":
                    raise Failure("start-failed")
                _healthy(cfg, url)
            except Exception:
                try:
                    _systemctl(cfg, "stop", "stop-failed")
                    stage = "stopped" if _active_state(cfg, "stop-failed") == "inactive" else "unknown"
                except Exception:
                    stage = "unknown"
        _deed_once(reason, stage)
        if fd is not None:
            os.close(fd)
    return 0 if reason == "none" else 1


if __name__ == "__main__":
    sys.exit(worker())

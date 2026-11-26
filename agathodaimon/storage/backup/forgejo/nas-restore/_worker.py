"""Forgejo NAS restore with post-commit owner and CI adoption."""
from __future__ import annotations

import configparser
import ctypes
import errno
import base64
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import pwd
import grp
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
from agathodaimon import _deed, _envelope, _seat
from agathodaimon.storage.nas import runtime as _nas


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
PROOF_KEYS = ("MOUNT", "WORK", "LOCK", "UNIT", "PG_PORT", "PG_SOCKET", "OS_USER", "SKELETON")
# Optional paths remain confined under AGATHODAIMON_SCRATCH_ROOT.
PROOF_POST_KEYS = ("FORGEJO", "WOODPECKER_ENV", "WOODPECKER_SETUP", "SYSTEMCTL")
# Optional, scratch-only rendezvous: worker creates <PAUSE>.ready and waits for
# <PAUSE>.continue, before removing the staged objects.
PROOF_PAUSE = "FORGEJO_NAS_RESTORE_PROOF_PAUSE"
PROOF_FAULT = "FORGEJO_NAS_RESTORE_PROOF_FAULT"
INTENT = "storage/backup/forgejo/nas-restore"


class Failure(Exception):
    def __init__(self, reason, count=None, kept=()):
        self.reason, self.count, self.kept = reason, count, kept
        super().__init__(reason)


def _inside(base, value):
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or not path.resolve().is_relative_to(base):
        raise Failure("launch-failed")
    return path


def _checkout_fault():
    """A root-owned proof file may fault an uninstalled checkout only."""
    invoked = Path(os.path.abspath(__file__))
    module = invoked.resolve(strict=True)
    if invoked.is_relative_to(Path('/usr/local/sbin')) or module.is_relative_to(Path('/usr/local/sbin')):
        return ''
    checkout = module.parents[5]
    proof = checkout / '.forgejo-nas-restore-fault'
    try:
        fd = os.open(proof, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    except FileNotFoundError:
        return ''
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 32:
            raise Failure('launch-failed')
        value = os.read(fd, 33).decode('ascii').strip()
        if value not in ('start', 'exchange-back', 'inventory-after-stop', 'tree-lookup-error', 'owner-patch-fails'):
            raise Failure('launch-failed')
        return 'start-and-exchange-back' if value == 'exchange-back' else value
    except (OSError, UnicodeError) as error:
        raise Failure('launch-failed') from error
    finally:
        os.close(fd)


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
                "psql": "/opt/homeserver/postgresql/bin/psql", "skeleton": Path("/root/key/skeleton.key"),
                "file_user": "git", "file_group": "git", "pause": None,
                "forgejo": Path("/opt/forgejo/forgejo"),
                "woodpecker_env": Path("/etc/default/woodpecker-server"),
                "woodpecker_setup": Path("/usr/local/sbin/woodpecker-setup.py"),
                "post_systemctl": Path("/usr/bin/systemctl"),
                "fault": _checkout_fault()}
    try:
        base = Path(root).resolve(strict=True)
        scratch = (Path(pwd.getpwnam("owner").pw_dir) / ".hermes/cache/scratch").resolve(strict=True)
        if (not Path(root).is_absolute() or ".." in Path(root).parts
                or base == scratch or not base.is_relative_to(scratch)):
            raise Failure("launch-failed")
        scratch_fd = _open_dir_path(scratch)
        base_fd = _open_dir_path(base)
        try:
            if _mount_id(base_fd) != _mount_id(scratch_fd):
                raise Failure("launch-failed")
        finally:
            os.close(base_fd)
            os.close(scratch_fd)
        values = {key: os.environ["FORGEJO_NAS_RESTORE_PROOF_" + key] for key in PROOF_KEYS}
        if not re.fullmatch(r"forgejo-restore-proof-[a-z0-9-]+\.service", values["UNIT"]):
            raise Failure("launch-failed")
        if not values["PG_PORT"].isdigit() or not 1024 <= int(values["PG_PORT"]) <= 65535 or int(values["PG_PORT"]) == 5432:
            raise Failure("launch-failed")
        if values["OS_USER"] != "owner":
            raise Failure("launch-failed")
        fault = os.environ.get(PROOF_FAULT, "")
        if fault not in ("", "start", "start-and-exchange-back"):
            raise Failure("launch-failed")
        post = {key: _inside(base, os.environ["FORGEJO_NAS_RESTORE_PROOF_" + key])
                for key in PROOF_POST_KEYS if "FORGEJO_NAS_RESTORE_PROOF_" + key in os.environ}
        return {"proof": True, "base": base, "fault": fault, "mount": _inside(base, values["MOUNT"]),
                "work": _inside(base, values["WORK"]), "lock": _inside(base, values["LOCK"]),
                "unit": values["UNIT"], "host": str(_inside(base, values["PG_SOCKET"])), "port": values["PG_PORT"],
                "os_user": values["OS_USER"], "psql": "/usr/bin/psql",
                "skeleton": _inside(base, values["SKELETON"]),
                "forgejo": post.get("FORGEJO", base / "opt/forgejo/forgejo"),
                "woodpecker_env": post.get("WOODPECKER_ENV", base / "etc/default/woodpecker-server"),
                "woodpecker_setup": post.get("WOODPECKER_SETUP", base / "usr/local/sbin/woodpecker-setup.py"),
                "post_systemctl": post.get("SYSTEMCTL", base / "usr/bin/systemctl"),
                "file_user": values["OS_USER"], "file_group": pwd.getpwnam(values["OS_USER"]).pw_gid,
                "pause": _inside(base, os.environ[PROOF_PAUSE]) if PROOF_PAUSE in os.environ else None}
    except (OSError, KeyError, ValueError) as error:
        raise Failure("launch-failed") from error


def require_primary(cfg):
    """Prove the fixed primary role, not merely a mount at its pathname."""
    if cfg["proof"]:
        # The independent source validator checks the actual scratch mount.
        return
    try:
        partition = _nas.role_partition("primary")
        info = _nas._observed_holder_info({}, _nas._info_for("primary", partition))
        mapper = _nas._mapper_state({}, info)
        mount = _nas._mount_readback(info)
        if (mapper.get("exists") is not True or mapper.get("backingMatches") is not True
                or mount.get("mounted") is not True or mount.get("sourceMatches") is not True
                or mount.get("fstype") != "xfs"):
            raise SourceError("source-missing")
    except (OSError, _nas.Refusal) as error:
        raise SourceError("source-missing") from error


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


def _run_raw(args, reason, timeout=15):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, check=False, timeout=timeout,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C", "PGCONNECT_TIMEOUT": "3"})
        if result.returncode:
            raise Failure(reason)
        return bytearray(result.stdout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Failure(reason) from error


def _run(args, reason, timeout=15):
    raw = _run_raw(args, reason, timeout)
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise Failure(reason) from error
    finally:
        raw[:] = b"\0" * len(raw)


def _sql(cfg, database, statement):
    if cfg["proof"]:
        try:
            sock = _inside(cfg["base"], str(Path(cfg["host"]) / (".s.PGSQL." + str(int(cfg["port"])))))
            if not stat.S_ISSOCK(os.lstat(sock).st_mode):
                raise Failure("forge-unobserved")
        except (OSError, ValueError):
            raise Failure("forge-unobserved") from None
    return _run(["/usr/sbin/runuser", "-u", cfg["os_user"], "--", cfg["psql"],
                 "-X", "-v", "ON_ERROR_STOP=1", "-qAt", "--no-password", "--host", cfg["host"], "--port", cfg["port"],
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
        host = ini.get("database", "HOST").strip()
        user = ini.get("database", "USER").strip()
        expected_host = "127.0.0.1:" + (cfg["port"] if cfg["proof"] else "5432")
        configured_work = Path(ini.get("__top__", "WORK_PATH", fallback=str(cfg["work"])).strip().strip('"'))
        if configured_work != cfg["work"] or host != expected_host or user != "git" or db != "forgejo":
            raise Failure("forge-unobserved")
        if not cfg["proof"]:
            unit = _run(["/usr/bin/systemctl", "show", cfg["unit"], "--property=WorkingDirectory", "--property=ExecStart"], "forge-unobserved")
            rows = dict(line.split("=", 1) for line in unit.splitlines() if "=" in line)
            match = re.search(r"--config\s+([^ ;}]+)", rows.get("ExecStart", ""))
            if (rows.get("WorkingDirectory") != str(cfg["work"]) or not match
                    or match.group(1) != str(cfg["work"] / "custom/conf/app.ini")):
                raise Failure("forge-unobserved")
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
    properties = ("FragmentPath", "WorkingDirectory", "ExecCondition", "ExecStartPre",
                  "ExecStart", "ExecStartPost", "ExecReload", "ExecStop", "ExecStopPost")
    info = _run(["/usr/bin/systemctl", "show", cfg["unit"],
                 *("--property=" + name for name in properties)], "launch-failed")
    rows = dict(line.split("=", 1) for line in info.splitlines() if "=" in line)
    paths = re.findall(r"(?:^|[ {;])path=([^ ;}]+)", rows.get("ExecStart", ""))
    if len(paths) != 1:
        raise Failure("launch-failed")
    for value in (rows.get("FragmentPath", ""), rows.get("WorkingDirectory", ""), *paths):
        _inside(cfg["base"], value)
    for name in properties[2:]:
        value = rows.get(name, "")
        commands = re.findall(r"(?:^|[ {;])path=([^ ;}]+)", value)
        if value and not commands:
            raise Failure("launch-failed")
        for command in commands:
            _inside(cfg["base"], command)


def _stop_guard(cfg):
    """Refuse before stop unless the service is the expected notify forge."""
    try:
        _unit_checked(cfg)
    except Failure as error:
        raise Failure("stop-failed") from error
    info = _run(["/usr/bin/systemctl", "show", cfg["unit"],
                 "--property=Type", "--property=ExecStart"], "stop-failed")
    rows = dict(line.split("=", 1) for line in info.splitlines() if "=" in line)
    paths = re.findall(r"(?:^|[ {;])path=([^ ;}]+)", rows.get("ExecStart", ""))
    expected = str(cfg["work"] / "forgejo")
    if rows.get("Type") != "notify" or paths != [expected]:
        raise Failure("stop-failed")


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


def _scratch_deed_listener(base):
    """Do not let a scratch receipt reach a listener outside this bench."""
    try:
        config = _inside(base, str(_envelope.appliance_runtime_path("config")))
        bind = json.loads(config.read_text(encoding="utf-8"))["caduceus"]["bind"]
        parsed = urlsplit(bind if "://" in bind else "http://" + bind)
        port = parsed.port
        if port is None or not 1024 <= port <= 65535:
            return False
        with open("/proc/net/tcp", encoding="ascii") as stream:
            next(stream)
            inodes = {row[9] for line in stream if len(row := line.split()) >= 10
                      and row[1] == f"0100007F:{port:04X}" and row[3] == "0A"}
        if not inodes:
            return False
        for process in Path("/proc").iterdir():
            if not process.name.isdigit():
                continue
            try:
                if not (process / "cwd").resolve(strict=True).is_relative_to(base):
                    continue
                argv = (process / "cmdline").read_bytes().split(b"\0")
                if not any(arg.startswith(os.fsencode(str(base) + "/")) for arg in argv):
                    continue
                for fd in (process / "fd").iterdir():
                    try:
                        target = os.readlink(fd)
                    except OSError:
                        continue
                    match = re.fullmatch(r"socket:\[(\d+)\]", target)
                    if match and match.group(1) in inodes:
                        return True
            except (OSError, ValueError):
                continue
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        pass
    return False


def _deed_once(reason, stage=None, kept=(), *, token_left=False, cleanup_left=()):
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    if root:
        try:
            base = Path(root).resolve(strict=True)
            if not Path(root).is_absolute() or base == Path("/") or not _scratch_deed_listener(base):
                return False
        except (OSError, ValueError):
            return False
    elif any(k.startswith("FORGEJO_NAS_RESTORE_PROOF_") for k in os.environ):
        return False
    # Hyalos projects the target but does not retain arbitrary stage tokens.
    # Keep the contracted copy-failed signal and identify a lookup failure in
    # the stored deed's target instead of relying on a discarded stage.
    target = ("forgejo-restore-token-left" if token_left else
              "forgejo-restore-committed-cleanup-left" if cleanup_left else
              "forgejo-tree-lookup-error" if "tree-lookup-error" in kept else "forgejo")
    return _deed.send("sbin", "forgejo-nas-restore", reason == "none", target=target,
                      outcome="ok" if reason == "none" else "failed",
                      signal="none" if reason == "none" else PREFIX + reason,
                      stages=([["forge", stage]] if stage else []) + [["prior", token] for token in kept])


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
            require_primary(cfg)
            validate_source(str(cfg["mount"]))
            repo, database, _ = forge_config(cfg)
            _check_prior(cfg, repo)
            gate(cfg, repo, database)
            _unit_checked(cfg)
        finally:
            os.close(fd)
        unit = PREFIX + uuid.uuid4().hex
        # Stop signals go to the worker first, not its in-flight child.  Allow
        # the worker time to finish that step and carry out its own unwind.
        args = ["/usr/bin/systemd-run", "--quiet", "--unit=" + unit,
                "--property=Type=exec", "--property=KillMode=mixed",
                "--property=TimeoutStopSec=1h"]
        if cfg["proof"]:
            for name in ("AGATHODAIMON_SCRATCH_ROOT", *("FORGEJO_NAS_RESTORE_PROOF_" + key for key in PROOF_KEYS)):
                args.append("--setenv=" + name + "=" + os.environ[name])
            if PROOF_PAUSE in os.environ:
                args.append("--setenv=" + PROOF_PAUSE + "=" + os.environ[PROOF_PAUSE])
            if PROOF_FAULT in os.environ:
                args.append("--setenv=" + PROOF_FAULT + "=" + os.environ[PROOF_FAULT])
            for key in PROOF_POST_KEYS:
                name = "FORGEJO_NAS_RESTORE_PROOF_" + key
                if name in os.environ:
                    args.append("--setenv=" + name + "=" + os.environ[name])
        args += ["--", sys.executable, os.path.abspath(__file__), "--worker"]
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
    _deed_once(failure.reason, kept=getattr(failure, "kept", ()))
    return _answer(failure, "preflight")


def _open_dir_path(path):
    if not path.is_absolute() or ".." in path.parts:
        raise Failure("copy-failed")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            child = _directory(fd, part)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def _source_fd(cfg):
    root = _open_dir_path(cfg["mount"])
    try:
        mount_id = _mount_id(root)
        for part in ("backups", "forgejo", "nas", "export"):
            child = _directory(root, part, mount_id)
            os.close(root)
            root = child
        return root
    except BaseException:
        os.close(root)
        raise


def _db_command(cfg, statement):
    try:
        return _sql(cfg, "postgres", statement)
    except Failure as error:
        raise Failure("db-failed") from error


def _db_inventory(cfg):
    names = _db_command(cfg, "SELECT datname FROM pg_database WHERE datname IN ('forgejo','forgejo_restore','forgejo_before_restore')")
    return set(names.splitlines())


def _drop_stage_db(cfg):
    _db_command(cfg, 'DROP DATABASE IF EXISTS "forgejo_restore" WITH (FORCE)')


def _staged_paths(cfg, repo):
    paths = [repo.with_name(repo.name + ".restore-staged"),
             cfg["work"] / "data.restore-staged", cfg["work"] / "custom.restore-staged"]
    live = [repo, cfg["work"] / "data", cfg["work"] / "custom"]
    # Refuse overlapping names, including a staged parent of a live tree.
    if len(set(paths)) != len(paths) or any(a == b or a in b.parents or b in a.parents
                                            for a in paths for b in live):
        raise Failure("copy-failed")
    return paths


def _prior_paths(cfg, repo):
    return [repo.with_name(repo.name + ".restore-prior"),
            cfg["work"] / "data.restore-prior", cfg["work"] / "custom.restore-prior"]


def _tree_present(cfg, path, inject=False):
    try:
        if inject and cfg.get("fault") == "tree-lookup-error":
            raise OSError(errno.EIO, "proof lookup failure")
        os.lstat(path)
        return True
    except OSError as error:
        if error.errno == errno.ENOENT:
            return False
        raise Failure("copy-failed", kept=["tree-lookup-error"]) from error


def _prior_tree_tokens(cfg, repo):
    return ["kept-prior-" + name
            for index, (name, path) in enumerate(zip(("repositories", "data", "custom"), _prior_paths(cfg, repo)))
            if _tree_present(cfg, path, inject=index == 0)]


def _kept_prior(cfg, repo, inventory_unreadable=False):
    trees = _prior_tree_tokens(cfg, repo)
    try:
        if inventory_unreadable:
            raise Failure("db-failed")
        names = _db_inventory(cfg)
    except Failure as error:
        error.kept = ["unknown-prior-db"] + trees
        raise
    return (["kept-prior-db"] if "forgejo_before_restore" in names else []) + trees


def _check_prior(cfg, repo, inventory_unreadable=False):
    kept = _kept_prior(cfg, repo, inventory_unreadable)
    if kept:
        error = Failure("db-failed" if "kept-prior-db" in kept else "copy-failed")
        error.kept = kept
        raise error
    # Staged names may be removed, but unknown is not the same as absent.
    for path in _staged_paths(cfg, repo):
        _tree_present(cfg, path)


def _check_destination_mount(cfg, parent):
    if not cfg["proof"]:
        return
    base = _open_dir_path(cfg["base"])
    try:
        if _mount_id(base) != _mount_id(parent):
            raise Failure("copy-failed")
    finally:
        os.close(base)


def _remove_stage_tree(cfg, path):
    parent = _open_dir_path(path.parent)
    try:
        _check_destination_mount(cfg, parent)
        mount_id = _mount_id(parent)
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        def remove_tree(pfd, name):
            child = _directory(pfd, name, mount_id)
            try:
                with os.scandir(child) as entries:
                    for entry in entries:
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            remove_tree(child, entry.name)
                        else:
                            os.unlink(entry.name, dir_fd=child)
                current = os.stat(name, dir_fd=pfd, follow_symlinks=False)
                opened = os.fstat(child)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    raise Failure("copy-failed")
                os.rmdir(name, dir_fd=pfd)
            finally:
                os.close(child)
        remove_tree(parent, path.name)
    finally:
        os.close(parent)


def _load_dump(cfg, source):
    try:
        fd = _regular(source, "forgejo.sql", _mount_id(source))
        try:
            args = ["/usr/sbin/runuser", "-u", cfg["os_user"], "--", cfg["psql"],
                    "-X", "-v", "ON_ERROR_STOP=1", "--no-password", "--host", cfg["host"],
                    "--port", cfg["port"], "--username", "postgres", "--dbname", "forgejo_restore"]
            process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL,
                                       env={"PATH": "/usr/bin:/bin", "LANG": "C", "PGCONNECT_TIMEOUT": "3"})
            try:
                with process.stdin as dest, os.fdopen(fd, "rb", closefd=False) as src:
                    dest.write(b"SET ROLE git;\n")
                    shutil.copyfileobj(src, dest, 1024 * 1024)
                if process.wait(timeout=300) != 0:
                    raise Failure("db-failed")
            except BaseException:
                process.kill()
                process.wait()
                raise
        finally:
            os.close(fd)
    except (OSError, SourceError, subprocess.SubprocessError) as error:
        raise Failure("db-failed") from error


def _copy_tree(cfg, source, name, destination):
    source_dir = _directory(source, name, _mount_id(source))
    parent = _open_dir_path(destination.parent)
    dest_dir = None
    try:
        _check_destination_mount(cfg, parent)
        os.mkdir(destination.name, 0o700, dir_fd=parent)
        dest_dir = _directory(parent, destination.name, _mount_id(parent))
        uid = pwd.getpwnam(cfg["file_user"]).pw_uid
        gid = cfg["file_group"] if isinstance(cfg["file_group"], int) else grp.getgrnam(cfg["file_group"]).gr_gid
        args = ["/usr/bin/rsync", "-rlpt", "--chown=" + str(uid) + ":" + str(gid),
                "/proc/self/fd/" + str(source_dir) + "/", "/proc/self/fd/" + str(dest_dir) + "/"]
        result = subprocess.run(args, pass_fds=(source_dir, dest_dir), stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, check=False)
        if result.returncode:
            raise Failure("copy-failed")
        # -h / physical traversal changes links themselves, never their targets.
        chown = subprocess.run(["/usr/bin/chown", "-R", "-h", str(uid) + ":" + str(gid),
                                "/proc/self/fd/" + str(dest_dir) + "/."],
                               pass_fds=(dest_dir,), stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=300, check=False)
        if chown.returncode:
            raise Failure("copy-failed")
        os.fchown(dest_dir, uid, gid)
        os.fchmod(dest_dir, os.fstat(source_dir).st_mode & 0o777)
    finally:
        if dest_dir is not None:
            os.close(dest_dir)
        os.close(parent)
        os.close(source_dir)


def _rekey_config(cfg, custom):
    skeleton = bytearray()
    parent = None
    temporary = None
    try:
        skfd = os.open(cfg["skeleton"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(skfd, "rb") as src:
            skeleton = bytearray(src.read())
        if skeleton.endswith(b"\n"):
            del skeleton[-1:]
        if b'"""' in skeleton or b"\n" in skeleton or b"\r" in skeleton or b"\0" in skeleton:
            raise Failure("copy-failed")
        parent = _open_dir_path(custom / "conf")
        _check_destination_mount(cfg, parent)
        ini = _regular(parent, "app.ini", _mount_id(parent))
        with os.fdopen(ini, "rb") as src:
            lines = src.read().splitlines(keepends=True)
        section = None
        count = 0
        for i, line in enumerate(lines):
            section_match = re.match(rb"^[ \t]*\[([^]]+)\]", line)
            if section_match:
                section = section_match.group(1).strip().lower()
            if section == b"database":
                match = re.match(rb"^([ \t]*PASSWD[ \t]*[=:][ \t]*).*?(\r\n|\n|\r)?$", line, re.I)
                if match:
                    lines[i] = match.group(1) + b'"""' + skeleton + b'"""' + (match.group(2) or b"")
                    count += 1
        if count != 1:
            raise Failure("copy-failed")
        temporary = ".app.ini.restore-" + uuid.uuid4().hex
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        with os.fdopen(out, "wb") as dst:
            dst.write(b"".join(lines))
            dst.flush()
            os.fchown(dst.fileno(), pwd.getpwnam(cfg["file_user"]).pw_uid,
                      cfg["file_group"] if isinstance(cfg["file_group"], int) else grp.getgrnam(cfg["file_group"]).gr_gid)
            os.fchmod(dst.fileno(), 0o640)
            os.fsync(dst.fileno())
        os.replace(temporary, "app.ini", src_dir_fd=parent, dst_dir_fd=parent)
        temporary = None
    finally:
        skeleton[:] = b"\0" * len(skeleton)
        if parent is not None:
            if temporary is not None:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
            os.close(parent)


def _pause(cfg):
    if cfg["pause"] is None:
        return
    ready = str(cfg["pause"]) + ".ready"
    proceed = str(cfg["pause"]) + ".continue"
    fd = os.open(ready, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    deadline = time.monotonic() + 120
    while not os.path.exists(proceed):
        if time.monotonic() >= deadline:
            raise Failure("launch-failed")
        time.sleep(0.1)


def _move_tree(cfg, source, destination):
    """Move a same-parent tree to an absent name, never replacing a tree."""
    if source.parent != destination.parent:
        raise Failure("copy-failed")
    parent = _open_dir_path(source.parent)
    handle = None
    try:
        _check_destination_mount(cfg, parent)
        handle = _directory(parent, source.name, _mount_id(parent))
        observed = os.stat(source.name, dir_fd=parent, follow_symlinks=False)
        held = os.fstat(handle)
        if (observed.st_dev, observed.st_ino) != (held.st_dev, held.st_ino):
            raise Failure("copy-failed")
        fn = ctypes.CDLL(None, use_errno=True).renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        if fn(parent, os.fsencode(source.name), parent, os.fsencode(destination.name), 1):
            raise Failure("copy-failed")
    except (OSError, SourceError) as error:
        raise Failure("copy-failed") from error
    finally:
        if handle is not None:
            os.close(handle)
        os.close(parent)


def _exchange_trees(cfg, live, staged):
    if live.parent != staged.parent:
        raise Failure("copy-failed")
    parent = _open_dir_path(live.parent)
    opened = []
    try:
        _check_destination_mount(cfg, parent)
        for name in (live.name, staged.name):
            opened.append(_directory(parent, name, _mount_id(parent)))
        for name, handle in zip((live.name, staged.name), opened):
            observed = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(handle)
            if (observed.st_dev, observed.st_ino) != (held.st_dev, held.st_ino):
                raise Failure("copy-failed")
        fn = ctypes.CDLL(None, use_errno=True).renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        if fn(parent, os.fsencode(live.name), parent, os.fsencode(staged.name), 2):
            raise Failure("copy-failed")
    except (OSError, SourceError) as error:
        raise Failure("copy-failed") from error
    finally:
        for handle in opened:
            os.close(handle)
        os.close(parent)


def _forge_request(url, method, path, authorization, payload=None):
    class LocalOnly(HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    parsed = urlsplit(url)
    if parsed.scheme != "http" or not ipaddress.ip_address(parsed.hostname).is_loopback:
        raise Failure("owner-rekey-failed")
    base = f"{parsed.scheme}://{parsed.netloc}"
    data = payload
    request = Request(base + path, data=data, method=method,
                      headers={"Authorization": authorization, "Content-Type": "application/json"})
    with build_opener(ProxyHandler({}), LocalOnly()).open(request, timeout=10) as response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise Failure("owner-rekey-failed")
        return response.status, json.loads(raw) if raw else {}


def _owner_rekey(cfg, url):
    skeleton, token, payload, authorization = bytearray(), bytearray(), bytearray(), bytearray()
    name = "forgejo-restore-" + uuid.uuid4().hex
    owner_id = None
    may_exist = False
    revoked = False
    failed = False
    basic_attempted = False
    try:
        skfd = os.open(cfg["skeleton"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(skfd, "rb") as stream:
            skeleton = bytearray(stream.read(65537))
        while skeleton and skeleton[-1] in (10, 13):
            del skeleton[-1]
        if not skeleton or len(skeleton) > 65536 or b"\0" in skeleton:
            raise Failure("owner-rekey-failed")
        cli = ["/usr/sbin/runuser", "-u", cfg["file_user"], "--", str(cfg["forgejo"]), "admin", "user"]
        opts = ["--config", str(cfg["work"] / "custom/conf/app.ini"), "--work-path", str(cfg["work"])]
        _run(cli + ["must-change-password"] + opts + ["--unset", "owner"], "owner-rekey-failed", timeout=90)
        identity = _sql(cfg, "forgejo", 'SELECT id FROM "user" WHERE lower_name=\'owner\' AND is_admin').strip()
        if not identity.isascii() or not identity.isdecimal() or int(identity) < 1:
            raise Failure("owner-rekey-failed")
        owner_id = int(identity)
        # A timed-out CLI can have created the row before the caller sees it.
        may_exist = True
        token = _run_raw(cli + ["generate-access-token"] + opts +
                         ["--username", "owner", "--token-name", name, "--scopes", "write:admin", "--raw"],
                         "owner-rekey-failed", timeout=90)
        while token and token[-1] in (10, 13):
            del token[-1]
        if not re.fullmatch(rb"[0-9a-f]{40}", token):
            raise Failure("owner-rekey-failed")
        if cfg.get("fault") == "owner-patch-fails":
            raise Failure("owner-rekey-failed")
        authorization.extend(b"token ")
        authorization.extend(token)
        # Python's JSON and HTTP layers make immutable copies which cannot be
        # overwritten; all mutable buffers under our control are wiped below.
        payload.extend(json.dumps({"password": skeleton.decode("utf-8"),
                                   "must_change_password": False}).encode("utf-8"))
        status, user = _forge_request(url, "PATCH", "/api/v1/admin/users/owner", authorization, payload)
        if status != 200 or user.get("login") != "owner":
            raise Failure("owner-rekey-failed")
        authorization[:] = b"\0" * len(authorization)
        authorization.clear()
        authorization.extend(b"Basic ")
        authorization.extend(base64.b64encode(b"owner:" + skeleton))
        basic_attempted = True
        status, _ = _forge_request(url, "DELETE", "/api/v1/users/owner/tokens/" + name, authorization)
        if status != 204:
            raise Failure("owner-rekey-failed")
        revoked = True
    except Exception:
        failed = True
    finally:
        # The PATCH may have reached the server despite a lost response.
        if may_exist and not revoked and not basic_attempted and skeleton:
            try:
                authorization[:] = b"\0" * len(authorization)
                authorization.clear()
                authorization.extend(b"Basic ")
                authorization.extend(base64.b64encode(b"owner:" + skeleton))
                status, _ = _forge_request(url, "DELETE", "/api/v1/users/owner/tokens/" + name, authorization)
                revoked = status == 204
            except Exception:
                pass
        if may_exist and not revoked and owner_id is not None:
            # Name is generated locally from a fixed prefix and UUID hex;
            # owner_id was read as a positive integer before token creation.
            predicate = f"uid={owner_id} AND name='{name}'"
            try:
                _sql(cfg, "forgejo", "DELETE FROM access_token WHERE " + predicate)
            except Exception:
                pass  # a timeout may still have committed; observe separately
            try:
                revoked = _sql(cfg, "forgejo", "SELECT count(*) FROM access_token WHERE " + predicate).strip() == "0"
            except Exception:
                revoked = False
        for value in (skeleton, token, payload, authorization):
            value[:] = b"\0" * len(value)
    if may_exist and not revoked:
        raise Failure("owner-rekey-failed", kept=("token-left",))
    if failed:
        raise Failure("owner-rekey-failed")


def _reset_woodpecker_env(cfg):
    path = cfg["woodpecker_env"]
    parent = _open_dir_path(path.parent)
    fd = None
    original = bytearray()
    rendered = bytearray()
    try:
        fcntl.flock(parent, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd = os.open(path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 65536:
            raise Failure("ci-adopt-failed")
        original = bytearray(os.read(fd, 65537))
        if len(original) > 65536:
            raise Failure("ci-adopt-failed")
        names = (b"WOODPECKER_FORGEJO_CLIENT", b"WOODPECKER_FORGEJO_SECRET")
        counts = {name: 0 for name in names}
        pos = 0
        while pos < len(original):
            newline = original.find(b"\n", pos)
            end = newline + 1 if newline >= 0 else len(original)
            matched = False
            for name in names:
                if original.startswith(name + b"=", pos, end):
                    ending = b"\r\n" if original[end - 2:end] == b"\r\n" else b"\n" if original[end - 1:end] == b"\n" else b""
                    rendered.extend(name + b"=${" + name + b"}" + ending)
                    counts[name] += 1
                    matched = True
                    break
            if not matched:
                rendered.extend(memoryview(original)[pos:end])
            pos = end
        if any(value != 1 for value in counts.values()):
            raise Failure("ci-adopt-failed")
        os.lseek(fd, 0, os.SEEK_SET)
        view = memoryview(rendered)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise Failure("ci-adopt-failed")
            view = view[written:]
        os.ftruncate(fd, len(rendered))
        os.fsync(fd)
    finally:
        original[:] = b"\0" * len(original)
        rendered[:] = b"\0" * len(rendered)
        if fd is not None:
            os.close(fd)
        os.close(parent)


def _adopt_ci(cfg, url):
    try:
        _reset_woodpecker_env(cfg)
        parsed = urlsplit(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        _run([str(cfg["woodpecker_setup"]), "--forgejo-url", base,
              "--env-file", str(cfg["woodpecker_env"]), "--skeleton", str(cfg["skeleton"]),
              "--systemctl", str(cfg["post_systemctl"])], "ci-adopt-failed", timeout=180)
        _run([str(cfg["post_systemctl"]), "restart", "woodpecker-server.service"],
             "ci-adopt-failed", timeout=120)
    except Exception as error:
        raise Failure("ci-adopt-failed") from error


def worker():
    reason, stage, fd, stopped, was_active, cfg, url = "launch-failed", None, None, False, False, None, None
    staged = None
    prior = None
    repo = None
    kept = []
    source = None
    changed_trees = []
    db_may_swap = False
    committed = False
    cleanup_left = []
    token_left = False
    stop_attempted = False
    pending_signal = False

    def defer_signal(_number, _frame):
        nonlocal pending_signal
        pending_signal = True

    def checkpoint():
        if pending_signal:
            raise Failure("launch-failed")

    previous_handlers = {sig: signal.signal(sig, defer_signal)
                         for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        cfg = settings()
        checkpoint()
        fd = acquire(cfg)
        checkpoint()
        require_primary(cfg)
        validate_source(str(cfg["mount"]))
        checkpoint()
        _stop_guard(cfg)
        repo, database, url = forge_config(cfg)
        _check_prior(cfg, repo)
        _stop_guard(cfg)
        checkpoint()
        state = _active_state(cfg, "stop-failed")
        if state not in ("active", "inactive"):
            raise Failure("stop-failed")
        was_active = state == "active"
        stopped = was_active  # a timed-out stop can have taken effect
        stop_attempted = True
        _systemctl(cfg, "stop", "stop-failed")
        checkpoint()
        if _active_state(cfg, "stop-failed") != "inactive":
            raise Failure("stop-failed")
        try:
            _check_prior(cfg, repo, inventory_unreadable=cfg.get("fault") == "inventory-after-stop")
        except Failure as error:
            if any(token in ("kept-prior-db", "kept-prior-repositories",
                             "kept-prior-data", "kept-prior-custom")
                   for token in getattr(error, "kept", ())):
                stopped, stage = False, "stopped"
            raise
        gate(cfg, repo, database)
        checkpoint()
        staged = _staged_paths(cfg, repo)
        prior = _prior_paths(cfg, repo)
        _drop_stage_db(cfg)
        checkpoint()
        try:
            for path in staged:
                _remove_stage_tree(cfg, path)
                checkpoint()
        except Exception as error:
            raise Failure("copy-failed") from error
        _db_command(cfg, 'CREATE DATABASE "forgejo_restore" OWNER "git"')
        checkpoint()
        source = _source_fd(cfg)
        _load_dump(cfg, source)
        checkpoint()
        try:
            for name, path in zip(("repositories", "data", "custom"), staged):
                _copy_tree(cfg, source, name, path)
                checkpoint()
            _rekey_config(cfg, staged[2])
            checkpoint()
        except Exception as error:
            raise Failure("copy-failed") from error
        _pause(cfg)
        checkpoint()
        # After the first ALTER the outcome can be ambiguous on timeout.
        # Inspect the database names during unwind rather than assuming failure
        # means the server did not apply the statement.
        db_may_swap = True
        _db_command(cfg, 'ALTER DATABASE "forgejo" RENAME TO "forgejo_before_restore"')
        checkpoint()
        _db_command(cfg, 'ALTER DATABASE "forgejo_restore" RENAME TO "forgejo"')
        checkpoint()
        for live, path, old in zip((repo, cfg["work"] / "data", cfg["work"] / "custom"), staged, prior):
            _move_tree(cfg, live, old)
            changed_trees.append((live, old, path, False))
            checkpoint()
            _move_tree(cfg, path, live)
            changed_trees[-1] = (live, old, path, True)
            checkpoint()
        if cfg.get("fault") in ("start", "start-and-exchange-back"):
            raise Failure("start-failed")
        _systemctl(cfg, "start", "start-failed")
        checkpoint()
        if _active_state(cfg, "start-failed") != "active":
            raise Failure("start-failed")
        _healthy(cfg, url)
        # The checkpoint and health commit form one boundary: do not accept
        # a signal in the gap as though it arrived after the commit.
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, (signal.SIGTERM, signal.SIGINT))
        try:
            if signal.sigpending().intersection((signal.SIGTERM, signal.SIGINT)):
                raise Failure("launch-failed")
            checkpoint()
            committed = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
        reason = "none"
    except SourceError as error:
        reason = error.reason
    except Failure as error:
        reason = error.reason
        kept = getattr(error, "kept", [])
    except Exception:
        reason = "launch-failed"
    finally:
        if source is not None:
            os.close(source)
        if committed:
            try:
                _db_command(cfg, 'DROP DATABASE "forgejo_before_restore" WITH (FORCE)')
            except Exception:
                cleanup_left.append("forgejo_before_restore")
            if prior is None:
                cleanup_left.append("prior-trees-unknown")
            else:
                for name, path in zip(("repositories", "data", "custom"), prior):
                    try:
                        _remove_stage_tree(cfg, path)
                    except Exception:
                        cleanup_left.append(name + ".restore-prior")
            try:
                _owner_rekey(cfg, url)
            except Failure as error:
                reason = "owner-rekey-failed"
                token_left = "token-left" in error.kept
            except Exception:
                reason = "owner-rekey-failed"
            else:
                try:
                    _adopt_ci(cfg, url)
                except Exception:
                    reason = "ci-adopt-failed"
        else:
            safe_to_reverse = True
            if stop_attempted and (db_may_swap or changed_trees):
                try:
                    _systemctl(cfg, "stop", "stop-failed")
                    if _active_state(cfg, "stop-failed") != "inactive":
                        raise Failure("stop-failed")
                except Exception:
                    safe_to_reverse = False
                    stage = "unknown"
            reversed_all = safe_to_reverse
            if safe_to_reverse and db_may_swap:
                # Attempt both renames independently. Re-observe before each:
                # a failed or timed-out SQL call can have reached PostgreSQL.
                try:
                    names = _db_inventory(cfg)
                    if "forgejo_before_restore" in names and "forgejo" in names:
                        _db_command(cfg, 'ALTER DATABASE "forgejo" RENAME TO "forgejo_restore"')
                except Exception:
                    reversed_all = False
                try:
                    names = _db_inventory(cfg)
                    if "forgejo_before_restore" in names:
                        _db_command(cfg, 'ALTER DATABASE "forgejo_before_restore" RENAME TO "forgejo"')
                    elif "forgejo" not in names:
                        reversed_all = False
                except Exception:
                    reversed_all = False
            unreversed = set()
            if safe_to_reverse:
                for live, old, path, installed in reversed(changed_trees):
                    try:
                        if cfg.get("fault") == "start-and-exchange-back" and not unreversed:
                            raise Failure("copy-failed")
                        if installed:
                            # The live tree is the NAS copy; move it to the
                            # removable staged name before returning the prior.
                            _move_tree(cfg, live, path)
                        _move_tree(cfg, old, live)
                    except Exception:
                        unreversed.add(old)
                        reversed_all = False
            else:
                unreversed = {old for _, old, _, _ in changed_trees}
            if staged is not None and safe_to_reverse:
                try:
                    _drop_stage_db(cfg)
                except Exception:
                    stage = "cleanup-failed"
                for path in staged:
                    if path in unreversed:
                        continue  # this name still holds the prior tree
                    try:
                        _remove_stage_tree(cfg, path)
                    except Exception:
                        stage = "cleanup-failed"
            if stop_attempted and not reversed_all:
                state = "stopped" if safe_to_reverse else "unknown"
                stage = state + "-cleanup-failed" if stage == "cleanup-failed" else state
            elif stopped and cfg is not None and url:
                try:
                    _systemctl(cfg, "start", "start-failed")
                    if _active_state(cfg, "start-failed") != "active":
                        raise Failure("start-failed")
                    _healthy(cfg, url)
                except Exception:
                    try:
                        _systemctl(cfg, "stop", "stop-failed")
                        state = "stopped" if _active_state(cfg, "stop-failed") == "inactive" else "unknown"
                        stage = state + "-cleanup-failed" if stage == "cleanup-failed" else state
                    except Exception:
                        stage = "unknown-cleanup-failed" if stage == "cleanup-failed" else "unknown"
        if cfg is not None and repo is not None:
            lookup_failed = "tree-lookup-error" in kept
            try:
                kept = _kept_prior(cfg, repo)
            except Failure as error:
                # A failed inventory is not evidence the prior DB remains.
                kept = list(error.kept)
            if lookup_failed and "tree-lookup-error" not in kept:
                kept.append("tree-lookup-error")
        _deed_once(reason, stage, kept, token_left=token_left, cleanup_left=cleanup_left)
        if committed and cleanup_left:
            # The caller already received the asynchronous accepted result;
            # this bounded worker stop reports which cleanup was unconfirmed.
            print(json.dumps({"ok": reason == "none", "status": "committed",
                              "reason": "cleanup-unconfirmed:" + ",".join(cleanup_left)},
                             separators=(",", ":")), flush=True)
        if fd is not None:
            os.close(fd)
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    return 0 if reason == "none" else 1


if __name__ == "__main__":
    sys.exit(worker())

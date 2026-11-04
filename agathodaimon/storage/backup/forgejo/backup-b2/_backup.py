"""Back up Forgejo to the bucket's restic repository, excluding selected files."""
from __future__ import annotations

from contextlib import contextmanager, nullcontext
from datetime import datetime, timezone
import configparser
import fcntl
import json
import os
from pathlib import Path
from typing import NoReturn
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit, unquote

# Direct execution by the transient service and dynamic staff loading share a root.
sys.path.insert(0, str(Path(__file__).resolve().parents[5]))
from agathodaimon.storage.backup.backblaze import shared as backblaze

ACTUATOR = "backblaze-forgejo-b2-push"
CONFIG = Path("/etc/appliance/config.json")
APP_INI = Path("/opt/forgejo/custom/conf/app.ini")
WORK = Path("/opt/forgejo")
NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")
UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
UNIT_PREFIX = "forgejo-backup-b2-"
DEADLINE_SECONDS = 3600


class Refusal(Exception):
    def __init__(self, step, reason):
        self.step, self.reason = step, reason
        super().__init__(reason)


def refuse(step, reason) -> NoReturn:
    raise Refusal(step, reason)


def read_config(bucket, path):
    try:
        with path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        row = backblaze.row_for(data, bucket)
        manager = backblaze.manager(row)
        if not manager.get('backblazeBackup', False):
            refuse('config', 'backblaze-backup-disabled')
        normalized = {value.lower() for value in backblaze.normalize_skips(manager.get('skip', []))}
        return row, normalized
    except backblaze.Refusal as error:
        refuse(error.step, error.reason)
    except (OSError, ValueError, KeyError, TypeError):
        refuse('config', 'bucket-not-configured')


def forgejo_paths(ini_path, work):
    try:
        raw = ini_path.read_text(encoding="utf-8")
        ini = configparser.ConfigParser(interpolation=None, strict=False)
        ini.read_string("[__top__]\n" + raw)
        def get(section, key, default=""):
            return ini.get(section, key, raw=True, fallback=default).strip().strip('"')
        data = get("__top__", "APP_DATA_PATH", get("server", "APP_DATA_PATH", str(work / "data")))
        def resolve(value):
            value = value.replace("%(APP_DATA_PATH)s", data).replace("%(app_data_path)s", data)
            if '%(' in value:
                refuse('forgejo-config', 'path-variable-unsupported')
            path = Path(value)
            return path if path.is_absolute() else work / path
        data_path = resolve(data)
        def expand_storage(value):
            expanded = value.replace("%(APP_DATA_PATH)s", str(data_path)).replace("%(app_data_path)s", str(data_path))
            if '%(' in expanded:
                refuse('forgejo-config', 'path-variable-unsupported')
            return expanded
        root = resolve(get("repository", "ROOT", str(data_path / "gitea-repositories")))
        def storage_path(section, name):
            kind = get(section, "STORAGE_TYPE", "") or get("storage." + name, "STORAGE_TYPE", "") or get("storage", "STORAGE_TYPE", "local")
            target = "storage." + kind
            if kind != "local" and get(target, "STORAGE_TYPE", "").lower() != "local":
                refuse("forgejo-config", name + "-storage-not-local")
            base = expand_storage(get(target, "PATH", "") if kind != "local" else get("storage", "PATH", ""))
            specific = expand_storage(get(section, "PATH", "") or get("storage." + name, "PATH", ""))
            if section == "lfs" and not specific:
                specific = expand_storage(get("server", "LFS_CONTENT_PATH", ""))
            if base:
                base_path = Path(base)
                if not base_path.is_absolute():
                    base_path = data_path / base_path
            else:
                base_path = data_path
            if specific:
                candidate = Path(specific)
                return candidate if candidate.is_absolute() else base_path / candidate
            return base_path if kind != 'local' and base else base_path / name
        attachments = storage_path("attachment", "attachments")
        lfs = storage_path("lfs", "lfs")
        archive = storage_path("repo-archive", "repo-archive")
        issue_index = resolve(get("indexer", "ISSUE_INDEXER_PATH", str(data_path / "indexers/issues.bleve")))
        repo_index = resolve(get("indexer", "REPO_INDEXER_PATH", str(data_path / "indexers/repos.bleve")))
        uploads = resolve(get("repository.upload", "TEMP_PATH", str(data_path / "tmp/uploads")))
        local_copy = resolve(get("repository.local", "LOCAL_COPY_PATH", "tmp/local-repo"))
        caches = [archive, issue_index, repo_index, data_path / "tmp", uploads, local_copy]
        db_type = get("database", "DB_TYPE", "sqlite3").lower()
        db_name, db_user = get("database", "NAME"), get("database", "USER")
        host = get("database", "HOST", "127.0.0.1:5432")
        if db_type not in ("postgres", "postgresql") or not NAME.fullmatch(db_name) or not NAME.fullmatch(db_user):
            refuse("forgejo-config", "postgres-configuration-unsupported")
        if host not in ("", "127.0.0.1:5432", "localhost:5432", "/var/run/postgresql"):
            refuse("forgejo-config", "postgres-host-not-local")
        if any(not p.is_absolute() or "\n" in str(p) or "\r" in str(p) for p in (root, data_path, attachments, lfs, *caches)):
            refuse("forgejo-config", "path-invalid")
        protected = (root, data_path, attachments, lfs, work / "custom", ini_path)
        for cache in caches:
            if any(p.resolve().is_relative_to(cache.resolve()) for p in protected):
                refuse("forgejo-config", "cache-overlaps-backup-source")
        return {"root": root, "data": data_path, "attachments": attachments, "lfs": lfs,
                "caches": caches, "custom": work / "custom", "ini": ini_path,
                "database": db_name, "user": db_user}
    except Refusal:
        raise
    except (OSError, UnicodeError, configparser.Error, ValueError):
        refuse("forgejo-config", "app-ini-unavailable")


def database_rows(database):
    query = ("SELECT row_to_json(t) FROM (SELECT "
             "COALESCE((SELECT json_agg(json_build_array(u.lower_name,r.lower_name,r.id)) "
             "FROM repository r JOIN \"user\" u ON u.id=r.owner_id),'[]'::json) AS repos, "
             "COALESCE((SELECT json_agg(json_build_array(a.repo_id,a.uuid, "
             "COALESCE(r.tag_name ~ '^sha-[0-9a-f]{40}$',false))) FROM attachment a "
             "LEFT JOIN release r ON r.id=a.release_id),'[]'::json) AS attachments, "
             "COALESCE((SELECT json_agg(json_build_array(l.repository_id,l.oid)) "
             "FROM lfs_meta_object l),'[]'::json) AS lfs) t")
    try:
        proc = subprocess.run(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1", "-d", database, "-c", query],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12, check=False)
        if proc.returncode:
            refuse("database", "forgejo-inventory-unavailable")
        value = json.loads(proc.stdout)
        if not isinstance(value, dict) or any(not isinstance(value.get(k), list) for k in ('repos', 'attachments', 'lfs')):
            refuse("database", "forgejo-inventory-invalid")
        return value
    except (OSError, ValueError, subprocess.TimeoutExpired):
        refuse("database", "forgejo-inventory-unavailable")


def inventory(paths, skips):
    data = database_rows(paths["database"])
    included, excluded, ids = 0, [], set()
    for row in data["repos"]:
        if not isinstance(row, list) or len(row) != 3:
            refuse("database", "forgejo-inventory-invalid")
        owner, repo, repo_id = row
        if (not isinstance(owner, str) or not isinstance(repo, str) or not NAME.fullmatch(owner)
                or not NAME.fullmatch(repo) or owner in (".", "..") or repo in (".", "..") or type(repo_id) is not int):
            refuse("database", "forgejo-inventory-invalid")
        owner, repo = owner.lower(), repo.lower()
        if owner in skips or owner + "/" + repo in skips:
            excluded.append((owner, repo))
            ids.add(repo_id)
        else:
            included += 1
    uuids, ci_count = set(), 0
    for row in data["attachments"]:
        if (not isinstance(row, list) or len(row) != 3 or
                (row[0] is not None and type(row[0]) is not int) or
                not isinstance(row[1], str) or not UUID.fullmatch(row[1]) or type(row[2]) is not bool):
            refuse("database", "forgejo-attachment-invalid")
        if row[2]:
            ci_count += 1
        if row[0] in ids or row[2]:
            uuids.add(row[1])
    skipped_oids, kept_oids = set(), set()
    for item in data['lfs']:
        if (not isinstance(item, list) or len(item) != 2 or type(item[0]) is not int or
                not isinstance(item[1], str) or not re.fullmatch(r'[0-9a-f]{64}', item[1])):
            refuse('database', 'forgejo-lfs-inventory-invalid')
        (skipped_oids if item[0] in ids else kept_oids).add(item[1])
    lfs_excluded = sorted(skipped_oids - kept_oids)
    shared = len(skipped_oids & kept_oids)
    excluded.sort()
    return included, excluded, sorted(uuids), lfs_excluded, shared, ci_count


def restic_repo(row):
    return "b2:" + row["bucket"] + ":" + row.get("prefix", "")


def plan(bucket, config_path, ini_path, work, *, include_ci_count=False):
    row, skips = read_config(bucket, config_path)
    paths = forgejo_paths(ini_path, work)
    included, excluded, uuids, lfs_excluded, shared, ci_count = inventory(paths, skips)
    result = (row, paths, included, excluded, uuids, lfs_excluded, shared)
    return (*result, ci_count) if include_ci_count else result


def _escaped(path):
    # Restic's exclude file is a line-oriented Go filepath.Match glob.
    return re.sub(r"([\\*?\[\]])", r"\\\1", str(path))


def exclusions(paths, skips, uuids, lfs_oids):
    # Preserve owner-wide exclusions even when an on-disk repository is not
    # represented in PostgreSQL; explicit repo entries likewise stand alone.
    result = []
    for entry in sorted(skips):
        parts = entry.split("/")
        target = paths["root"] / parts[0]
        if len(parts) == 2:
            target /= parts[1] + ".git"
        result.append(_escaped(target))
    result.extend(_escaped(paths["attachments"] / u[0] / u[1] / u) for u in uuids)
    result.extend(_escaped(paths['lfs'] / oid[:2] / oid[2:4] / oid[4:]) for oid in lfs_oids)
    result.extend(_escaped(path) for path in paths['caches'])
    return result


def run_short(args, timeout=5):
    try:
        return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        refuse("launch", "systemd-unavailable")


def launch(bucket):
    if os.geteuid() != 0:
        refuse("launch", "root-required")
    try:
        # A stable existing inode serializes the admission window without a state file.
        with APP_INI.open("rb") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                refuse("launch", "backup-already-active")
            current = run_short(["/usr/bin/systemctl", "list-units", "--all", "--plain", "--no-legend",
                                 "--state=active,activating,reloading,deactivating", UNIT_PREFIX + "*.service"])
            if current.returncode:
                refuse("launch", "systemd-state-unavailable")
            if current.stdout.strip():
                refuse("launch", "backup-already-active")
            unit = UNIT_PREFIX + str(int(time.time()))
            command = ["/usr/bin/systemd-run", "--quiet", "--unit=" + unit, "--property=Type=exec",
                       "--", sys.executable, str(Path(__file__).resolve()), "--worker", bucket]
            launched = run_short(command, timeout=8)
            if launched.returncode:
                refuse("launch", "backup-launch-refused")
            return {"ok": True, "status": "accepted", "unit": unit}
    except OSError:
        refuse("launch", "config-lock-unavailable")


def checked(args, step, **kwargs):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False, **kwargs)
    except OSError:
        refuse(step, step + "-unavailable")
    if result.returncode:
        refuse(step, step + "-failed")
    return result


@contextmanager
def backup_child(args, **kwargs):
    # Do not deliver an interruption between fork and recording its group.
    signals = {signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
    child = None
    try:
        child = subprocess.Popen(args, start_new_session=True,
                                 preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, previous),
                                 **kwargs)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        yield child
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            if child.stdout is not None:
                child.stdout.close()
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def prepare_repository(row, env, application_key):
    # Repository preparation may launch restic too: supervise its whole group.
    watched = {signal.SIGALRM, signal.SIGTERM, signal.SIGINT, signal.SIGHUP}
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, watched)
    reader, writer = os.pipe()
    pid = None
    try:
        pid = os.fork()
        if pid == 0:
            try:
                os.close(reader)
                os.setpgid(0, 0)
                signal.pthread_sigmask(signal.SIG_SETMASK, previous)
                try:
                    backblaze.ensure_repository(row, env, application_key)
                    result = ["ok"]
                except backblaze.Refusal as error:
                    result = ["refused", error.step, error.reason]
                os.write(writer, json.dumps(result).encode("utf-8"))
            finally:
                os._exit(0)
        os.close(writer)
        writer = None
        try:
            os.setpgid(pid, pid)
        except (PermissionError, ProcessLookupError):
            pass  # The child established its group or already exited.
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        data = os.read(reader, 4096)
        _, status = os.waitpid(pid, 0)
        if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0 or not data:
            refuse("restic", "restic-repository-unavailable")
        result = json.loads(data)
        if result != ["ok"]:
            if isinstance(result, list) and len(result) == 3 and result[0] == "refused":
                refuse(result[1], result[2])
            refuse("restic", "restic-repository-unavailable")
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, watched)
        if writer is not None:
            os.close(writer)
        os.close(reader)
        if pid:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def capture_restic_error(stream, env, application_key, result):
    """Drain stderr concurrently, redact before retaining a bounded line tail."""
    values = [bytes(application_key)]
    for key in ("B2_ACCOUNT_ID", "B2_ACCOUNT_KEY", "RESTIC_PASSWORD", "RESTIC_REPOSITORY"):
        if env.get(key):
            values.append(env[key].encode())
    repo = env.get("RESTIC_REPOSITORY", "")
    try:
        url = urlsplit(repo)
        for part in (url.username, url.password):
            if part:
                values.extend((part.encode(), unquote(part).encode()))
    except ValueError:
        pass
    values = sorted({v for v in values if v}, key=len, reverse=True)
    hold = max((len(v) for v in values), default=1)
    pending = b""
    line = bytearray()
    last = b""
    def emit(data):
        nonlocal last
        for c in data:
            if c in (10, 13):
                if bytes(line).strip():
                    last = bytes(line)
                line.clear()
            else:
                line.append(c)
                if len(line) > 400:
                    del line[:-400]
    while True:
        chunk = stream.read(4096)
        if not chunk:
            break
        pending += chunk
        while len(pending) >= hold:
            match = next((v for v in values if pending.startswith(v)), None)
            if match:
                emit(b"[scrubbed]")
                pending = pending[len(match):]
            else:
                emit(pending[:1])
                pending = pending[1:]
    while pending:
        match = next((v for v in values if pending.startswith(v)), None)
        if match:
            emit(b"[scrubbed]")
            pending = pending[len(match):]
        else:
            emit(pending[:1])
            pending = pending[1:]
    if bytes(line).strip():
        last = bytes(line)
    result.append(last.decode("utf-8", errors="replace"))


def log_deed(bucket, started, outcome, included, excluded, snapshot, failure, byte_counts, ci_count, restic_error):
    record = {"who": "agathodaimon", "verb": ACTUATOR, "bucket": bucket, "outcome": outcome,
              "duration_ms": int((time.monotonic() - started) * 1000), "included": included,
              "excluded": excluded, "snapshot": snapshot, "signal": failure,
              "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "excludedCiReleaseAttachments": ci_count, **byte_counts}
    if outcome != "ok" and restic_error:
        record["restic_error"] = restic_error
    line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    while len(line.encode()) + 1 >= 1024 and record.get("restic_error"):
        record["restic_error"] = record["restic_error"][1:]
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
    if len(line.encode()) + 1 >= 1024:
        print("forgejo-backup-deed-too-large", file=sys.stderr)
        return False
    try:
        with open("/var/log/appliance/appliance.log", "a", encoding="utf-8") as stream:
            stream.write(line + "\n")
        return True
    except OSError:
        print("forgejo-backup-deed-write-failed", file=sys.stderr)
        return False


def backup(bucket):
    started = time.monotonic()
    included, excluded, snapshot, failure, outcome = 0, [], "", "none", "failed"
    byte_counts = {}
    ci_count, restic_error = 0, ""
    restart_required = False
    operation_lock = None
    config_lock = None
    tmp_context = None
    secrets = []
    deed_ok = True
    try:
        deadline_seconds = min(DEADLINE_SECONDS, max(1, int(os.environ.get("FORGEJO_BACKUP_DEADLINE_SECONDS", DEADLINE_SECONDS))))
    except ValueError:
        deadline_seconds = DEADLINE_SECONDS
    def interrupted(signum, _frame):
        raise Refusal("signal", "interrupted-" + str(signum))
    def deadline(_signum, _frame):
        raise Refusal("deadline", "forgejo-backup-deadline")
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    signal.signal(signal.SIGALRM, deadline)
    try:
        signal.alarm(deadline_seconds)
        lock_path = backblaze.config_lock_path()
        config_lock = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        fcntl.flock(config_lock, fcntl.LOCK_SH)
        try:
            row, skips = read_config(bucket, CONFIG)
        finally:
            os.close(config_lock)
            config_lock = None
        paths = forgejo_paths(APP_INI, WORK)
        operation_lock = APP_INI.open('rb')
        fcntl.flock(operation_lock, fcntl.LOCK_EX)
        try:
            env, application_key = backblaze.restic_environment(row)
            secrets.append(application_key)
            prepare_repository(row, env, application_key)
        except backblaze.Refusal as error:
            refuse(error.step, error.reason)
        tmp_context = tempfile.TemporaryDirectory(prefix="forgejo-backup-b2-")
        with nullcontext(tmp_context.name) as tmp:
            temporary = Path(tmp)
            dump = temporary / "forgejo.pg_dump"
            restart_required = True
            checked(["/usr/bin/systemctl", "stop", "forgejo.service"], "forgejo-stop", stdout=subprocess.DEVNULL)
            included, excluded, uuids, lfs_oids, _shared, ci_count = inventory(paths, skips)
            exclude_file = temporary / "exclude"
            exclude_file.write_text("".join(p + "\n" for p in exclusions(paths, skips, uuids, lfs_oids)), encoding="utf-8")
            with dump.open("wb") as stream:
                with backup_child(["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/pg_dump", "--format=custom", "--no-owner", "--dbname", paths["database"]], stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.DEVNULL) as child:
                    if child.wait() != 0:
                        refuse("pg-dump", "pg-dump-failed")
            source_paths = [dump, paths["data"], paths["attachments"], paths["custom"], paths["ini"], paths["root"]]
            if paths['lfs'].exists():
                source_paths.append(paths['lfs'])
            sources = list(dict.fromkeys(str(p) for p in source_paths))
            try:
                with backup_child(["/usr/bin/restic", "--no-cache", "backup", "--json", "--tag", "forgejo",
                                          "--exclude-file", str(exclude_file), "--", *sources], env=env,
                                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                    assert child.stdout is not None and child.stderr is not None
                    captured = []
                    reader = threading.Thread(target=capture_restic_error, args=(child.stderr, env, application_key, captured), daemon=True)
                    reader.start()
                    for line in child.stdout:
                        try:
                            message = json.loads(line)
                        except ValueError:
                            continue
                        if isinstance(message, dict) and message.get("message_type") == "summary":
                            backblaze.add_counts(byte_counts, backblaze.summary_counts(message))
                            value = message.get("snapshot_id")
                            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{8,64}", value):
                                snapshot = value
                    status = child.wait()
                    reader.join()
                    if status != 0 or not snapshot:
                        restic_error = captured[0] if captured else ""
                        refuse("restic-backup", "restic-backup-failed")
            except OSError:
                refuse("restic-backup", "restic-unavailable")
            outcome = "ok"
    except Refusal as error:
        failure = error.reason
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError):
        failure = "backup-internal-failure"
    finally:
        # Once stopping was attempted, further ordinary termination signals must
        # not interrupt the mandatory restart or the final deed.
        signal.alarm(0)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGALRM):
            signal.signal(sig, signal.SIG_IGN)
        deed_written = False
        if failure == "forgejo-backup-deadline":
            deed_written = True
            deed_ok = log_deed(bucket, started, outcome, included, len(excluded), snapshot, failure, byte_counts, ci_count, restic_error)
        if restart_required:
            try:
                restarted = subprocess.run(["/usr/bin/systemctl", "start", "forgejo.service"], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                if restarted.returncode:
                    outcome, failure = "failed", "forgejo-start-failed"
            except OSError:
                outcome, failure = "failed", "forgejo-start-failed"
        if tmp_context is not None:
            try:
                tmp_context.cleanup()
            except OSError:
                outcome, failure = "failed", "temporary-cleanup-failed"
        for secret in secrets:
            secret[:] = b"\0" * len(secret)
        if operation_lock is not None:
            operation_lock.close()
        if config_lock is not None:
            os.close(config_lock)
        if not deed_written:
            deed_ok = log_deed(bucket, started, outcome, included, len(excluded), snapshot, failure, byte_counts, ci_count, restic_error)
        if not deed_ok:
            outcome = "failed"
    print(json.dumps({"ok": outcome == "ok", "signal": failure, "deadline_seconds": deadline_seconds, "deed_ok": deed_ok, **byte_counts}, separators=(",", ":")))
    return 0 if outcome == "ok" else 1



if __name__ == "__main__":
    args = list(sys.argv[1:])
    if len(args) == 2 and args[0] == "--worker" and backblaze.valid_bucket(args[1]):
        if os.environ.get("BACKBLAZE_SCRATCH_ROOT"):
            raise SystemExit(1)
        raise SystemExit(backup(args[1]))
    print(json.dumps({"ok": False, "step": "shape", "reason": "request-invalid"}, separators=(",", ":")))
    raise SystemExit(1)

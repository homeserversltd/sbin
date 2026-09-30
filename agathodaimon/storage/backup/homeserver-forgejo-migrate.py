#!/usr/bin/env python3
"""
HOMESERVER Forgejo backup and restore (migrate) CLI.

Full-instance export: stop forgejo, pg_dump database forgejo, forgejo dump as git user,
then start forgejo. Output: DB dump SQL + Forgejo dump zip in --output-dir.

Full-instance restore: validate the dump before stopping forgejo, ensure the database role
from the dump's app.ini is ready, restore PostgreSQL, extract the Forgejo dump into its work
directory and configured repository root, chown restored files to git, regenerate hooks and
keys, start forgejo, then report the optional doctor result.

restore-from-b2: download encrypted forgejo backup (zip + sql) from a Backblaze B2 bucket,
decrypt with skeleton key (FAK), then restore. Same encryption as Backblaze tab (salt
backblazetab_forgejo_backup_salt). Requires b2sdk and cryptography (script bootstraps
a venv on first use if needed).

Export and restore require root/sudo; file-only preflight does not.
"""

from __future__ import annotations

import argparse
import configparser
import logging
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import venv
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Optional

# Bootstrap b2sdk/cryptography when restore-from-b2 or restore-from-encrypted is used (reuse disaster-recovery venv)
if "restore-from-b2" in sys.argv or "restore-from-encrypted" in sys.argv:
    try:
        from b2sdk.v2 import B2Api, InMemoryAccountInfo
        from cryptography.fernet import Fernet, InvalidToken
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        _venv_base = Path.home() / ".local" / "share" / "homeserver-backblaze-recovery"
        _venv_path = _venv_base / "venv"
        _venv_path.mkdir(parents=True, exist_ok=True)
        _py = _venv_path / "bin" / "python3"
        if not _py.exists():
            venv.create(_venv_path, with_pip=True)
        _pip = _venv_path / "bin" / "pip"
        subprocess.run(
            [str(_pip), "install", "--quiet", "b2sdk>=2.0.0", "cryptography>=41.0.0"],
            check=True,
        )
        os.execv(str(_py), [str(_py)] + sys.argv)

import base64

logger = logging.getLogger("forgejo_migrate")

# Fixed paths (bare-metal Forgejo install)
FORGEJO_BINARY = "/opt/forgejo/forgejo"
FORGEJO_CONFIG = "/opt/forgejo/custom/conf/app.ini"
FORGEJO_WORK_DIR = "/opt/forgejo"
FORGEJO_USER = "git"
FORGEJO_DB_NAME = "forgejo"
SYSTEMCTL = "/usr/bin/systemctl"
PG_DUMP = "/usr/bin/pg_dump"
PSQL = "/usr/bin/psql"
CHOWN = "/usr/bin/chown"
SERVICE_NAME = "forgejo"

# Salt for FAK-derived encryption of Forgejo backups in B2 (must match Backblaze tab / export_backblaze_fak)
FORGEJO_BACKUP_SALT = b"backblazetab_forgejo_backup_salt"


class RestorePreflightError(Exception):
    """A safe, user-facing reason why a restore cannot proceed."""


@dataclass(frozen=True)
class _RestorePlan:
    zip_path: Path
    sql_path: Path
    app_ini: bytes = field(repr=False)
    database_user: str
    database_password: Optional[str] = field(repr=False)
    repository_root: Path


def _sql_identifier(value: str) -> str:
    if not value or "\x00" in value or len(value.encode("utf-8")) > 63:
        raise RestorePreflightError("dump app.ini [database] USER is not a valid PostgreSQL role name")
    return '"' + value.replace('"', '""') + '"'


def _sql_literal(value: str) -> str:
    if "\x00" in value:
        raise RestorePreflightError("dump app.ini [database] PASSWD contains an unsupported NUL byte")
    return "'" + value.replace("'", "''") + "'"


def _expand_ini_value(parser: configparser.ConfigParser, section: str, raw: str) -> str:
    """Expand Forgejo-style %(name)s values across app.ini sections."""
    pattern = re.compile(r"%\(([^)]+)\)s")
    value = raw
    for _ in range(10):
        matches = list(pattern.finditer(value))
        if not matches:
            return value

        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            candidates = [section, "server", "DEFAULT", *parser.sections()]
            for candidate in candidates:
                if candidate == "DEFAULT":
                    found = parser.defaults().get(parser.optionxform(key))
                    if found is not None:
                        return found
                elif parser.has_section(candidate) and parser.has_option(candidate, key):
                    return parser.get(candidate, key, raw=True)
            raise RestorePreflightError(
                f"dump app.ini [repository] ROOT has an unresolved value: {key}"
            )

        value = pattern.sub(replace, value)
    raise RestorePreflightError("dump app.ini [repository] ROOT interpolation is recursive")


def _reject_symlink_components(path: Path, description: str) -> None:
    """Reject existing symlinks in a destination path without resolving through them."""
    candidate = Path(os.path.abspath(path))
    current = Path(candidate.anchor)
    for index, component in enumerate(candidate.parts[1:], start=1):
        current /= component
        try:
            component_stat = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise RestorePreflightError(
                f"{description} could not be inspected at {current}"
            ) from exc
        if stat.S_ISLNK(component_stat.st_mode):
            raise RestorePreflightError(
                f"{description} contains a symlink path component: {current}"
            )
        if index < len(candidate.parts) - 1 and not stat.S_ISDIR(component_stat.st_mode):
            raise RestorePreflightError(
                f"{description} has a non-directory path component: {current}"
            )


def _repository_root_from_app_ini(parser: configparser.ConfigParser) -> Path:
    default_root = "/opt/forgejo/repositories"
    try:
        raw_root = (
            parser.get("repository", "root", raw=True)
            if parser.has_section("repository") and parser.has_option("repository", "root")
            else default_root
        )
        root = _expand_ini_value(parser, "repository", raw_root).strip()
    except (configparser.Error, ValueError) as exc:
        raise RestorePreflightError("dump app.ini [repository] ROOT could not be read") from exc
    if not root:
        raise RestorePreflightError("dump app.ini [repository] ROOT is empty")

    root_path = Path(root)
    if not root_path.is_absolute():
        root_path = Path(FORGEJO_WORK_DIR) / root_path
    root_path = Path(os.path.abspath(root_path))
    work_dir = Path(os.path.abspath(FORGEJO_WORK_DIR))
    config_path = Path(os.path.abspath(FORGEJO_CONFIG))
    _reject_symlink_components(root_path, "dump app.ini [repository] ROOT")
    if root_path == Path(root_path.anchor) or root_path == work_dir or work_dir.is_relative_to(root_path):
        raise RestorePreflightError("dump app.ini [repository] ROOT would replace the Forgejo work directory or an ancestor")
    if root_path == config_path or config_path.is_relative_to(root_path):
        raise RestorePreflightError("dump app.ini [repository] ROOT would replace the installed Forgejo config")
    return root_path


def _file_preflight(dump_zip: str | Path, db_dump: str | Path) -> _RestorePlan:
    zip_path = Path(dump_zip)
    sql_path = Path(db_dump)
    if not zip_path.exists() or not zip_path.is_file():
        raise RestorePreflightError(f"dump zip does not exist or is not a file: {zip_path}")
    if not sql_path.exists() or not sql_path.is_file():
        raise RestorePreflightError(f"DB dump does not exist or is not a file: {sql_path}")
    try:
        with sql_path.open("rb") as sql_file:
            sql_file.read(1)
    except OSError as exc:
        raise RestorePreflightError(f"DB dump is not readable by the restore loader: {sql_path}") from exc

    work_dir = Path(os.path.abspath(FORGEJO_WORK_DIR))
    _reject_symlink_components(work_dir, "Forgejo archive extraction destination")
    _reject_symlink_components(Path(FORGEJO_CONFIG), "Forgejo config destination")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            names: set[str] = set()
            for info in infos:
                name = info.filename
                member_path = PurePosixPath(name)
                if (
                    not name
                    or "\x00" in name
                    or "\\" in name
                    or name.startswith("/")
                    or re.match(r"^[A-Za-z]:", name)
                    or any(part in (".", "..") for part in name.split("/"))
                    or member_path.is_absolute()
                ):
                    raise RestorePreflightError("dump zip contains an unsafe member path")
                destination = work_dir.joinpath(*member_path.parts)
                _reject_symlink_components(
                    destination, "Forgejo archive extraction destination"
                )
                if name in names:
                    raise RestorePreflightError("dump zip contains duplicate member paths")
                names.add(name)

            for required_dir in ("repos/", "custom/"):
                if not any(
                    info.filename == required_dir or info.filename.startswith(required_dir)
                    for info in infos
                ):
                    raise RestorePreflightError(f"dump zip is missing required {required_dir} content")

            app_ini_info = next((info for info in infos if info.filename == "app.ini"), None)
            if app_ini_info is None or app_ini_info.is_dir():
                raise RestorePreflightError("dump zip is missing its top-level app.ini")
            if stat.S_ISLNK((app_ini_info.external_attr >> 16) & 0xFFFF):
                raise RestorePreflightError("dump zip top-level app.ini is not a regular file")

            bad_member = zf.testzip()
            if bad_member is not None:
                raise RestorePreflightError(f"dump zip member failed its integrity check: {bad_member}")
            app_ini = zf.read(app_ini_info)
    except RestorePreflightError:
        raise
    except Exception as exc:
        raise RestorePreflightError("dump zip could not be opened or read completely") from exc

    try:
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(app_ini.decode("utf-8-sig"))
        database_user = parser.get("database", "user", raw=True).strip()
        database_password = parser.get("database", "passwd", raw=True, fallback=None)
        if database_password is not None:
            _sql_literal(database_password)
    except (UnicodeDecodeError, configparser.Error, ValueError) as exc:
        raise RestorePreflightError("dump top-level app.ini is invalid or lacks [database] USER") from exc
    _sql_identifier(database_user)
    repository_root = _repository_root_from_app_ini(parser)
    return _RestorePlan(
        zip_path=zip_path,
        sql_path=sql_path,
        app_ini=app_ini,
        database_user=database_user,
        database_password=database_password,
        repository_root=repository_root,
    )


def _postgres_command(database: str) -> list[str]:
    return [
        "/usr/bin/sudo",
        "-u",
        "postgres",
        PSQL,
        "-X",
        "-q",
        "-A",
        "-t",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        database,
    ]


def _run_postgres_query(script: str, description: str) -> Optional[str]:
    logger.info("Running: %s", description)
    try:
        result = subprocess.run(
            _postgres_command("postgres") + ["-F", "|"],
            input=script,
            capture_output=True,
            text=True,
        )
    except OSError:
        logger.error("%s could not be run", description)
        return None
    if result.returncode != 0:
        logger.error("%s failed (exit %s; output suppressed)", description, result.returncode)
        return None
    return result.stdout.strip()


def _role_status(database_user: str) -> tuple[Optional[str], bool]:
    user_literal = _sql_literal(database_user)
    script = f"""SET standard_conforming_strings = on;
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = {user_literal}) THEN 'missing'
    WHEN EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = {user_literal}
          AND rolcanlogin
          AND (rolvaliduntil IS NULL OR rolvaliduntil > CURRENT_TIMESTAMP)
    ) THEN 'ready'
    ELSE 'unready'
END || '|' || CASE
    WHEN EXISTS (
        SELECT 1 FROM pg_roles
        WHERE rolname = current_user AND (rolsuper OR rolcreaterole)
    ) THEN 'yes'
    ELSE 'no'
END;
"""
    output = _run_postgres_query(script, "query Forgejo database role readiness")
    if output is None:
        return None, False
    parts = output.split("|", 1)
    if len(parts) != 2 or parts[0] not in {"missing", "ready", "unready"}:
        logger.error("query Forgejo database role readiness returned an invalid result")
        return None, False
    return parts[0], parts[1] == "yes"


def _run_postgres_script(script: str, description: str) -> bool:
    logger.info("Running: %s", description)
    try:
        result = subprocess.run(
            _postgres_command("postgres"),
            input=script,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        logger.error("%s could not be run", description)
        return False
    if result.returncode != 0:
        logger.error("%s failed (exit %s; output suppressed)", description, result.returncode)
        return False
    logger.info("%s succeeded", description)
    return True


def _run_postgres_dump(sql_path: Path) -> bool:
    description = "restore Postgres from dump"
    logger.info("Running: %s", description)
    try:
        # Open as this process and pass the descriptor to psql; postgres need not
        # open or have filesystem permissions on the dump path.
        with sql_path.open("rb") as sql_file:
            result = subprocess.run(
                _postgres_command(FORGEJO_DB_NAME),
                stdin=sql_file,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except OSError:
        logger.error("%s failed because the SQL dump could not be opened", description)
        return False
    if result.returncode != 0:
        logger.error("%s failed (exit %s; output suppressed)", description, result.returncode)
        return False
    logger.info("%s succeeded", description)
    return True


def _run_checked_silent(
    cmd: list[str],
    description: str,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> bool:
    logger.info("Running: %s", description)
    try:
        result = subprocess.run(
            cmd,
            env=env,
            cwd=cwd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except OSError:
        logger.error("%s could not be run", description)
        return False
    if result.returncode != 0:
        logger.error("%s failed (exit %s; output suppressed)", description, result.returncode)
        return False
    logger.info("%s succeeded", description)
    return True


def _restart_after_pre_destructive_failure(step: str) -> int:
    logger.error("Restore failed during %s before database replacement; no database drop was attempted.", step)
    if _start_forgejo():
        logger.info("Forgejo was restarted after the pre-destructive restore failure.")
    else:
        logger.error("Forgejo was not confirmed running after the restore failure; inspect or start it manually.")
    return 1


def _fail_after_destructive(step: str) -> int:
    logger.error(
        "Restore failed during %s after destructive work began; Forgejo was not restarted and remains stopped.",
        step,
    )
    return 1


def _position_repositories(plan: _RestorePlan) -> None:
    source = Path(FORGEJO_WORK_DIR) / "repos"
    target = plan.repository_root
    _reject_symlink_components(target, "configured repository ROOT")
    if source.resolve(strict=False) == target:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    shutil.move(str(source), str(target))


def _require_root() -> None:
    if os.geteuid() != 0:
        logger.error("This script must be run as root (e.g. sudo)")
        sys.exit(1)


def _run(
    cmd: list[str],
    env: Optional[dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        env=env,
        cwd=cwd,
        capture_output=True,
        text=True,
    )


def _run_log(
    cmd: list[str],
    description: str,
    env: Optional[dict[str, str]] = None,
    cwd: Optional[str] = None,
) -> bool:
    logger.info("Running: %s", description)
    try:
        result = _run(cmd, env=env, cwd=cwd)
    except OSError as exc:
        logger.error("%s could not be run: %s", description, exc)
        return False
    if result.returncode != 0:
        logger.error(
            "%s failed (exit %s): %s",
            description,
            result.returncode,
            (result.stderr or result.stdout or "").strip() or "(no output)",
        )
        return False
    logger.info("%s succeeded", description)
    return True


def _stop_forgejo() -> bool:
    return _run_log([SYSTEMCTL, "stop", SERVICE_NAME], "stop forgejo service")


def _start_forgejo() -> bool:
    return _run_log([SYSTEMCTL, "start", SERVICE_NAME], "start forgejo service")


def _derive_fernet_from_skeleton(skeleton_key: str, salt: bytes) -> "Fernet":
    """Derive a Fernet key from skeleton key (FAK) using PBKDF2; same as Backblaze tab."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(skeleton_key.encode()))
    return Fernet(key)


def _decrypt_forgejo_backup_file(enc_path: Path, out_path: Path, fernet: "Fernet") -> None:
    """Decrypt backup file; supports chunked format (4-byte len + token per chunk) and legacy whole-file."""
    with open(enc_path, "rb") as f:
        first4 = f.read(4)
    if len(first4) < 4:
        raise InvalidToken("File too short")
    chunk_len = struct.unpack(">I", first4)[0]
    # Chunked format uses reasonable chunk sizes (100 B to ~50 MB)
    if 100 <= chunk_len <= 50 * 1024 * 1024:
        with open(enc_path, "rb") as f_in, open(out_path, "wb") as f_out:
            while True:
                hdr = f_in.read(4)
                if len(hdr) < 4:
                    break
                length = struct.unpack(">I", hdr)[0]
                cipher = f_in.read(length)
                if len(cipher) != length:
                    raise InvalidToken("Truncated chunk")
                f_out.write(fernet.decrypt(cipher))
    else:
        with open(enc_path, "rb") as f:
            cipher = f.read()
        with open(out_path, "wb") as f:
            f.write(fernet.decrypt(cipher))


def do_restore_from_encrypted(
    enc_zip_path: str,
    enc_sql_path: str,
    skeleton_key: str,
    no_doctor: bool,
    yes: bool,
) -> int:
    """Restore from local encrypted zip + sql (e.g. uploaded via GUI). Decrypt with skeleton key, then restore."""
    _require_root()
    enc_zip = Path(enc_zip_path)
    enc_sql = Path(enc_sql_path)
    if not enc_zip.exists() or not enc_zip.is_file():
        logger.error("Encrypted zip does not exist or is not a file: %s", enc_zip_path)
        return 1
    if not enc_sql.exists() or not enc_sql.is_file():
        logger.error("Encrypted sql does not exist or is not a file: %s", enc_sql_path)
        return 1
    if not yes:
        logger.error(
            "restore-from-encrypted will REPLACE the current Forgejo instance. Add --yes to confirm."
        )
        return 1
    if not skeleton_key:
        logger.error(
            "Provide --skeleton-key or --skeleton-key-file (FAK from the HOMESERVER that created the backup)"
        )
        return 1

    logger.info(
        "restore-from-encrypted: decrypting %s and %s with skeleton key, then restore.",
        enc_zip_path,
        enc_sql_path,
    )
    tmpdir = tempfile.mkdtemp(prefix="forgejo_restore_enc_")
    try:
        fernet = _derive_fernet_from_skeleton(skeleton_key, FORGEJO_BACKUP_SALT)
        decrypted_zip = Path(tmpdir) / "forgejo-dump.zip"
        decrypted_sql = Path(tmpdir) / "forgejo_db.sql"
        for enc_path, out_path in [(enc_zip, decrypted_zip), (enc_sql, decrypted_sql)]:
            try:
                _decrypt_forgejo_backup_file(enc_path, out_path, fernet)
            except InvalidToken as e:
                logger.error(
                    "Decryption failed (wrong skeleton key or corrupted file?): %s", e
                )
                return 1
        logger.info("Decrypted backup with skeleton key; starting restore.")
        return do_restore(
            str(decrypted_zip),
            str(decrypted_sql),
            no_doctor=no_doctor,
            yes=True,
        )
    finally:
        try:
            for f in Path(tmpdir).iterdir():
                f.unlink(missing_ok=True)
            Path(tmpdir).rmdir()
        except OSError:
            pass


def do_restore_from_b2(
    bucket_name: str,
    backup_key: str,
    key_id: str,
    application_key: str,
    skeleton_key: str,
    no_doctor: bool,
    yes: bool,
) -> int:
    """Download encrypted backup from B2 (single .enc tarball or legacy .zip+.sql), decrypt, then restore."""
    _require_root()
    if not yes:
        logger.error(
            "restore-from-b2 will REPLACE the current Forgejo instance. Add --yes to confirm."
        )
        return 1

    logger.info(
        "restore-from-b2: bucket=%s prefix=%s; will download, decrypt with skeleton key, then restore.",
        bucket_name,
        backup_key,
    )
    prefix = backup_key.strip("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"

    info = InMemoryAccountInfo()
    api = B2Api(info)
    try:
        api.authorize_account("production", key_id, application_key)
    except Exception as e:
        logger.error("B2 authorization failed: %s", e)
        return 1

    bucket = api.get_bucket_by_name(bucket_name)
    files = list(bucket.ls(folder_to_list=prefix, recursive=False))
    enc_key: Optional[str] = None
    zip_key: Optional[str] = None
    sql_key: Optional[str] = None
    for file_info, _ in files:
        key = file_info.file_name
        if key.endswith(".enc"):
            enc_key = key
        elif key.endswith(".zip"):
            zip_key = key
        elif key.endswith(".sql"):
            sql_key = key

    tmpdir = tempfile.mkdtemp(prefix="forgejo_restore_b2_")
    try:
        if enc_key:
            return _restore_from_b2_single_enc(
                bucket, enc_key, tmpdir, skeleton_key, no_doctor
            )
        if zip_key and sql_key:
            return _restore_from_b2_legacy_zip_sql(
                bucket, zip_key, sql_key, tmpdir, skeleton_key, no_doctor
            )
        logger.error(
            "Expected one .enc file or one .zip and one .sql in prefix %s; found enc=%s zip=%s sql=%s",
            prefix or "(root)",
            enc_key,
            zip_key,
            sql_key,
        )
        return 1
    finally:
        try:
            for f in Path(tmpdir).iterdir():
                f.unlink()
            Path(tmpdir).rmdir()
        except OSError:
            pass


def _restore_from_b2_single_enc(
    bucket, enc_key: str, tmpdir: str, skeleton_key: str, no_doctor: bool
) -> int:
    """Download single .enc (encrypted tarball), decrypt, extract, restore."""
    enc_path = Path(tmpdir) / "enc.enc"
    downloaded = bucket.download_file_by_name(enc_key)
    downloaded.save(enc_path)
    logger.info("Downloaded %s from B2", enc_key)

    fernet = _derive_fernet_from_skeleton(skeleton_key, FORGEJO_BACKUP_SALT)
    tar_path = Path(tmpdir) / "backup.tar"
    try:
        _decrypt_forgejo_backup_file(enc_path, tar_path, fernet)
    except InvalidToken as e:
        logger.error("Decryption failed (wrong skeleton key or corrupted file?): %s", e)
        return 1
    extract_dir = Path(tmpdir) / "extract"
    extract_dir.mkdir()
    with tarfile.open(tar_path, "r") as tar:
        tar.extractall(extract_dir)
    zip_path = extract_dir / "forgejo-dump.zip"
    sql_path = extract_dir / "forgejo_db.sql"
    if not zip_path.is_file() or not sql_path.is_file():
        logger.error("Tarball missing forgejo-dump.zip or forgejo_db.sql")
        return 1
    logger.info("Decrypted and extracted backup; starting restore.")
    return do_restore(str(zip_path), str(sql_path), no_doctor=no_doctor, yes=True)


def _restore_from_b2_legacy_zip_sql(
    bucket, zip_key: str, sql_key: str, tmpdir: str, skeleton_key: str, no_doctor: bool
) -> int:
    """Legacy: download .zip and .sql, decrypt each, restore."""
    enc_zip_path = Path(tmpdir) / "enc.zip"
    enc_sql_path = Path(tmpdir) / "enc.sql"
    bucket.download_file_by_name(zip_key).save(enc_zip_path)
    bucket.download_file_by_name(sql_key).save(enc_sql_path)
    logger.info("Downloaded %s and %s from B2", zip_key, sql_key)

    fernet = _derive_fernet_from_skeleton(skeleton_key, FORGEJO_BACKUP_SALT)
    decrypted_zip = Path(tmpdir) / "forgejo-dump.zip"
    decrypted_sql = Path(tmpdir) / "forgejo_db.sql"
    for enc_path, out_path in [(enc_zip_path, decrypted_zip), (enc_sql_path, decrypted_sql)]:
        try:
            _decrypt_forgejo_backup_file(Path(enc_path), out_path, fernet)
        except InvalidToken as e:
            logger.error("Decryption failed (wrong skeleton key or corrupted file?): %s", e)
            return 1
    logger.info("Decrypted backup with skeleton key; starting restore.")
    return do_restore(
        str(decrypted_zip),
        str(decrypted_sql),
        no_doctor=no_doctor,
        yes=True,
    )


def do_export(output_dir: str) -> int:
    _require_root()
    output_path = Path(output_dir)
    if not output_path.is_dir():
        logger.error("Output directory does not exist or is not a directory: %s", output_dir)
        return 1

    # Allow postgres and git to write here (dir is created by www-data; we run pg_dump as postgres, dump as git)
    try:
        output_path.chmod(0o777)
    except OSError as e:
        logger.warning("Could not chmod output dir %s: %s", output_dir, e)

    # Clobber: single fixed names, no dates (anti-pattern: file names do not contain dates).
    for name in ("forgejo_db.sql", "forgejo-dump.zip"):
        old = output_path / name
        if old.exists():
            try:
                old.unlink()
                logger.info("Removed previous export artifact: %s", name)
            except OSError as e:
                logger.warning("Could not remove %s: %s", old, e)

    logger.info("Forgejo export started; output_dir=%s", output_dir)
    logger.info("Forgejo will be stopped briefly during export; it will be started again when done.")
    db_dump_path = output_path / "forgejo_db.sql"
    dump_zip_path = output_path / "forgejo-dump.zip"

    if not _stop_forgejo():
        return 1

    # Subprocesses run as postgres/git; cwd must be a dir they can access (avoid inheriting /root).
    # Use output_dir (on disk, already chmod 777) not /tmp (tmpfs could exhaust RAM on large dumps).
    safe_cwd = str(output_path)
    try:
        # pg_dump as postgres (peer auth, no password)
        if not _run_log(
            ["/usr/bin/sudo", "-u", "postgres", PG_DUMP, FORGEJO_DB_NAME, "-f", str(db_dump_path)],
            "pg_dump forgejo database",
            cwd=safe_cwd,
        ):
            return 1

        # forgejo dump as git (FORGEJO_WORK_DIR set via env in command)
        if not _run_log(
            [
                "/usr/bin/sudo",
                "-u",
                FORGEJO_USER,
                "env",
                f"FORGEJO_WORK_DIR={FORGEJO_WORK_DIR}",
                FORGEJO_BINARY,
                "dump",
                "--config",
                FORGEJO_CONFIG,
                "--file",
                str(dump_zip_path),
            ],
            "forgejo dump",
            cwd=safe_cwd,
        ):
            return 1

        logger.info(
            "Export complete: db_dump=%s dump_zip=%s",
            db_dump_path,
            dump_zip_path,
        )
        return 0
    finally:
        if not _start_forgejo():
            logger.error("Forgejo was left stopped; start it manually: systemctl start forgejo")
            sys.exit(1)


def _doctor_error_total(output: str) -> Optional[int]:
    """Read an explicit doctor summary total, not counts embedded in prose."""
    patterns = (
        r"(?im)^\s*(?:doctor\s+)?found\s+(\d+)\s+errors?\b[^\n]*$",
        r"(?im)^\s*(\d+)\s+errors?\s+(?:found|detected|reported)\b[^\n]*$",
        r"(?im)^\s*(?:total\s+)?errors?\s*(?:count)?\s*[:=]\s*(\d+)\b[^\n]*$",
        r"(?im)^\s*total\s*[:=]\s*(\d+)\s+errors?\b[^\n]*$",
        r"(?im)^\s*(\d+)\s+errors?\s*$",
    )
    for pattern in patterns:
        matches = re.findall(pattern, output)
        if matches:
            return int(matches[-1])
    return None


def _doctor_error_lines(output: str) -> int:
    """Count line-level doctor error markers when no summary total is available."""
    return len(
        re.findall(
            r"(?im)^\s*(?:(?:-\s*)?\[E\](?:\s|$)|ERROR\b|error\s*:|FAIL(?:ED)?\b).*$",
            output,
        )
    )


def do_restore(dump_zip: str, db_dump: str, no_doctor: bool, yes: bool) -> int:
    _require_root()
    if not yes:
        logger.error(
            "Restore will REPLACE the current Forgejo instance (database and files in %s). "
            "Add --yes to confirm and proceed.",
            FORGEJO_WORK_DIR,
        )
        return 1

    try:
        plan = _file_preflight(dump_zip, db_dump)
    except RestorePreflightError as exc:
        logger.error("Restore preflight failed: %s; Forgejo was not stopped and no restore changes were made.", exc)
        return 1

    role_status, can_create_role = _role_status(plan.database_user)
    if role_status is None:
        logger.error("Restore preflight failed: could not establish database role readiness; Forgejo was not stopped.")
        return 1
    role_missing = role_status == "missing"
    if role_status == "unready":
        logger.error(
            "Restore preflight failed: dump database role exists but is not login-ready; Forgejo was not stopped."
        )
        return 1
    if role_missing and not plan.database_password:
        logger.error(
            "Restore preflight failed: dump app.ini [database] PASSWD must be non-empty to create its absent USER role; Forgejo was not stopped."
        )
        return 1
    if role_missing and not can_create_role:
        logger.error(
            "Restore preflight failed: PostgreSQL cannot create the dump database role; Forgejo was not stopped."
        )
        return 1

    logger.info("Forgejo restore started; dump_zip=%s db_dump=%s", dump_zip, db_dump)
    logger.info("Current instance will be replaced after all file and role preflight checks pass.")

    if not _stop_forgejo():
        logger.error("Forgejo stop failed before database replacement; attempting to leave Forgejo running.")
        if _start_forgejo():
            logger.info("Forgejo was started after the failed stop; the database and files were not replaced.")
        else:
            logger.error("Forgejo state is uncertain after the failed stop; inspect or start it manually.")
        return 1

    if role_missing:
        assert plan.database_password is not None
        create_role_sql = (
            "SET standard_conforming_strings = on;\n"
            f"CREATE ROLE {_sql_identifier(plan.database_user)} LOGIN "
            f"PASSWORD {_sql_literal(plan.database_password)};\n"
        )
        if not _run_postgres_script(create_role_sql, "create dump database role"):
            return _restart_after_pre_destructive_failure("database role creation")
        logger.info("Created the absent database role from dump app.ini; password output is suppressed.")

    role_status, _ = _role_status(plan.database_user)
    if role_status != "ready":
        return _restart_after_pre_destructive_failure("database role readiness verification")

    # Terminating sessions can change live database state, so all later failures
    # leave Forgejo stopped rather than starting it against a partial restore.
    terminate_sql = (
        "SET standard_conforming_strings = on;\n"
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        f"WHERE datname = {_sql_literal(FORGEJO_DB_NAME)} AND pid <> pg_backend_pid();\n"
    )
    if not _run_postgres_script(terminate_sql, "terminate Forgejo database connections"):
        return _fail_after_destructive("database connection termination")

    drop_cmd = [
        "/usr/bin/sudo",
        "-u",
        "postgres",
        PSQL,
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        "postgres",
        "-c",
        f"DROP DATABASE IF EXISTS {FORGEJO_DB_NAME};",
    ]
    if not _run_log(drop_cmd, "drop forgejo database"):
        return _fail_after_destructive("database drop")

    create_cmd = [
        "/usr/bin/sudo",
        "-u",
        "postgres",
        PSQL,
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        "postgres",
        "-c",
        f"CREATE DATABASE {FORGEJO_DB_NAME} OWNER {_sql_identifier(plan.database_user)};",
    ]
    if not _run_log(create_cmd, "create forgejo database"):
        return _fail_after_destructive("database creation")

    if not _run_postgres_dump(plan.sql_path):
        return _fail_after_destructive("database load")

    try:
        logger.info("Extracting dump zip into %s", FORGEJO_WORK_DIR)
        Path(FORGEJO_WORK_DIR).mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(plan.zip_path, "r") as zf:
            zf.extractall(
                FORGEJO_WORK_DIR,
                members=(
                    info
                    for info in zf.infolist()
                    if info.filename not in {"app.ini", "custom/conf/app.ini"}
                ),
            )
        config_path = Path(FORGEJO_CONFIG)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_fd, config_tmp = tempfile.mkstemp(
            prefix=".app.ini.", dir=config_path.parent
        )
        try:
            with os.fdopen(config_fd, "wb") as config_file:
                os.fchmod(config_file.fileno(), 0o600)
                config_file.write(plan.app_ini)
            os.replace(config_tmp, config_path)
        finally:
            Path(config_tmp).unlink(missing_ok=True)
        _position_repositories(plan)
        logger.info("Dump files extracted; app.ini installed and repositories positioned at %s", plan.repository_root)
    except Exception as exc:
        logger.error("Restore file placement failed after database replacement: %s", exc)
        return _fail_after_destructive("file extraction or placement")

    chown_paths = [FORGEJO_WORK_DIR]
    work_dir = Path(FORGEJO_WORK_DIR).resolve(strict=False)
    if not plan.repository_root.is_relative_to(work_dir):
        chown_paths.append(str(plan.repository_root))
    if not _run_log(
        [CHOWN, "-R", f"{FORGEJO_USER}:{FORGEJO_USER}", *chown_paths],
        "chown restored Forgejo files to git:git",
    ):
        return _fail_after_destructive("restored file ownership")

    for operation in ("hooks", "keys"):
        if not _run_checked_silent(
            [
                "/usr/bin/sudo",
                "-u",
                FORGEJO_USER,
                "env",
                f"FORGEJO_WORK_DIR={FORGEJO_WORK_DIR}",
                FORGEJO_BINARY,
                "admin",
                "regenerate",
                operation,
                "--config",
                FORGEJO_CONFIG,
            ],
            f"forgejo admin regenerate {operation}",
        ):
            return _fail_after_destructive(f"Forgejo {operation} regeneration")

    if not _start_forgejo():
        logger.error("Restore steps completed, but Forgejo was not confirmed running; inspect or start it manually.")
        return 1

    if no_doctor:
        logger.info("Doctor result: skipped by --no-doctor")
        return 0

    try:
        doctor = _run(
            [
                "/usr/bin/sudo",
                "-u",
                FORGEJO_USER,
                "env",
                f"FORGEJO_WORK_DIR={FORGEJO_WORK_DIR}",
                FORGEJO_BINARY,
                "doctor",
                "check",
                "--all",
                "--config",
                FORGEJO_CONFIG,
            ]
        )
    except (OSError, UnicodeError):
        logger.error(
            "Doctor result: at least 1 error (count unavailable; doctor command could not be run or its output could not be read)"
        )
        return 1
    doctor_output = f"{doctor.stdout or ''}\n{doctor.stderr or ''}"
    error_total = _doctor_error_total(doctor_output)
    error_lines = _doctor_error_lines(doctor_output)
    command_failed = doctor.returncode != 0
    has_findings = error_lines > 0 or (error_total is not None and error_total > 0)
    if command_failed or has_findings:
        if error_total is not None and error_total > 0:
            result = f"{error_total} error{'s' if error_total != 1 else ''}"
        elif error_lines:
            result = f"{error_lines} error{'s' if error_lines != 1 else ''}"
        else:
            result = "at least 1 error (count unavailable)"
        logger.error("Doctor result: %s", result)
        return 1

    logger.info("Doctor result: clean")
    return 0


def do_preflight(dump_zip: str, db_dump: str) -> int:
    """Safe, file-only preflight; does not query PostgreSQL or touch the service."""
    try:
        plan = _file_preflight(dump_zip, db_dump)
    except RestorePreflightError as exc:
        logger.error("Restore preflight failed: %s", exc)
        return 1
    logger.info(
        "File-only restore preflight passed: database_user=%s repository_root=%s; no service or PostgreSQL operations ran.",
        plan.database_user,
        plan.repository_root,
    )
    return 0


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    prog_name = "homeserver-forgejo-migrate.py"
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description="HOMESERVER Forgejo backup and restore CLI. Export and restore commands require root; file-only preflight does not.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
export: stop forgejo, pg_dump + forgejo dump, start forgejo.
restore: preflight local dump zip + sql; replace Forgejo from the dump.
preflight: file-only restore preflight; does not query PostgreSQL or touch Forgejo.
restore-from-b2: download encrypted backup from B2, decrypt with skeleton key (FAK), then restore.
restore-from-encrypted: from local encrypted zip + sql (e.g. GUI upload), decrypt with FAK, then restore.

Examples:
  sudo {prog_name} export --output-dir /var/www/homeserver/premium/forgejo_export
  sudo {prog_name} restore --dump-zip /path/forgejo-dump-20260315_120000.zip --db-dump /path/forgejo_db_20260315_120000.sql --yes
  sudo {prog_name} restore-from-b2 --bucket-name my-bucket --backup-key forgejo-backups/latest/ --key-id KEY --application-key SECRET --skeleton-key-file /root/key/skeleton.key --yes
  sudo {prog_name} restore-from-encrypted --enc-zip /tmp/enc.zip --enc-sql /tmp/enc.sql --skeleton-key-file /root/key/skeleton.key --yes
""",
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="export, restore, preflight, restore-from-b2, or restore-from-encrypted"
    )

    export_parser = subparsers.add_parser("export", help="Export Forgejo instance to output directory")
    export_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write forgejo_db_<timestamp>.sql and forgejo-dump-<timestamp>.zip",
    )
    export_parser.set_defaults(func=do_export)

    restore_parser = subparsers.add_parser(
        "restore",
        help="Restore Forgejo instance from dump (REPLACES live instance; requires --yes)",
    )
    restore_parser.add_argument(
        "--dump-zip",
        required=True,
        help="Path to forgejo-dump-<timestamp>.zip",
    )
    restore_parser.add_argument(
        "--db-dump",
        required=True,
        help="Path to forgejo_db_<timestamp>.sql",
    )
    restore_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm restore; required. Replaces the database, work-dir files, and configured repository ROOT.",
    )
    restore_parser.add_argument(
        "--no-doctor",
        action="store_true",
        help="Skip forgejo doctor check --all after restore",
    )
    restore_parser.set_defaults(func=do_restore)

    preflight_parser = subparsers.add_parser(
        "preflight",
        help="Validate restore files only; does not query PostgreSQL or touch Forgejo",
    )
    preflight_parser.add_argument("--dump-zip", required=True, help="Path to forgejo-dump zip")
    preflight_parser.add_argument("--db-dump", required=True, help="Path to forgejo SQL dump")

    b2_parser = subparsers.add_parser(
        "restore-from-b2",
        help="Download encrypted Forgejo backup from B2, decrypt with skeleton key (FAK), then restore",
    )
    b2_parser.add_argument("--bucket-name", required=True, help="B2 bucket name")
    b2_parser.add_argument(
        "--backup-key",
        required=True,
        help="Backup prefix in bucket (e.g. forgejo-backups/2026-03-15_14-30-00/)",
    )
    b2_parser.add_argument("--key-id", required=True, help="B2 application key ID")
    b2_parser.add_argument("--application-key", required=True, help="B2 application key")
    b2_parser.add_argument(
        "--skeleton-key",
        default=None,
        help="Skeleton key (FAK) from original HOMESERVER to decrypt the backup",
    )
    b2_parser.add_argument(
        "--skeleton-key-file",
        default=None,
        help="Read skeleton key from file (e.g. /root/key/skeleton.key); use this or --skeleton-key",
    )
    b2_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm restore; required. Replaces current Forgejo instance.",
    )
    b2_parser.add_argument(
        "--no-doctor",
        action="store_true",
        help="Skip forgejo doctor check --all after restore",
    )
    b2_parser.set_defaults(func=do_restore_from_b2)

    enc_parser = subparsers.add_parser(
        "restore-from-encrypted",
        help="Restore from local encrypted zip + sql (e.g. uploaded via GUI). Decrypt with FAK, then restore.",
    )
    enc_parser.add_argument(
        "--enc-zip",
        required=True,
        help="Path to encrypted forgejo-dump zip file",
    )
    enc_parser.add_argument(
        "--enc-sql",
        required=True,
        help="Path to encrypted forgejo_db sql file",
    )
    enc_parser.add_argument(
        "--skeleton-key",
        default=None,
        help="Skeleton key (FAK) from original HOMESERVER to decrypt the backup",
    )
    enc_parser.add_argument(
        "--skeleton-key-file",
        default=None,
        help="Read skeleton key from file (e.g. /root/key/skeleton.key); use this or --skeleton-key",
    )
    enc_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm restore; required. Replaces current Forgejo instance.",
    )
    enc_parser.add_argument(
        "--no-doctor",
        action="store_true",
        help="Skip forgejo doctor check --all after restore",
    )
    enc_parser.set_defaults(func=do_restore_from_encrypted)

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command == "export":
        return do_export(args.output_dir)
    if args.command == "restore":
        return do_restore(
            args.dump_zip,
            args.db_dump,
            getattr(args, "no_doctor", False),
            getattr(args, "yes", False),
        )
    if args.command == "preflight":
        return do_preflight(args.dump_zip, args.db_dump)
    if args.command == "restore-from-b2":
        skeleton_key = getattr(args, "skeleton_key", None) or ""
        skeleton_key_file = getattr(args, "skeleton_key_file", None)
        if skeleton_key_file:
            path = Path(skeleton_key_file)
            if not path.exists() or not path.is_file():
                logger.error("skeleton-key-file does not exist or is not a file: %s", skeleton_key_file)
                return 1
            skeleton_key = path.read_text().strip()
        if not skeleton_key:
            logger.error(
                "Provide --skeleton-key or --skeleton-key-file (FAK from the HOMESERVER that created the backup)"
            )
            return 1
        return do_restore_from_b2(
            bucket_name=args.bucket_name,
            backup_key=args.backup_key,
            key_id=args.key_id,
            application_key=args.application_key,
            skeleton_key=skeleton_key,
            no_doctor=getattr(args, "no_doctor", False),
            yes=getattr(args, "yes", False),
        )
    if args.command == "restore-from-encrypted":
        skeleton_key = getattr(args, "skeleton_key", None) or ""
        skeleton_key_file = getattr(args, "skeleton_key_file", None)
        if skeleton_key_file:
            path = Path(skeleton_key_file)
            if not path.exists() or not path.is_file():
                logger.error("skeleton-key-file does not exist or is not a file: %s", skeleton_key_file)
                return 1
            skeleton_key = path.read_text().strip()
        return do_restore_from_encrypted(
            enc_zip_path=args.enc_zip,
            enc_sql_path=args.enc_sql,
            skeleton_key=skeleton_key,
            no_doctor=getattr(args, "no_doctor", False),
            yes=getattr(args, "yes", False),
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())

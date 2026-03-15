#!/usr/bin/env python3
"""
HOMESERVER Forgejo backup and restore (migrate) CLI.

Full-instance export: stop forgejo, pg_dump database forgejo, forgejo dump as git user,
then start forgejo. Output: DB dump SQL + Forgejo dump zip in --output-dir.

Full-instance restore: stop forgejo, restore Postgres from dump, extract Forgejo dump
zip into /opt/forgejo, chown git:git, start forgejo, optional forgejo doctor.

restore-from-b2: download encrypted forgejo backup (zip + sql) from a Backblaze B2 bucket,
decrypt with skeleton key (FAK), then restore. Same encryption as Backblaze tab (salt
backblazetab_forgejo_backup_salt). Requires b2sdk and cryptography (script bootstraps
a venv on first use if needed).

Requires root/sudo. Fixed paths for bare-metal Forgejo install (binary, config, work dir).
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import tempfile
import venv
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

# Bootstrap b2sdk/cryptography only when restore-from-b2 is used (reuse disaster-recovery venv)
if "restore-from-b2" in sys.argv:
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
    result = _run(cmd, env=env, cwd=cwd)
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


def _timestamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")


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


def do_restore_from_b2(
    bucket_name: str,
    backup_key: str,
    key_id: str,
    application_key: str,
    skeleton_key: str,
    no_doctor: bool,
    yes: bool,
) -> int:
    """Download encrypted zip+sql from B2, decrypt with skeleton key, then restore."""
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
    # Normalize prefix: no leading slash; trailing slash for folder listing
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
    zip_key: Optional[str] = None
    sql_key: Optional[str] = None
    for file_info, _ in files:
        key = file_info.file_name
        if key.endswith(".zip"):
            zip_key = key
        elif key.endswith(".sql"):
            sql_key = key
    if not zip_key or not sql_key:
        logger.error(
            "Expected one .zip and one .sql in prefix %s; found zip=%s sql=%s",
            prefix or "(root)",
            zip_key,
            sql_key,
        )
        return 1

    # Download to temp dir (encrypted content)
    tmpdir = tempfile.mkdtemp(prefix="forgejo_restore_b2_")
    try:
        decrypted_zip: Optional[Path] = None
        decrypted_sql: Optional[Path] = None
        try:
            enc_zip_path = Path(tmpdir) / "enc.zip"
            enc_sql_path = Path(tmpdir) / "enc.sql"
            downloaded_zip = bucket.download_file_by_name(zip_key)
            downloaded_zip.save(enc_zip_path)
            downloaded_sql = bucket.download_file_by_name(sql_key)
            downloaded_sql.save(enc_sql_path)
            logger.info("Downloaded %s and %s from B2", zip_key, sql_key)

            fernet = _derive_fernet_from_skeleton(skeleton_key, FORGEJO_BACKUP_SALT)
            decrypted_zip = Path(tmpdir) / "forgejo-dump.zip"
            decrypted_sql = Path(tmpdir) / "forgejo_db.sql"
            for enc_path, out_path in [(enc_zip_path, decrypted_zip), (enc_sql_path, decrypted_sql)]:
                with open(enc_path, "rb") as f:
                    cipher = f.read()
                try:
                    plain = fernet.decrypt(cipher)
                except InvalidToken as e:
                    logger.error(
                        "Decryption failed (wrong skeleton key or corrupted file?): %s", e
                    )
                    return 1
                with open(out_path, "wb") as f:
                    f.write(plain)
            logger.info("Decrypted backup with skeleton key; starting restore.")
            return do_restore(
                str(decrypted_zip),
                str(decrypted_sql),
                no_doctor=no_doctor,
                yes=True,
            )
        finally:
            for p in (decrypted_zip, decrypted_sql):
                if p and p.exists():
                    try:
                        p.unlink()
                    except OSError:
                        pass
    finally:
        try:
            for f in Path(tmpdir).iterdir():
                f.unlink()
            Path(tmpdir).rmdir()
        except OSError:
            pass


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

    logger.info("Forgejo export started; output_dir=%s", output_dir)
    logger.info("Forgejo will be stopped briefly during export; it will be started again when done.")
    ts = _timestamp()
    db_dump_path = output_path / f"forgejo_db_{ts}.sql"
    dump_zip_path = output_path / f"forgejo-dump-{ts}.zip"

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


def do_restore(dump_zip: str, db_dump: str, no_doctor: bool, yes: bool) -> int:
    _require_root()
    zip_path = Path(dump_zip)
    sql_path = Path(db_dump)
    if not zip_path.exists() or not zip_path.is_file():
        logger.error("Dump zip does not exist or is not a file: %s", dump_zip)
        return 1
    if not sql_path.exists() or not sql_path.is_file():
        logger.error("DB dump does not exist or is not a file: %s", db_dump)
        return 1

    if not yes:
        logger.error(
            "Restore will REPLACE the current Forgejo instance (database and files in %s). "
            "Add --yes to confirm and proceed.",
            FORGEJO_WORK_DIR,
        )
        return 1

    logger.info("Forgejo restore started; dump_zip=%s db_dump=%s", dump_zip, db_dump)
    logger.info("Current instance will be replaced; Forgejo will be stopped then started after restore.")

    if not _stop_forgejo():
        return 1

    try:
        # Terminate connections to forgejo DB, then drop and recreate
        term_cmd = [
            "/usr/bin/sudo",
            "-u",
            "postgres",
            PSQL,
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = %s AND pid <> pg_backend_pid();"
            % repr(FORGEJO_DB_NAME),
        ]
        _run(term_cmd)

        drop_cmd = [
            "/usr/bin/sudo",
            "-u",
            "postgres",
            PSQL,
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            f"DROP DATABASE IF EXISTS {FORGEJO_DB_NAME};",
        ]
        if not _run_log(drop_cmd, "drop forgejo database"):
            return 1

        create_cmd = [
            "/usr/bin/sudo",
            "-u",
            "postgres",
            PSQL,
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            f"CREATE DATABASE {FORGEJO_DB_NAME} OWNER {FORGEJO_USER};",
        ]
        if not _run_log(create_cmd, "create forgejo database"):
            return 1

        restore_cmd = [
            "/usr/bin/sudo",
            "-u",
            "postgres",
            PSQL,
            "-d",
            FORGEJO_DB_NAME,
            "-v",
            "ON_ERROR_STOP=1",
            "-f",
            str(sql_path),
        ]
        if not _run_log(restore_cmd, "restore Postgres from dump"):
            return 1

        # Extract zip into /opt/forgejo (Forgejo dump format: archive members are under work dir)
        logger.info("Extracting dump zip into %s", FORGEJO_WORK_DIR)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(FORGEJO_WORK_DIR)
        logger.info("Extract succeeded")

        if not _run_log(
            [CHOWN, "-R", f"{FORGEJO_USER}:{FORGEJO_USER}", FORGEJO_WORK_DIR],
            "chown git:git /opt/forgejo",
        ):
            return 1

        if not _start_forgejo():
            return 1

        if not no_doctor:
            _run_log(
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
                ],
                "forgejo doctor check --all",
            )

        logger.info("Restore complete")
        return 0
    finally:
        # If we exited early, try to start Forgejo so instance is not left stopped
        if not _start_forgejo():
            logger.error("Forgejo was left stopped; start it manually: systemctl start forgejo")
            sys.exit(1)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    prog_name = "homeserver-forgejo-migrate.py"
    parser = argparse.ArgumentParser(
        prog=prog_name,
        description="HOMESERVER Forgejo backup and restore (export/restore full instance). Requires root.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
export: stop forgejo, pg_dump + forgejo dump, start forgejo.
restore: from local dump zip + sql; stop forgejo, restore Postgres, extract zip, chown, start forgejo.
restore-from-b2: download encrypted backup from B2, decrypt with skeleton key (FAK), then restore.

Examples:
  sudo {prog_name} export --output-dir /var/www/homeserver/premium/forgejo_export
  sudo {prog_name} restore --dump-zip /path/forgejo-dump-20260315_120000.zip --db-dump /path/forgejo_db_20260315_120000.sql --yes
  sudo {prog_name} restore-from-b2 --bucket-name my-bucket --backup-key forgejo-backups/2026-03-15_14-30-00/ --key-id KEY --application-key SECRET --skeleton-key-file /root/key/skeleton.key --yes
""",
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="export, restore, or restore-from-b2"
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
        help="Confirm restore; required. Restore replaces the current database and /opt/forgejo contents.",
    )
    restore_parser.add_argument(
        "--no-doctor",
        action="store_true",
        help="Skip forgejo doctor check --all after restore",
    )
    restore_parser.set_defaults(func=do_restore)

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
    return 1


if __name__ == "__main__":
    sys.exit(main())

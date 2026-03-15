#!/usr/bin/env python3
"""
HOMESERVER Forgejo backup and restore (migrate) CLI.

Full-instance export: stop forgejo, pg_dump database forgejo, forgejo dump as git user,
then start forgejo. Output: DB dump SQL + Forgejo dump zip in --output-dir.

Full-instance restore: stop forgejo, restore Postgres from dump, extract Forgejo dump
zip into /opt/forgejo, chown git:git, start forgejo, optional forgejo doctor.

Requires root/sudo. Fixed paths for bare-metal Forgejo install (binary, config, work dir).
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Optional

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


def _require_root() -> None:
    if os.geteuid() != 0:
        logger.error("This script must be run as root (e.g. sudo)")
        sys.exit(1)


def _run(cmd: list[str], env: Optional[dict[str, str]] = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True,
    )


def _run_log(cmd: list[str], description: str, env: Optional[dict[str, str]] = None) -> bool:
    logger.info("Running: %s", description)
    result = _run(cmd, env=env)
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


def do_export(output_dir: str) -> int:
    _require_root()
    output_path = Path(output_dir)
    if not output_path.is_dir():
        logger.error("Output directory does not exist or is not a directory: %s", output_dir)
        return 1

    logger.info("Forgejo export started; output_dir=%s", output_dir)
    ts = _timestamp()
    db_dump_path = output_path / f"forgejo_db_{ts}.sql"
    dump_zip_path = output_path / f"forgejo-dump-{ts}.zip"

    if not _stop_forgejo():
        return 1

    try:
        # pg_dump as postgres (peer auth, no password)
        if not _run_log(
            ["/usr/bin/sudo", "-u", "postgres", PG_DUMP, FORGEJO_DB_NAME, "-f", str(db_dump_path)],
            "pg_dump forgejo database",
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


def do_restore(dump_zip: str, db_dump: str, no_doctor: bool) -> int:
    _require_root()
    zip_path = Path(dump_zip)
    sql_path = Path(db_dump)
    if not zip_path.exists() or not zip_path.is_file():
        logger.error("Dump zip does not exist or is not a file: %s", dump_zip)
        return 1
    if not sql_path.exists() or not sql_path.is_file():
        logger.error("DB dump does not exist or is not a file: %s", db_dump)
        return 1

    logger.info("Forgejo restore started; dump_zip=%s db_dump=%s", dump_zip, db_dump)

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
export: stop forgejo, pg_dump + forgejo dump, start forgejo. Writes forgejo_db_<timestamp>.sql and forgejo-dump-<timestamp>.zip to --output-dir.
restore: stop forgejo, restore Postgres, extract zip to /opt/forgejo, chown, start forgejo, optional doctor.

Examples:
  sudo {prog_name} export --output-dir /var/www/homeserver/premium/forgejo_export
  sudo {prog_name} restore --dump-zip /path/forgejo-dump-20260315_120000.zip --db-dump /path/forgejo_db_20260315_120000.sql
""",
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="export or restore")

    export_parser = subparsers.add_parser("export", help="Export Forgejo instance to output directory")
    export_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write forgejo_db_<timestamp>.sql and forgejo-dump-<timestamp>.zip",
    )
    export_parser.set_defaults(func=do_export)

    restore_parser = subparsers.add_parser("restore", help="Restore Forgejo instance from dump zip and DB dump")
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
        "--no-doctor",
        action="store_true",
        help="Skip forgejo doctor check --all after restore",
    )
    restore_parser.set_defaults(func=do_restore)

    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    if args.command == "export":
        return do_export(args.output_dir)
    if args.command == "restore":
        return do_restore(args.dump_zip, args.db_dump, getattr(args, "no_doctor", False))
    return 1


if __name__ == "__main__":
    sys.exit(main())

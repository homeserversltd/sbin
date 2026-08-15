#!/usr/bin/env python3
"""
HOMESERVER BackblazeTab B2 Disaster Recovery (standalone, self-contained)

Offline, last-resort recovery for Backblaze B2 chunked backups. Reconstructs
files from a chunk database + skeleton key + B2 credentials into a local zip.
Designed for "everything else is gone" (e.g. fire): run on any machine with
this script—no HOMESERVER or Backblaze tab required.

If b2sdk/cryptography are missing, this script creates a venv under
~/.local/share/homeserver-backblaze-recovery/venv and re-execs itself.

Inputs:
- Skeleton key (FAK / decryption key from original HOMESERVER)
- B2 credentials (key_id + application_key) and bucket name
- Chunk database: optional path to .db or .encrypted.db; if omitted, the latest
  _chunk_database_backup_*.encrypted.db is fetched from the bucket automatically.

Flow (fully automated when --database_path omitted): fetch encrypted DB from B2 ->
decrypt with skeleton key -> use manifest to pull encrypted chunks from B2 ->
decrypt chunks (reverse Rabin pipeline) -> write cleartext zip locally.

Output:
- Local zip archive of reconstructed files (cleartext on the machine running this).
"""

from __future__ import annotations

import argparse
import base64
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Bootstrap: ensure b2sdk and cryptography available (create venv and re-exec if not)
def _bootstrap_and_reexec() -> None:
    venv_base = Path.home() / ".local" / "share" / "homeserver-backblaze-recovery"
    venv_path = venv_base / "venv"
    venv_path.mkdir(parents=True, exist_ok=True)
    py = venv_path / "bin" / "python3"
    if not py.exists():
        venv.create(venv_path, with_pip=True)
    pip = venv_path / "bin" / "pip"
    subprocess.run(
        [str(pip), "install", "--quiet", "b2sdk>=2.0.0", "cryptography>=41.0.0"],
        check=True,
    )
    os.execv(str(py), [str(py)] + sys.argv)


try:
    from b2sdk.v2 import B2Api, InMemoryAccountInfo
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    _bootstrap_and_reexec()

CHUNK_SALT = b"backblazetab_chunk_salt"
DB_SALT = b"backblazetab_db_backup_salt"
DB_BACKUP_PREFIX = "_chunk_database_backup_"
DB_BACKUP_SUFFIX = ".encrypted.db"

logger = logging.getLogger("backblaze_recovery")


def _parse_db_backup_timestamp(filename: str) -> Optional[str]:
    """Extract YYYYMMDD_HHMMSS from _chunk_database_backup_YYYYMMDD_HHMMSS.encrypted.db. Returns None if invalid."""
    if not filename.startswith(DB_BACKUP_PREFIX) or not filename.endswith(DB_BACKUP_SUFFIX):
        return None
    try:
        ts = filename[len(DB_BACKUP_PREFIX) : -len(DB_BACKUP_SUFFIX)]
        if len(ts) == 15 and ts[8] == "_":  # YYYYMMDD_HHMMSS
            return ts
    except Exception:
        pass
    return None


def download_latest_db_backup_from_b2(
    bucket_name: str, b2_api: B2Api
) -> Tuple[Path, Optional[Path]]:
    """
    List bucket root for _chunk_database_backup_*.encrypted.db, pick latest by timestamp,
    download to a temp file. Returns (path_to_encrypted_db, path_to_cleanup).
    Caller must unlink the returned path when done if they want to remove the temp file.
    """
    bucket = b2_api.get_bucket_by_name(bucket_name)
    files = list(bucket.ls(folder_to_list="", recursive=False))
    candidates = []
    for file_info, _ in files:
        if file_info.file_name.startswith(DB_BACKUP_PREFIX) and file_info.file_name.endswith(DB_BACKUP_SUFFIX):
            ts = _parse_db_backup_timestamp(file_info.file_name)
            if ts:
                candidates.append((ts, file_info.file_name))
    if not candidates:
        raise RuntimeError(
            f"No chunk database backups found in bucket '{bucket_name}' "
            f"(looking for {DB_BACKUP_PREFIX}*{DB_BACKUP_SUFFIX})"
        )
    candidates.sort(key=lambda x: x[0], reverse=True)
    latest_name = candidates[0][1]
    logger.info("Downloading latest chunk database backup from B2: %s", latest_name)
    downloaded = bucket.download_file_by_name(latest_name)
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=DB_BACKUP_SUFFIX)
    try:
        downloaded.save(tmp)
        tmp.flush()
        tmp.close()
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise
    return Path(tmp.name), Path(tmp.name)


def derive_fernet_from_skeleton(skeleton_key: str, salt: bytes) -> Fernet:
    """Derive a Fernet key from the skeleton key using PBKDF2 (same as export_backblaze_fak.sh)."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(skeleton_key.encode()))
    return Fernet(key)


def decrypt_db_if_needed(db_path: Path, skeleton_key: str) -> Path:
    """
    If the database is encrypted (filename suggests .encrypted.db or sqlite open fails),
    decrypt it with the db salt into a temp file and return that path.
    """
    is_encrypted_ext = db_path.suffixes[-2:] == [".encrypted", ".db"] or db_path.suffix == ".encrypted.db"

    def _decrypt_to_temp() -> Path:
        fernet = derive_fernet_from_skeleton(skeleton_key, DB_SALT)
        with open(db_path, "rb") as f:
            encrypted = f.read()
        try:
            plaintext = fernet.decrypt(encrypted)
        except InvalidToken as exc:
            raise RuntimeError("Failed to decrypt database with provided skeleton key") from exc
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.write(plaintext)
        tmp.flush()
        tmp.close()
        return Path(tmp.name)

    if is_encrypted_ext:
        logger.info("Database appears encrypted (.encrypted.db); decrypting with skeleton key")
        return _decrypt_to_temp()

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        conn.execute("SELECT 1")
        conn.close()
        return db_path
    except sqlite3.DatabaseError:
        logger.info("Database failed sqlite open; attempting decryption with skeleton key")
        return _decrypt_to_temp()


def open_database(db_path: Path, skeleton_key: str) -> Tuple[sqlite3.Connection, Optional[Path]]:
    """Open the database read-only. If encrypted, decrypt to temp first."""
    resolved = decrypt_db_if_needed(db_path, skeleton_key)
    conn = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    temp_path = resolved if resolved != db_path else None
    return conn, temp_path


def authenticate_b2(key_id: str, application_key: str) -> B2Api:
    """Authenticate to B2 with provided credentials."""
    info = InMemoryAccountInfo()
    api = B2Api(info)
    api.authorize_account("production", key_id, application_key)
    return api


def choose_backup_id(conn: sqlite3.Connection, requested: Optional[str]) -> str:
    """Select backup_id (requested or most recent)."""
    cursor = conn.execute(
        """
        SELECT backup_id, created_at
        FROM backups
        ORDER BY datetime(created_at) DESC
        """
    )
    backups = cursor.fetchall()
    if not backups:
        raise RuntimeError("No backups found in database.")

    if requested:
        for row in backups:
            if row["backup_id"] == requested:
                return requested
        raise RuntimeError(f"Requested backup_id {requested} not found in database.")

    return backups[0]["backup_id"]


def load_file_records(conn: sqlite3.Connection, backup_id: str) -> List[sqlite3.Row]:
    """Load file records for the backup."""
    cursor = conn.execute(
        """
        SELECT id, original_path, file_type, size, chunk_count
        FROM backup_files
        WHERE backup_id = ?
        ORDER BY original_path
        """,
        (backup_id,),
    )
    return cursor.fetchall()


def load_chunk_mappings(conn: sqlite3.Connection, backup_id: str) -> Dict[int, List[sqlite3.Row]]:
    """Load chunk mappings keyed by file_id."""
    cursor = conn.execute(
        """
        SELECT m.file_id, m.chunk_hash, m.chunk_index, c.remote_path, c.encrypted_size
        FROM backup_chunk_mappings m
        JOIN chunks c ON m.chunk_hash = c.chunk_hash
        WHERE m.backup_id = ?
        ORDER BY m.file_id, m.chunk_index
        """,
        (backup_id,),
    )
    files: Dict[int, List[sqlite3.Row]] = {}
    for row in cursor.fetchall():
        files.setdefault(row["file_id"], []).append(row)
    return files


def download_chunk(bucket, remote_path: str) -> bytes:
    """Download a chunk from B2 and return bytes."""
    downloaded = bucket.download_file_by_name(remote_path)
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        downloaded.save(tmp)
        tmp.flush()
        tmp.seek(0)
        data = tmp.read()
    try:
        os.unlink(tmp.name)
    except OSError:
        pass
    return data


def reconstruct_files(
    conn: sqlite3.Connection,
    backup_id: str,
    bucket_name: str,
    b2_api: B2Api,
    chunk_fernet: Fernet,
    output_zip: Path,
) -> Dict[str, int]:
    """Reconstruct files from B2 into a zip. Returns summary stats."""
    files = load_file_records(conn, backup_id)
    mappings = load_chunk_mappings(conn, backup_id)
    bucket = b2_api.get_bucket_by_name(bucket_name)

    recovered = 0
    skipped = 0
    chunk_cache: Dict[str, bytes] = {}

    with tempfile.TemporaryDirectory() as staging_dir:
        staging_root = Path(staging_dir) / "recovered"
        staging_root.mkdir(parents=True, exist_ok=True)

        for file_row in files:
            file_id = file_row["id"]
            original_path = file_row["original_path"]
            file_type = file_row["file_type"] or "file"

            if file_type == "directory":
                (staging_root / original_path).mkdir(parents=True, exist_ok=True)
                continue

            file_chunks = mappings.get(file_id, [])
            if not file_chunks:
                logger.warning("Skipping %s (no chunks found in DB)", original_path)
                skipped += 1
                continue

            target_path = staging_root / original_path
            target_path.parent.mkdir(parents=True, exist_ok=True)

            try:
                with open(target_path, "wb") as out_f:
                    for chunk in file_chunks:
                        chunk_hash = chunk["chunk_hash"]
                        remote_path = chunk["remote_path"]

                        if chunk_hash in chunk_cache:
                            encrypted_chunk = chunk_cache[chunk_hash]
                        else:
                            encrypted_chunk = download_chunk(bucket, remote_path)
                            chunk_cache[chunk_hash] = encrypted_chunk

                        try:
                            decrypted = chunk_fernet.decrypt(encrypted_chunk)
                        except InvalidToken:
                            logger.error(
                                "Decryption failed for chunk %s (path=%s); file will be incomplete",
                                chunk_hash[:16],
                                original_path,
                            )
                            raise

                        out_f.write(decrypted)

                recovered += 1
                logger.info("Recovered %s (%d chunks)", original_path, len(file_chunks))
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to recover %s: %s", original_path, exc)
                skipped += 1
                continue

        output_zip.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in staging_root.rglob("*"):
                if path.is_file():
                    zf.write(path, path.relative_to(staging_root))

    return {"recovered_files": recovered, "skipped_files": skipped, "total_files": len(files)}


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    example = """
Example (fill in all placeholders for the tool to run):

  %(prog)s \\
    --skeleton_key "YOUR_FAK" \\
    --bucket_name "my_bucket" \\
    --key_id "YOUR_B2_KEY_ID" \\
    --application_key "YOUR_B2_APP_KEY" \\
    --output recovered_data.zip

Omit --database_path to fetch the latest chunk DB backup from B2 automatically.
"""

    class _Parser(argparse.ArgumentParser):
        def error(self, message: str) -> None:
            sys.stderr.write("Missing required options. Provide all of the following for the tool to run:\n")
            sys.stderr.write("  --skeleton_key   (FAK / decryption key from original HOMESERVER)\n")
            sys.stderr.write("  --bucket_name    (B2 bucket name)\n")
            sys.stderr.write("  --key_id         (B2 key ID)\n")
            sys.stderr.write("  --application_key (B2 application key)\n\n")
            sys.stderr.write("Example:\n")
            sys.stderr.write(
                "  %s --skeleton_key \"YOUR_FAK\" --bucket_name \"my_bucket\" "
                "--key_id \"YOUR_B2_KEY_ID\" --application_key \"YOUR_B2_APP_KEY\" --output recovered_data.zip\n\n"
                % self.prog
            )
            super().error(message)

    parser = _Parser(
        description="HOMESERVER BackblazeTab B2 disaster recovery: pull from B2 to a local zip (standalone, no HOMESERVER required).",
        epilog=example.strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--database_path",
        default=None,
        help="Path to chunk database (.db or .encrypted.db). If omitted, the latest _chunk_database_backup_*.encrypted.db is downloaded from the bucket automatically.",
    )
    parser.add_argument("--skeleton_key", required=True, help="Skeleton key (FAK / decryption key from original HOMESERVER)")
    parser.add_argument("--bucket_name", required=True, help="B2 bucket name to recover from")
    parser.add_argument("--key_id", required=True, help="B2 key ID")
    parser.add_argument("--application_key", required=True, help="B2 application key")
    parser.add_argument(
        "--backup_id",
        help="Optional backup_id to recover (default: most recent in database)",
    )
    parser.add_argument(
        "--output",
        default="recovered_data.zip",
        help="Output zip path (default: recovered_data.zip)",
    )

    args = parser.parse_args(argv)
    return args


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    temp_downloaded_db: Optional[Path] = None
    b2_api = authenticate_b2(args.key_id, args.application_key)
    if args.database_path:
        db_path = Path(args.database_path)
        if not db_path.exists():
            logger.error("Database path does not exist: %s", db_path)
            return 1
    else:
        db_path, temp_downloaded_db = download_latest_db_backup_from_b2(args.bucket_name, b2_api)

    try:
        conn, temp_db = open_database(db_path, args.skeleton_key)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to open database: %s", exc)
        if temp_downloaded_db and temp_downloaded_db.exists():
            try:
                temp_downloaded_db.unlink()
            except OSError:
                pass
        return 1

    try:
        backup_id = choose_backup_id(conn, args.backup_id)
        logger.info("Using backup_id: %s", backup_id)

        chunk_fernet = derive_fernet_from_skeleton(args.skeleton_key, CHUNK_SALT)

        summary = reconstruct_files(
            conn=conn,
            backup_id=backup_id,
            bucket_name=args.bucket_name,
            b2_api=b2_api,
            chunk_fernet=chunk_fernet,
            output_zip=Path(args.output),
        )

        logger.info(
            "Recovery complete: recovered=%d skipped=%d total=%d output=%s",
            summary["recovered_files"],
            summary["skipped_files"],
            summary["total_files"],
            Path(args.output).resolve(),
        )
        if summary["recovered_files"] == 0:
            return 2
        return 0
    finally:
        conn.close()
        if temp_db and temp_db.exists():
            try:
                temp_db.unlink()
            except OSError:
                pass
        if temp_downloaded_db and temp_downloaded_db.exists():
            try:
                temp_downloaded_db.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())

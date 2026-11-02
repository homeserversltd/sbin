"""Check one Forgejo owner or owner/repository without enumerating names."""
from __future__ import annotations

import configparser
import json
import os
import re
import subprocess
from pathlib import Path

from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.backup.backblaze import shared

SCHEMA = "caduceus.forgejo.skip-check.v1"
APP_INI = Path("/opt/forgejo/custom/conf/app.ini")
DB_NAME = re.compile(r"[A-Za-z0-9_.-]+\Z")


def check(name):
    result = {"schema": SCHEMA, "ok": False, "name": name if isinstance(name, str) else None,
              "matches": False, "firstMissingSignal": "forgejo-skip-check-not-complete"}
    try:
        normalized = shared.normalize_skips([name])[0]
        result["name"] = normalized
    except shared.Refusal:
        result["firstMissingSignal"] = "skip-entry-malformed"
        return result
    if os.geteuid() != 0:
        result["firstMissingSignal"] = "forgejo-skip-check-root-required"
        return result
    try:
        ini = configparser.ConfigParser(interpolation=None, strict=False)
        ini.read_string("[__top__]\n" + APP_INI.read_text(encoding="utf-8"))
        def get(key, default=""):
            return ini.get("database", key, raw=True, fallback=default).strip().strip('"')
        db_type = get("DB_TYPE", "sqlite3").lower()
        database, user = get("NAME"), get("USER")
        host = get("HOST", "127.0.0.1:5432")
        if db_type not in ("postgres", "postgresql") or not DB_NAME.fullmatch(database) or not DB_NAME.fullmatch(user):
            result["firstMissingSignal"] = "postgres-configuration-unsupported"
            return result
        if host not in ("", "127.0.0.1:5432", "localhost:5432", "/var/run/postgresql"):
            result["firstMissingSignal"] = "postgres-host-not-local"
            return result
    except (OSError, UnicodeError, configparser.Error, ValueError):
        result["firstMissingSignal"] = "app-ini-unavailable"
        return result
    parts = normalized.lower().split("/")
    argv = ["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/bin/psql", "-X", "-q", "-A", "-t",
            "-v", "ON_ERROR_STOP=1", "-v", "owner=" + parts[0],
            "-h", "/var/run/postgresql", "-p", "5432", "-d", database]
    if len(parts) == 1:
        sql = 'SELECT EXISTS (SELECT 1 FROM "user" u WHERE u.lower_name = :\'owner\');\n'
    else:
        argv.extend(["-v", "repo=" + parts[1]])
        sql = ('SELECT EXISTS (SELECT 1 FROM repository r JOIN "user" u ON u.id = r.owner_id '
               'WHERE u.lower_name = :\'owner\' AND r.lower_name = :\'repo\');\n')
    try:
        proc = subprocess.run(argv, input=sql.encode(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, timeout=15, check=False)
        output = proc.stdout.strip()
        if proc.returncode or output not in (b"t", b"f"):
            result["firstMissingSignal"] = "forgejo-skip-check-database-unavailable"
            return result
    except (OSError, subprocess.TimeoutExpired):
        result["firstMissingSignal"] = "forgejo-skip-check-database-unavailable"
        return result
    result.update(ok=True, matches=output == b"t", firstMissingSignal="none")
    return result


def main(argv=None):
    del argv
    request = None
    try:
        request = read(known_fields=("name",))
        result = check(request.payload.get("name"))
    except (EnvelopeError, ValueError, UnicodeError):
        result = {"schema": SCHEMA, "ok": False, "name": None, "matches": False,
                  "firstMissingSignal": "forgejo-skip-check-request-invalid"}
    if request is not None:
        result = attach(result, request)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1

"""Ask the HomeServer to pair this backup-drive box."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time

from agathodaimon.lib.keyman_export.index import KeymanExportError, exchange_session
from agathodaimon.keyman.custody import call as custody_call
from agathodaimon.storage.backup.mirror.pull.index import seat

KEYMAN = "/vault/keyman/keyman"
MAC = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\Z")


def wipe(value):
    if value is not None:
        for i in range(len(value)):
            value[i] = 0


def proof():
    # Proof only: all overrides require a named scratch root and local stand-ins.
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    keyman = os.environ.get("BACKUP_DRIVE_PROOF_KEYMAN")
    target = os.environ.get("BACKUP_DRIVE_PROOF_SEAT")
    if not any((root, keyman, target)):
        return None
    if not all((root, keyman, target)):
        raise ValueError("backup-drive-proof-invalid")
    root_path = Path(root).resolve(strict=True)
    executable = Path(keyman).resolve(strict=True)
    host, port = target.rsplit(":", 1)
    port = int(port)
    if root_path == Path("/") or not executable.is_relative_to(root_path) or host != "127.0.0.1" or not 0 < port < 65536:
        raise ValueError("backup-drive-proof-invalid")
    return root_path, str(executable), host, port


def own_mac(context):
    # Proof only: ruyi.json is read below the scratch root in stand-in mode.
    path = context[0] / "ruyi.json" if context else Path("/etc/appliance/ruyi.json")
    value = json.loads(path.read_text()).get("self", {}).get("mac")
    if not isinstance(value, str) or not MAC.fullmatch(value):
        raise ValueError("backup-drive-mac-unavailable")
    return value


def homeserver(context):
    return (context[2], context[3]) if context else seat()


def post(host, port, route, body):
    connection = http.client.HTTPConnection(host, port, timeout=15)
    try:
        connection.request("POST", route, body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError("backup-drive-response-invalid")
        if response.status == 401:
            return 401, None
        value = json.loads(raw)
        if response.status != 200 or not isinstance(value, dict) or value.get("ok") is not True or value.get("state") not in {"pending", "accepted"}:
            raise ValueError("backup-drive-response-invalid")
        return response.status, value["state"]
    finally:
        connection.close()


def new_pair(mac, credential, context):
    payload = bytearray(b'username="')
    try:
        payload.extend(mac.encode("ascii"))
        payload.extend(b'"\npassword="')
        payload.extend(credential)
        payload.extend(b'"\n')
        keyman = context[1] if context else KEYMAN
        env = os.environ.copy()
        env.pop("KEYMAN_ROOT", None)
        if context:
            env["KEYMAN_ROOT"] = str(context[0])
        session = (exchange_session(scratch_root=str(context[0]), exporter=keyman)
                   if context else exchange_session(native=True))
        with session:
            result = custody_call("newkey", subprocess.run, [keyman, "newkey", "--stdin", "backup_pair", "--replace"],
                                    input=payload, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=env, timeout=15, check=False, close_fds=True)
        if result.returncode != 0:
            raise ValueError("backup-drive-keyman-failed")
    finally:
        wipe(payload)


def ask():
    credential = None
    try:
        context = proof()
        mac = own_mac(context)
        host, port = homeserver(context)
        credential = bytearray(secrets.token_urlsafe(48), "ascii")
        new_pair(mac, credential, context)
        body = json.dumps({"mac": mac, "hostname": socket.gethostname(),
                           "credential_sha256": hashlib.sha256(credential).hexdigest()}, separators=(",", ":")).encode()
        status, state = post(host, port, "/api/v1/storage/backup/pair/request", body)
        if status != 200:
            raise ValueError("backup-drive-request-refused")
        return {"ok": True, "state": state, "homeserver": {"ipv4": host, "port": port}}
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError, http.client.HTTPException, KeymanExportError, subprocess.SubprocessError):
        return {"ok": False, "firstMissingSignal": "backup-drive-ask-failed"}
    finally:
        wipe(credential)


def main(_argv=None):
    started = time.monotonic()
    result = ask()
    # A change emits one secret-free canonical deed; the status read emits none.
    print(json.dumps({"who": "agathodaimon", "verb": "backup-drive-ask", "target": "backup_pair",
                      "outcome": "ok" if result["ok"] else "failed", "duration_ms": int((time.monotonic() - started) * 1000),
                      "signal": "none" if result["ok"] else result["firstMissingSignal"]}, separators=(",", ":")), file=sys.stderr)
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

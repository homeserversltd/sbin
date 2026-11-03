"""Read this box's backup pairing state from the HomeServer."""
from __future__ import annotations

import http.client
import json
import subprocess

from agathodaimon.lib.keyman_export.index import KeymanExportError, MISSING_KEY, export_credential
from agathodaimon.storage.backup.drive.ask.index import MAC, homeserver, post, proof, wipe


def status():
    username = password = body = None
    try:
        context = proof()
        # Proof only: export uses the labelled scratch Keyman and exchange root.
        if context:
            username, password = export_credential("backup_pair", scratch_root=str(context[0]), exporter=context[1])
        else:
            username, password = export_credential("backup_pair")
        mac = username.decode("ascii")
        token = password.decode("ascii")
        if not MAC.fullmatch(mac) or not token or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise ValueError("backup-drive-credential-invalid")
        body = bytearray(json.dumps({"mac": mac, "credential": token}, separators=(",", ":")), "ascii")
        del token
        host, port = homeserver(context)
        code, state = post(host, port, "/api/v1/storage/backup/pair/status", body)
        return {"ok": True, "state": "unknown" if code == 401 else state}
    except KeymanExportError as error:
        return {"ok": False, "firstMissingSignal": "backup-drive-not-asked" if error.signal == MISSING_KEY else "backup-drive-status-failed"}
    except (OSError, ValueError, TypeError, AttributeError, RuntimeError, http.client.HTTPException, subprocess.SubprocessError):
        return {"ok": False, "firstMissingSignal": "backup-drive-status-failed"}
    finally:
        wipe(username)
        wipe(password)
        wipe(body)


def main(_argv=None):
    result = status()
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Woodpecker agent token custody and non-secret posture."""
from __future__ import annotations

import grp
import json
import os
from pathlib import Path
import stat
import sys
import time
import uuid

from agathodaimon.lib.receipts.index import emit
from agathodaimon.thyrsus._common import _rooted
from agathodaimon.unit import _control

TOKEN = "/etc/woodpecker-agent/token"
UNIT = "woodpecker-agent.service"


class Refusal(Exception):
    pass


def _token(arguments):
    if arguments or (len(sys.argv) > 2 and sys.argv[1] == "woodpecker/agent-token"):
        raise Refusal("woodpecker-token-stdin-required")
    raw = sys.stdin.read(65537)
    if len(raw) > 65536:
        raise Refusal("woodpecker-request-too-large")
    try:
        obj = json.loads(raw)
    except ValueError:
        obj = None
    if isinstance(obj, dict):
        payload = obj.get("payload")
        if not isinstance(payload, dict):
            payload = obj
        value = payload.get("token")
    else:
        value = raw.removesuffix("\n")
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or not value.isprintable() or any(c.isspace() for c in value)):
        raise Refusal("woodpecker-token-invalid")
    return value


def _store(token, receipt):
    path = _rooted(TOKEN)
    scratch = os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None
    # Only the named directory is created; its parent belongs to the system.
    try:
        path.parent.mkdir(mode=0o750)
        created = True
    except FileExistsError:
        created = False
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = ".agent-token-" + uuid.uuid4().hex
    staged = False
    try:
        if created:
            if os.geteuid() == 0:
                os.fchown(directory, 0, grp.getgrnam("woodpecker-agent").gr_gid)
            os.fchmod(directory, 0o750)
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        staged = True
        try:
            if os.geteuid() == 0:
                os.fchown(fd, 0, grp.getgrnam("woodpecker-agent").gr_gid)
            os.fchmod(fd, 0o640)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                stream.write(token.encode("utf-8") + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd >= 0:
                os.close(fd)
        os.replace(name, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        staged = False
        receipt["mutationPerformed"] = True
        receipt["file"] = TOKEN
        os.fsync(directory)
    finally:
        if staged:
            os.unlink(name, dir_fd=directory)
        os.close(directory)


def _present():
    try:
        fd = os.open(_rooted(TOKEN), os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            return stat.S_ISREG(info.st_mode) and info.st_size > 0
        finally:
            os.close(fd)
    except (FileNotFoundError, PermissionError):
        return False


def _deed(receipt, started):
    from agathodaimon._deed import send
    if not send("sbin", "woodpecker-agent-token", receipt["ok"], target="woodpecker-agent",
                duration_ms=int((time.monotonic() - started) * 1000)):
        raise OSError("ledger-write-failed")


def main_for(verb, arguments=None):
    started = time.monotonic()
    receipt = {"schema": "caduceus.staff.v1", "ok": False,
               "firstMissingSignal": "none", "mutationPerformed": False}
    try:
        if verb == "agent-token":
            receipt.update(file=None, restart=None, restarted=False)
            token = _token(list(arguments or []))
            try:
                _store(token, receipt)
            finally:
                token = None
            if os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None:
                receipt["restart"] = "skipped"
            else:
                result = _control.control("restart", UNIT, "system")
                receipt["restart"] = result
                if not result["ok"]:
                    raise Refusal("woodpecker-unit-restart-failed")
                # The door and the face read this boolean; the restart object stays for the record.
                receipt["restarted"] = True
        else:
            if arguments:
                raise Refusal("woodpecker-arguments-invalid")
            present = _present()
            if os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None:
                active = False
            else:
                result = _control.control("status", UNIT, "system")
                active = result["readback"]["active_state"] == "active"
            receipt.update(token_present=present, unit_active=active)
        receipt["ok"] = True
    except Refusal as error:
        receipt["firstMissingSignal"] = str(error)
    except (OSError, ValueError, UnicodeError, KeyError, TypeError):
        receipt["firstMissingSignal"] = "woodpecker-operation-failed"
    if verb == "agent-token":
        try:
            _deed(receipt, started)
        except (OSError, ValueError):
            receipt.update(ok=False, firstMissingSignal="woodpecker-ledger-unavailable")
    receipt["final"] = {"ok": receipt["ok"], "signal": receipt["firstMissingSignal"],
                        "mutationPerformed": receipt["mutationPerformed"]}
    return emit(receipt)

"""Woodpecker agent token custody and non-secret posture."""
from __future__ import annotations

import grp
import os
from pathlib import Path
import stat
import time
import uuid

from agathodaimon.lib.receipts.index import emit
from agathodaimon import _envelope
from agathodaimon.thyrsus._common import _rooted
from agathodaimon.unit import _control

TOKEN = "/etc/woodpecker-agent/token"
UNIT = "woodpecker-agent.service"


class Refusal(Exception):
    pass


def _token():
    try:
        request = _envelope.read(known_fields=("token",), secret_bytes=("token",),
                                 max_input_bytes=65536)
    except _envelope.EnvelopeError as error:
        signal = str(error)
        if signal == "agathodaimon-envelope-input-too-large":
            raise Refusal("woodpecker-request-too-large") from None
        if signal == "agathodaimon-vault-open-request-invalid":
            raise Refusal("woodpecker-token-invalid") from None
        raise Refusal("woodpecker-request-invalid") from None
    token = request.secret_bytes.get("token")
    if token is None:
        raise Refusal("woodpecker-token-invalid")
    try:
        value = token.decode("utf-8")
        valid = (1 <= len(value) <= 256 and value.isprintable()
                 and not any(c.isspace() for c in value))
        del value
        if not valid:
            raise Refusal("woodpecker-token-invalid")
        return token
    except BaseException:
        _envelope.wipe_bytes(token)
        raise


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
    send("sbin", "woodpecker-agent-token", receipt["ok"], target="woodpecker-agent",
         duration_ms=int((time.monotonic() - started) * 1000))


def main_for(verb, arguments=None):
    started = time.monotonic()
    receipt = {"ok": False,
               "firstMissingSignal": "none", "mutationPerformed": False}
    try:
        if verb == "agent-token":
            receipt.update(file=None, restart=None, restarted=False)
            token = _token()
            try:
                _store(token.decode("utf-8"), receipt)
            finally:
                _envelope.wipe_bytes(token)
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

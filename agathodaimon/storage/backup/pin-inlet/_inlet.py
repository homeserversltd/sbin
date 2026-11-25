"""Bounded Keyman custody for the HomeServer's box PIN inlets."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from importlib import import_module

from agathodaimon._envelope import EnvelopeError, read, wipe_bytes
from agathodaimon._nidus.lock import held, identity_lock_path
from agathodaimon.keyman.custody import call as custody_call
from agathodaimon.lib.keyman_export.index import (
    KEYMAN, MISSING_KEY, KeymanExportError, exchange_session, export_credential,
)

NAME = re.compile(r"[a-z][a-z0-9_]{0,53}_pin_inlet\Z")
MAC = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")


def context():
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    keyroot = os.environ.get("KEYMAN_ROOT")
    if root != keyroot or (root is not None and (not os.path.isabs(root) or os.path.realpath(root) == "/")):
        raise ValueError("scratch context")
    return root


def exists(root, name):
    directory = Path(root or "/") / "vault/.keys"
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            meta = os.stat(name + ".key", dir_fd=fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(meta.st_mode):
            raise ValueError("not a key file")
        return True
    finally:
        os.close(fd)


def newkey(name, username, password):
    previous = sys.stdin
    try:
        with io.BytesIO(password) as source, io.StringIO() as output, io.StringIO() as errors:
            sys.stdin = source
            try:
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    rc = import_module("agathodaimon.keyman.newkey.index").main(
                        [name, "--username", username, "--pword", "-", "--replace"])
                answer = json.loads(output.getvalue())
            finally:
                with source.getbuffer() as buffer:
                    buffer[:] = b"\0" * len(buffer)
        from agathodaimon.keyman._common import _scrub
        secrets = {password.decode("utf-8")}
        ok_key, mutation_key = _scrub({"ok": None, "mutationPerformed": None}, secrets)
        return (isinstance(answer, dict) and answer.get(ok_key) is True
                and answer.get(mutation_key) is True and rc == (0 if ok_key == "ok" else 1))
    finally:
        sys.stdin = previous


def delete(root, name):
    session = exchange_session(scratch_root=root, exporter=KEYMAN, native=True) if root else exchange_session(native=True)
    with session:
        result = custody_call("delete", subprocess.run, [KEYMAN, "delete", name],
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=30, check=False, close_fds=True)
        answer = json.loads(result.stdout)
        return (result.returncode == 0 and isinstance(answer, dict) and answer.get("ok") is True
                and answer.get("operation") == "delete" and answer.get("service") == name
                and answer.get("secret_free") is True and answer.get("deleted") is True
                and not exists(root, name))


def deed(verb, ok, name):
    from agathodaimon._deed import send
    try:
        with contextlib.redirect_stderr(io.StringIO()):
            send("sbin", "pin-inlet-" + verb, ok, target="keyman",
                 outcome="ok" if ok else "refused", ref=name)
    except Exception:
        pass


def main(verb):
    password = username_bytes = exported = None
    name = None
    result = {"ok": False, "firstMissingSignal": "pin-inlet-" + ({"put": "store", "delete": "delete", "export": "export"}[verb]) + "-failed"}
    if verb == "put":
        result.update(name=None, replaced=False)
    elif verb == "delete":
        result["deleted"] = False
    try:
        try:
            request = read(known_fields=("name", "username"), secret_bytes=("password",) if verb == "put" else (), max_input_bytes=16384, quiet_on_tty=True)
        except EnvelopeError:
            raise ValueError("pin-inlet-value-invalid" if verb == "put" else "pin-inlet-name-invalid") from None
        password = request.secret_bytes.get("password")
        name = request.payload.get("name")
        if not isinstance(name, str) or NAME.fullmatch(name) is None:
            name = None
            raise ValueError("pin-inlet-name-invalid")
        if verb == "put":
            username = request.payload.get("username")
            if not isinstance(username, str) or MAC.fullmatch(username) is None:
                raise ValueError("pin-inlet-username-invalid")
            if not isinstance(password, bytearray) or not 1 <= len(password) <= 511 or any(x in password for x in b'\0\r\n"'):
                raise ValueError("pin-inlet-value-invalid")
            result["name"] = name
        root = context()
        with held("pin-inlet", path=identity_lock_path().parent / "pin-inlet.lock"):
            if verb == "put":
                result["replaced"] = exists(root, name)
                if result["replaced"]:
                    try:
                        if root:
                            username_bytes, exported = export_credential(name, scratch_root=root, exporter=KEYMAN)
                        else:
                            username_bytes, exported = export_credential(name)
                        matches = username_bytes == username.encode("ascii")
                    except KeymanExportError:
                        matches = False
                    finally:
                        if username_bytes is not None:
                            wipe_bytes(username_bytes)
                        if exported is not None:
                            wipe_bytes(exported)
                    if not matches:
                        raise ValueError("pin-inlet-name-taken")
                if not newkey(name, username, password):
                    raise RuntimeError("store")
            elif verb == "delete":
                if exists(root, name):
                    if not delete(root, name):
                        raise RuntimeError("delete")
                    result["deleted"] = True
            else:
                try:
                    if root:
                        username_bytes, exported = export_credential(name, scratch_root=root, exporter=KEYMAN)
                    else:
                        username_bytes, exported = export_credential(name)
                except KeymanExportError as error:
                    if error.signal == MISSING_KEY:
                        raise ValueError("pin-inlet-missing") from None
                    raise
                username = username_bytes.decode("utf-8")
                if MAC.fullmatch(username) is None or not 1 <= len(exported) <= 511 or any(x in exported for x in b'\0\r\n"'):
                    raise RuntimeError("invalid stored credential")
                result["username"] = username
                result["password"] = exported.decode("utf-8")
        result.update(ok=True, firstMissingSignal="none")
    except ValueError as error:
        if str(error) in {"pin-inlet-name-invalid", "pin-inlet-username-invalid", "pin-inlet-value-invalid", "pin-inlet-missing", "pin-inlet-name-taken"}:
            result["firstMissingSignal"] = str(error)
    except Exception:
        pass
    finally:
        if password is not None:
            wipe_bytes(password)
    if not result["ok"] or verb == "put" or (verb == "delete" and result["deleted"]):
        deed(verb, result["ok"], name)
    try:
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=True))
    finally:
        result.pop("password", None)
        if username_bytes is not None:
            wipe_bytes(username_bytes)
        if exported is not None:
            wipe_bytes(exported)
    return 0 if result["ok"] else 1

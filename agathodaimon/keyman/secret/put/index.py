"""Put a named value into Keyman from an envelope or flat JSON request."""
from __future__ import annotations

import contextlib
import io
import json
import os
from importlib import import_module
from pathlib import Path
import re
import stat
import sys
import time
import unicodedata
from uuid import uuid4

from agathodaimon._envelope import EnvelopeError, read, wipe_bytes
from agathodaimon._nidus.lock import household_config_held
from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon.keyman._common import _scrub

_CONFIG = import_module("agathodaimon.update.module-toggle.index")
_BAND = "keyman/secret/put"
_PREFIX = "keyman-secret-"
_MAX_INPUT = 16384
_NAME = re.compile(r"[A-Za-z0-9_]{1,64}")
_NEWKEY_SIGNAL = re.compile(r"keyman-newkey-([a-z0-9-]{1,80})")


class Refusal(Exception):
    """Only fixed signals or a validated, secret-free newkey signal tail."""


def _request():
    try:
        return read(known_fields=("name", "about", "value"),
                    secret_bytes=("value",), max_input_bytes=_MAX_INPUT,
                    quiet_on_tty=True)
    except EnvelopeError as error:
        signal = "value-invalid" if str(error) == "agathodaimon-vault-open-request-invalid" else "request-invalid"
        raise Refusal(signal) from None


def _valid_about(about):
    return about is None or (isinstance(about, str) and len(about) <= 200 and
                            all(unicodedata.category(c) not in {"Cc", "Cs"} for c in about))


def _valid_value(value):
    return (isinstance(value, bytearray) and 1 <= len(value) <= 511 and
            not any(c in value for c in b'\0\r\n"'))


def _public_fields(name, about, value):
    # Neither the service label (which newkey takes on argv) nor the public
    # description may carry a copy of the submitted value.
    if value in name.encode("utf-8"):
        raise Refusal("name-invalid")
    if about is not None and value in about.encode("utf-8"):
        raise Refusal("about-invalid")


def _identity(info):
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _config_snapshot(directory, filename):
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode):
            raise Refusal("config-invalid")
        raw = stream.read().decode("utf-8")
        if _identity(os.fstat(stream.fileno())) != _identity(meta):
            raise Refusal("config-changed")
    return raw, meta


def _replace_config(directory, filename, raw, meta, updated):
    # Same-directory staging and fsyncs, with mode set *after* fchown (which
    # can clear permission bits). No backup, and no following a config symlink.
    staged = ".config." + uuid4().hex
    fd = os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(updated)
            stream.flush()
            os.fchown(stream.fileno(), meta.st_uid, meta.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(meta.st_mode))
            os.fsync(stream.fileno())
        try:
            current, current_meta = _config_snapshot(directory, filename)
        except FileNotFoundError:
            raise Refusal("config-changed") from None
        if current != raw or _identity(meta) != _identity(current_meta):
            raise Refusal("config-changed")
        os.replace(staged, filename, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(staged, dir_fd=directory)
        except FileNotFoundError:
            pass


def _register(raw, name):
    document = _CONFIG._load(raw)
    section = document.get("secrets")
    if section is not None and not isinstance(section, dict):
        raise Refusal("register-invalid")
    entries = None if section is None else section.get("entries")
    if entries is None:
        entries = []
    if not isinstance(entries, list):
        raise Refusal("register-invalid")
    matched = None
    matches = 0
    for index, entry in enumerate(entries):
        listed = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(listed, str) or listed.lower() != name.lower():
            continue
        if entry.get("builtin") is True:
            raise Refusal("name-builtin")
        matches += 1
        matched = index
    if matches > 1:
        raise Refusal("register-invalid")
    return section, entries, matched


def _edited_config(raw, section, entries):
    start, end, members = _CONFIG._object_members(raw)
    rendered = json.dumps(entries, ensure_ascii=True)
    if section is None:
        key = "secrets"
        rendered = '{"entries": ' + rendered + "}"
    else:
        key = "entries"
        start, end, members = _CONFIG._object_members(raw, members["secrets"][0])
    if key in members:
        first, last = members[key]
        return raw[:first] + rendered + raw[last:]

    # Insert before the closing trivia, leaving even CRLF and outer whitespace
    # byte-for-byte as they were. Keep the local member spacing when multiline.
    insertion_at = max((span[1] for span in members.values()), default=start + 1)
    spacer = " " if members else ""
    if "\n" in raw[start:end]:
        lead = raw[start + 1:insertion_at]
        newline = "\r\n" if "\r\n" in raw[start:end] else "\n"
        spacer = lead[:len(lead) - len(lead.lstrip(" \t\r\n"))] if members else newline + "  "
    insertion = ("," if members else "") + spacer + json.dumps(key) + ": " + rendered
    return raw[:insertion_at] + insertion + raw[insertion_at:]


def _vault_dir():
    scratch = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    keyman_root = os.environ.get("KEYMAN_ROOT")
    if scratch != keyman_root:
        raise Refusal("vault-scratch-context-invalid")
    return Path(scratch or "/") / "vault" / ".keys"


def _existing_key(name, owner):
    filename = name + ".key"
    try:
        directory = os.open(_vault_dir(), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            matches = {item for item in os.listdir(directory) if item.lower() == filename.lower()}
            if not matches:
                return False
            if (not owner or matches != {filename} or
                    not stat.S_ISREG(os.stat(filename, dir_fd=directory, follow_symlinks=False).st_mode)):
                raise Refusal("name-held")
            return True
        finally:
            os.close(directory)
    except OSError:
        # No vault directory (or no permission to enumerate it) is not proof
        # that the name is free. Never fall back to a different root.
        raise Refusal("vault-unobservable") from None


def _newkey(name, value, secrets):
    original = sys.stdin
    try:
        with io.BytesIO(value) as source, io.StringIO() as output, io.StringIO() as errors:
            sys.stdin = source
            try:
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
                    setter = import_module("agathodaimon.keyman.newkey.index")
                    status = setter.main([name, "--username", "secret", "--pword", "-", "--replace"])
                answer = json.loads(output.getvalue())
            finally:
                with source.getbuffer() as buffer:
                    buffer[:] = b"\0" * len(buffer)
    except (Exception, SystemExit):
        return False, "vault-receipt-invalid", None
    finally:
        sys.stdin = original
    if not isinstance(answer, dict):
        return False, "vault-receipt-invalid", None

    # newkey passes even its wire keys through _scrub. Recover just the three
    # known fields, including its derived exit status if 'ok' was masked.
    ok_key, signal_key, mutation_key = _scrub(
        {"ok": None, "firstMissingSignal": None, "mutationPerformed": None}, secrets)
    mutation = answer.get(mutation_key)
    if answer.get(ok_key) is True and status == (0 if ok_key == "ok" else 1):
        return True, "none", True
    signal = answer.get(signal_key)
    match = _NEWKEY_SIGNAL.fullmatch(signal) if isinstance(signal, str) else None
    tail = match[1] if match and value not in match[1].encode("utf-8") else "refused"
    return False, "vault-" + tail, mutation if isinstance(mutation, bool) else None


def _put(name, about, value, secrets, receipt):
    path = appliance_runtime_path("config")
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw, _ = _config_snapshot(directory, path.name)
        section, entries, matched = _register(raw, name)
        owner = matched is not None and entries[matched].get("builtin") is False
        if matched is not None:
            name = entries[matched]["name"]  # Keyman's filename is case-sensitive.
            if not _NAME.fullmatch(name):
                raise Refusal("register-invalid")
        receipt["name"] = name
        existing = _existing_key(name, owner)
        receipt["replaced"] = matched is not None or existing
        _public_fields(name, about, value)
        if os.geteuid() != 0:
            raise Refusal("vault-root-required")
    finally:
        os.close(directory)
    # Custody may launch a child; it must finish before taking the house lock.
    ok, signal, mutation = _newkey(name, value, secrets)
    receipt["mutationPerformed"] = mutation
    if not ok:
        raise Refusal(signal)
    with household_config_held():
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            raw, meta = _config_snapshot(directory, path.name)
            section, entries, current = _register(raw, name)
            if (current is None) != (matched is None):
                raise Refusal("config-changed")
            if current is not None and (entries[current].get("name") != name or
                                        (entries[current].get("builtin") is False) != owner):
                raise Refusal("config-changed")
            entry = {"name": name, "about": about, "builtin": False}
            if current is None:
                entries.append(entry)
            else:
                entries[current] = entry
            updated = _edited_config(raw, section, entries).encode("utf-8")
            _replace_config(directory, path.name, raw, meta, updated)
        finally:
            os.close(directory)


def _safe_refusal_signal(signal, secrets, *, deed=False):
    # A submitted value can itself be a diagnostic. Keep the required namespace
    # and use a fixed fallback rather than replaying such a value in the tail.
    for candidate in (signal, _PREFIX + "refused", _PREFIX + "error"):
        if deed and len(candidate) > 40:  # The hyalos sender's signal limit.
            continue
        if all(secret in _PREFIX or secret not in candidate for secret in secrets):
            return candidate
    return _PREFIX + "error"


def main(argv=None):
    started = time.monotonic()
    receipt = {"ok": False, "firstMissingSignal": "none", "mutationPerformed": False,
               "name": None, "about": None, "replaced": False}
    secrets = set()
    value = None
    try:
        request = _request()
        name, about = (request.payload.get(key) for key in ("name", "about"))
        value = request.secret_bytes.get("value")
        if value:
            secrets.add(value.decode("utf-8"))
        if not isinstance(name, str) or not _NAME.fullmatch(name):
            raise Refusal("name-invalid")
        receipt["name"] = name
        if not _valid_about(about):
            raise Refusal("about-invalid")
        receipt["about"] = about
        if not _valid_value(value):
            raise Refusal("value-invalid")
        _put(name, about, value, secrets, receipt)
        receipt["ok"] = True
    except Refusal as error:
        receipt["firstMissingSignal"] = _PREFIX + str(error)
    except (OSError, ValueError, RecursionError):
        receipt["firstMissingSignal"] = _PREFIX + "config-unavailable"
    finally:
        if value is not None:
            wipe_bytes(value)

    # Scrub caller-derived metadata without changing the wire field names.
    for key in ("name", "about"):
        safe = _scrub(receipt[key], secrets)
        receipt[key] = None if isinstance(safe, str) and any(secret in safe for secret in secrets) else safe
    signal = receipt["firstMissingSignal"]
    if not receipt["ok"]:
        receipt["firstMissingSignal"] = _safe_refusal_signal(signal, secrets)
        signal = _safe_refusal_signal(receipt["firstMissingSignal"], secrets, deed=True)
    from agathodaimon._deed import send
    send("keyman", "secret-put", receipt["ok"], signal=signal,
         duration_ms=int((time.monotonic() - started) * 1000))
    # The slash stream bypasses the stdout wrapper. Use the front door's own
    # receipt stamper here too so that both invocation forms answer identically.
    from agathodaimon.cli import _stamp_receipt
    print(json.dumps(_stamp_receipt(receipt, _BAND), separators=(",", ":")))
    return 0 if receipt["ok"] else 1

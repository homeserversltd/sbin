"""Marked-block file mechanics for the parity Sway overrides."""
from __future__ import annotations

import grp
import os
import pwd
import stat

from agathodaimon._nidus.write import WriteError, write
from agathodaimon.settings import _shared


def path():
    return _shared.home() / ".config/sway/input-overrides.conf"


def read_block(begin, end):
    lines = _shared.ini_read(path())
    if begin not in lines or end not in lines:
        return None
    start, stop = lines.index(begin), lines.index(end)
    if stop <= start:
        return None
    return lines[start + 1:stop]


def replace_blocks(blocks, receipt, invalid, *, strict_order=False, reload=None, apply_live=None):
    target = path()
    try:
        metadata = target.lstat()
    except FileNotFoundError:
        metadata, original = None, None
    else:
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(invalid)
        original = target.read_bytes()
    lines = (original or b"").splitlines(keepends=True)
    for begin, end, body in blocks:
        start_marker, end_marker = begin.encode().rstrip(b"\r\n"), end.encode().rstrip(b"\r\n")
        starts = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == start_marker]
        stops = [i for i, line in enumerate(lines) if line.rstrip(b"\r\n") == end_marker]
        if starts or stops:
            if len(starts) != 1 or len(stops) != 1 or stops[0] < starts[0] or (strict_order and stops[0] == starts[0]):
                raise ValueError(invalid)
            del lines[starts[0]:stops[0] + 1]
        if lines and not lines[-1].endswith(b"\n"):
            lines.append(b"\n")
        lines.extend(line.encode() for line in (begin, *body, end))
    candidate = b"".join(lines)
    edit = {"path": target, "candidate": candidate}
    owner_changed = False
    if _shared.home() == _shared.OWNER_HOME:
        owner = pwd.getpwnam(_shared.OWNER_USER)
        if os.geteuid() in (0, owner.pw_uid):
            edit["owner"] = (owner.pw_name, grp.getgrgid(owner.pw_gid).gr_name)
            owner_changed = metadata is not None and (metadata.st_uid, metadata.st_gid) != (owner.pw_uid, owner.pw_gid)
    if candidate != original or owner_changed:
        receipt.backup(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    parts = write([edit], reload=reload, readback=apply_live)
    receipt.changed |= parts["changed"]


def replace_block(begin, end, body, receipt, invalid, *, strict_order=False):
    try:
        replace_blocks([(begin, end, body)], receipt, invalid, strict_order=strict_order)
    except WriteError as error:
        if error.restore_errors:
            raise
        raise error.cause from error


def restore_backup(target, original, metadata):
    edit = {"path": target, "candidate": original}
    if original is not None:
        edit.update(mode=metadata["mode"], owner=(pwd.getpwuid(metadata["uid"]).pw_name,
                                                   grp.getgrgid(metadata["gid"]).gr_name))
    write([edit])

"""Marked-block file mechanics for the parity Sway overrides."""
from __future__ import annotations

import os
import pwd

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


def replace_block(begin, end, body, receipt, invalid, *, strict_order=False):
    target = path()
    lines = _shared.ini_read(target)
    if begin in lines and end in lines:
        start, stop = lines.index(begin), lines.index(end)
        if stop < start or (strict_order and stop == start):
            raise ValueError(invalid)
        del lines[start:stop + 1]
    elif begin in lines or end in lines:
        raise ValueError(invalid)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    lines += [begin, *body, end]
    receipt.replace(target, "".join(lines).encode())
    if os.geteuid() == 0 and _shared.home() == _shared.OWNER_HOME:
        owner = pwd.getpwnam(_shared.OWNER_USER)
        os.chown(target, owner.pw_uid, owner.pw_gid)

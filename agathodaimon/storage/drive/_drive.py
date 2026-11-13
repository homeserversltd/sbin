"""Read mount state and the owner's numeric identity for data drives."""
from __future__ import annotations

import pwd
import re

from agathodaimon.storage.nas import runtime as _runtime


def mountinfo_entries() -> list[dict]:
    try:
        text = _runtime.runtime_path(_runtime.MOUNTINFO).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise _runtime.Refusal("agathodaimon-drive-mount-census-unavailable", "mount-census") from None
    entries = []
    for line in text.splitlines():
        before, separator, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if not separator or len(fields) < 6 or len(tail) < 2 or not re.fullmatch(r"\d+:\d+", fields[2]):
            raise _runtime.Refusal("agathodaimon-drive-mount-census-invalid", "mount-census")
        def unescape(value):
            return _runtime.MOUNT_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)
        entries.append({"target": unescape(fields[4]), "root": unescape(fields[3]),
                        "dev": fields[2], "source": unescape(tail[1]),
                        "fstype": tail[0], "superOptions": unescape(tail[2]) if len(tail) > 2 else ""})
    if not entries:
        raise _runtime.Refusal("agathodaimon-drive-mount-census-invalid", "mount-census")
    return entries


def mount_of(node: dict) -> dict | None:
    return next((entry for entry in mountinfo_entries() if entry["dev"] == node["maj:min"]), None)


def owner_identity() -> tuple[int, int]:
    try:
        owner = pwd.getpwnam("owner")
    except KeyError:
        raise _runtime.Refusal("agathodaimon-drive-owner-unresolved", "owner-identity") from None
    return owner.pw_uid, owner.pw_gid

"""Read mount state and the owner's numeric identity for data drives."""
from __future__ import annotations

import pwd

from agathodaimon.storage.nas import runtime as _runtime


def mountinfo_entries() -> list[dict]:
    try:
        return _runtime._mountinfo()
    except _runtime.Refusal as failure:
        signals = {
            "agathodaimon-nas-mount-census-unavailable": "agathodaimon-drive-mount-census-unavailable",
            "agathodaimon-nas-mount-census-invalid": "agathodaimon-drive-mount-census-invalid",
            "agathodaimon-nas-mount-census-empty": "agathodaimon-drive-mount-census-invalid",
        }
        if failure.signal_name not in signals:
            raise
        raise _runtime.Refusal(signals[failure.signal_name], failure.step,
                               failure.return_code, failure.receipt) from None


def mount_of(node: dict) -> dict | None:
    return next((entry for entry in mountinfo_entries() if entry["dev"] == node["maj:min"]), None)


def owner_identity() -> tuple[int, int]:
    try:
        owner = pwd.getpwnam("owner")
    except KeyError:
        raise _runtime.Refusal("agathodaimon-drive-owner-unresolved", "owner-identity") from None
    return owner.pw_uid, owner.pw_gid

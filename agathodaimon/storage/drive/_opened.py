"""The persistent set of data drives opened by the staff."""
from __future__ import annotations

import os
import re
import sqlite3
import stat
from urllib.parse import quote

from agathodaimon.storage.nas import runtime

PATH = "/var/lib/agathodaimon/opened-drives.sqlite3"
_LABEL = re.compile(r"[A-Za-z0-9_-]{1,32}\Z")
_ID = re.compile(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)\Z")
_RESERVED = {"nas", "nas_backup", "global", "homes", "printers", "print$"}


def valid_label(label):
    return isinstance(label, str) and bool(_LABEL.fullmatch(label)) and label.lower() not in _RESERVED


def _connect(create=False, writable=False):
    path = runtime.runtime_path(PATH)
    if create:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = os.lstat(path.parent)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) != 0o700:
            raise OSError("unsafe ledger directory")
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600) if not path.exists() else None
        if fd is not None:
            os.close(fd)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if create:
            raise
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600:
        raise OSError("unsafe ledger")
    conn = sqlite3.connect("file:" + quote(str(path), safe="/") + "?mode=" + ("rw" if create or writable else "ro"), uri=True, isolation_level=None, timeout=5)
    if create:
        conn.execute("CREATE TABLE IF NOT EXISTS opened (label TEXT PRIMARY KEY, device_identity TEXT NOT NULL, mountpoint TEXT NOT NULL)")
    return conn


def record(label, device_identity):
    if not valid_label(label) or not isinstance(device_identity, str) or not _ID.fullmatch(device_identity):
        raise ValueError("invalid opened drive")
    runtime._require_root({})
    with runtime.drive_guard():
        conn = _connect(create=True)
        if conn is None:
            raise OSError("ledger unavailable")
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO opened(label, device_identity, mountpoint) VALUES(?, ?, ?) ON CONFLICT(label) DO UPDATE SET device_identity=excluded.device_identity, mountpoint=excluded.mountpoint WHERE device_identity != excluded.device_identity OR mountpoint != excluded.mountpoint", (label, device_identity, "/mnt/" + label))
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()


def rows():
    conn = _connect()
    if conn is None:
        return []
    try:
        return [dict(label=label, device_identity=identity, mountpoint=mountpoint) for label, identity, mountpoint in conn.execute("SELECT label, device_identity, mountpoint FROM opened ORDER BY label")]
    finally:
        conn.close()


def forget(label):
    runtime._require_root({})
    with runtime.drive_guard():
        return _forget_many([label])


def _forget_many(labels):
    if not labels:
        return []
    conn = _connect(writable=True)
    if conn is None:
        return []
    removed = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        for label in labels:
            if conn.execute("DELETE FROM opened WHERE label = ?", (label,)).rowcount:
                removed.append(label)
        conn.commit()
        return removed
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()

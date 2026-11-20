"""Rebuild Samba's drive-only share file from verified live mounts."""
from __future__ import annotations

import os
import re
import sqlite3

from agathodaimon._nidus.write import WriteError, write
from agathodaimon.storage.drive import _opened
from agathodaimon.storage.nas import runtime

FILE = "/etc/samba/drives.conf"
SMB = "/etc/samba/smb.conf"
TESTPARM = "/usr/bin/testparm"


def _smb_config():
    try:
        raw, _ = runtime._read_regular_nofollow(SMB)
        text = raw.decode("utf-8")
    except (OSError, UnicodeError):
        raise runtime.Refusal("agathodaimon-drive-shares-smb-conf-unavailable", "smb-conf") from None
    included = False
    sections = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        section = re.fullmatch(r"\[([^\]]+)\]\s*(?:[;#].*)?", line)
        if section:
            sections.add(section.group(1).strip().casefold())
            continue
        key, separator, value = line.partition("=")
        if separator and key.strip().casefold() == "include" and value.strip() == FILE:
            included = True
    return included, sections


def _nas_live(mount, info):
    if not mount or mount["fstype"] != "xfs":
        return False
    mapper = "/dev/mapper/" + info["mapper"]
    try:
        identity = runtime._device_identity(mapper, "mapper-readback")
        if mount["dev"] != identity or runtime._device_identity(mount["source"], "mapper-readback") != identity:
            return False
        name = runtime._sysfs_block_name(identity)
        if not re.fullmatch(r"dm-[0-9]+", name):
            return False
        slaves = runtime.runtime_path("/sys/block/" + name + "/slaves")
        names = os.listdir(slaves)
        if not names:
            return False
        for slave in names:
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", slave):
                return False
            if not (runtime.runtime_path("/sys/class/block/" + slave).exists() and (slaves / slave).exists()):
                return False
        return True
    except (OSError, runtime.Refusal):
        return False


def _render(shares):
    lines = ["# Written by the staff from attached drives; replaced whole on the next rebuild.", ""]
    for share in shares:
        name, path = share["name"], share["path"]
        lines.append("[" + name + "]")
        if name == "nas":
            lines.append("    comment = NAS Storage")
        lines.extend(["    path = " + path, "    browseable = yes", "    read only = no", "    guest ok = no", "    valid users = owner"])
        if name in ("nas", "nas_backup"):
            lines.extend(["    create mask = 0777", "    directory mask = 0777"])
        lines.append("")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _reload_samba():
    result = runtime._run([runtime.SYSTEMCTL, "reload", "smbd.service"], step="reload")
    if result.returncode:
        raise runtime.Refusal("agathodaimon-drive-shares-reload-failed", "reload", result.returncode)


def _write_config(data, receipt, included):
    def check():
        # testparm consumes the candidate without a second on-disk writer.
        result = runtime._run([TESTPARM, "-s", "/dev/stdin"], input_data=data, step="candidate-validation")
        if result.returncode:
            raise runtime.Refusal("agathodaimon-drive-shares-candidate-invalid", "candidate-validation", result.returncode)

    def readback():
        if runtime._read_regular_nofollow(FILE)[0] != data:
            raise runtime.Refusal("agathodaimon-drive-shares-readback-mismatch", "readback")

    cause = None
    try:
        parts = write([{"path": runtime.runtime_path(FILE), "candidate": data, "mode": 0o644}],
                      check=check, reload=_reload_samba if included else None,
                      readback=readback)
    except WriteError as failure:
        parts, cause = failure.parts, failure.cause
    steps = parts["attempt"]["steps"]
    receipt["steps"].extend(steps)
    receipt.update(observed={"files": parts["observed"]},
                   could_change_to={"files": parts["could_change_to"]},
                   attempt=parts["attempt"],
                   changed=any(row["before"] != row["after"] for row in parts["observed"]))
    # Count the act even after compensation, but distinguish reloading the restored bytes.
    if any(row["step"] in {"reload", "restore"} or (row["step"] == "replace" and row["outcome"] == "ok")
           for row in steps):
        receipt["mutationPerformed"] = True
    receipt["reloaded"] = cause is None and any(row["step"] == "reload" for row in steps)
    if isinstance(cause, runtime.Refusal):
        raise cause from None
    if cause is not None:
        raise runtime.Refusal("agathodaimon-drive-shares-io-failed", "shares-io") from None


def rebuild(exclude_mountpoints=(), *, force_reload=False):
    receipt = {"ok": False, "firstMissingSignal": "agathodaimon-drive-shares-incomplete", "changed": False, "mutationPerformed": False, "reloaded": False, "file": FILE, "includedBySmbConf": False, "shares": [], "pruned": [], "steps": []}
    try:
        runtime._require_root({})
        receipt["steps"].append({"step": "root-preflight", "outcome": "ok"})
        if not isinstance(exclude_mountpoints, tuple) or any(not isinstance(p, str) or not p.startswith("/") or os.path.normpath(p) != p for p in exclude_mountpoints):
            raise runtime.Refusal("agathodaimon-drive-shares-exclusion-invalid", "request")
        # An absent scratch census refuses before a scratch lock path can be opened.
        if runtime._scratch_root() is not None and not runtime.runtime_path(runtime.MOUNTINFO).exists():
            runtime._mountinfo()
        with runtime.drive_guard():
            mounts = runtime._mountinfo()
            receipt["steps"].append({"step": "mount-census", "outcome": "ok"})
            included, sections = _smb_config()
            receipt["includedBySmbConf"] = included
            shares = []
            for role in ("primary", "backup"):
                info = runtime._role_info(role)
                mountpoint = info["mountpoint"]
                if mountpoint not in exclude_mountpoints and _nas_live(runtime._mount_for_target(mounts, mountpoint), info):
                    shares.append({"name": info["key"], "path": mountpoint})
            dead = []
            data = []
            for row in _opened.rows():
                label, identity, mountpoint = row["label"], row["device_identity"], row["mountpoint"]
                valid = _opened.valid_label(label) and isinstance(identity, str) and _opened._ID.fullmatch(identity) and mountpoint == "/mnt/" + label
                mount = runtime._mount_for_target(mounts, mountpoint)
                alive = bool(valid and mount and mount["dev"] == identity and runtime.runtime_path("/sys/dev/block/" + identity).exists())
                if mount is None:
                    dead.append(label)
                elif alive and mountpoint not in exclude_mountpoints:
                    data.append({"name": label, "path": mountpoint})
            shares.extend(sorted(data, key=lambda row: row["name"]))
            names = [item["name"].casefold() for item in shares]
            if len(set(names)) != len(names) or (included and sections.intersection(names)):
                raise runtime.Refusal("agathodaimon-drive-shares-smb-conf-collision", "smb-conf")
            receipt["shares"] = shares
            rendered = _render(shares)
            try:
                existing, _ = runtime._read_regular_nofollow(FILE)
            except FileNotFoundError:
                existing = None
            if existing != rendered:
                _write_config(rendered, receipt, included)
            elif included and force_reload:
                # Removal still needs confirmation when its candidate was already seated.
                receipt["mutationPerformed"] = True
                _reload_samba()
                receipt["reloaded"] = True
                receipt["steps"].append({"step": "reload", "outcome": "ok"})
            receipt["pruned"] = _opened._forget_many(dead)
            if receipt["pruned"]:
                receipt["mutationPerformed"] = True
            receipt.update(ok=True, firstMissingSignal="none")
    except runtime.Refusal as failure:
        receipt.update(firstMissingSignal=failure.signal_name, failedStep=failure.step)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        receipt.update(firstMissingSignal="agathodaimon-drive-shares-io-failed", failedStep="shares-io")
    if not receipt["ok"] and not any(row["outcome"] == "failed" for row in receipt["steps"]):
        receipt["steps"].append({"step": receipt["failedStep"], "outcome": "failed"})
    return receipt

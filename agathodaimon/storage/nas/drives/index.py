"""Observe the two NAS drives without changing them."""
from __future__ import annotations

import json
import os
import re

from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.nas import runtime

SCHEMA = "caduceus.nas.drives.v1"
LSBLK = "/usr/bin/lsblk"
SMARTCTL = "/usr/sbin/smartctl"


def _health(disk, transport):
    commands = [[SMARTCTL, "-H", "-j", disk]]
    if transport == "usb":
        commands.append([SMARTCTL, "-H", "-j", "-d", "sat", disk])
    for command in commands:
        try:
            result = runtime._run(command, timeout=15, step="smart-health")
            data = json.loads(result.stdout)
            passed = data.get("smart_status", {}).get("passed")
            if isinstance(passed, bool):
                return "passed" if passed else "failed"
        except (runtime.Refusal, ValueError, TypeError, AttributeError):
            pass
    return "unknown"


def _errors(disk):
    name = disk.removeprefix("/dev/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return None
    try:
        text = runtime.runtime_path("/sys/block/" + name + "/device/ioerr_cnt").read_text(encoding="ascii").strip()
        return int(text, 16)
    except (OSError, ValueError, UnicodeError, runtime.Refusal):
        return None


def observe():
    receipt = {"schema": SCHEMA, "ok": False, "drives": [], "firstMissingSignal": "agathodaimon-nas-not-complete"}
    try:
        runtime._require_root({})
        result = runtime._run([LSBLK, "--json", "--tree", "--bytes", "--paths", "--output", "PATH,TYPE,PARTLABEL,MAJ:MIN,MODEL,SIZE,TRAN"], timeout=15, step="drive-census")
        if result.returncode:
            raise runtime.Refusal("agathodaimon-nas-drive-census-failed", "drive-census")
        tree = json.loads(result.stdout)["blockdevices"]
        if not isinstance(tree, list):
            raise ValueError("blockdevices")
        matches = {"primary": [], "backup": []}
        def visit(row, disk=None):
            if not isinstance(row, dict):
                raise ValueError("device")
            if row.get("type") == "disk":
                disk = row
            if row.get("type") == "part":
                for role in matches:
                    if row.get("partlabel") == runtime._role_info(role)["partlabel"]:
                        if disk is None or not isinstance(disk.get("path"), str) or not disk["path"].startswith("/dev/"):
                            raise ValueError("disk")
                        matches[role].append((disk, row))
            children = row.get("children", []) or []
            if not isinstance(children, list):
                raise ValueError("children")
            for child in children:
                visit(child, disk)
        for row in tree:
            visit(row)
        mounts = runtime._mountinfo()
        for role, display in (("primary", "main"), ("backup", "backup")):
            info = runtime._role_info(role)
            row = {"role": display, "partlabel": info["partlabel"], "present": False,
                   "mountpoint": None, "mounted": False, "model": None, "sizeBytes": None,
                   "transport": None, "usedBytes": None, "freeBytes": None,
                   "health": "unknown", "readErrors": None}
            if len(matches[role]) > 1:
                raise runtime.Refusal("agathodaimon-nas-partlabel-duplicate", "drive-census")
            if matches[role]:
                disk, partition = matches[role][0]
                ids = set()
                def descendants(node):
                    identity = node.get("maj:min")
                    if isinstance(identity, str):
                        ids.add(identity)
                    for child in node.get("children", []) or []:
                        descendants(child)
                descendants(partition)
                mount = runtime._mount_for_target(mounts, info["mountpoint"])
                mounted = mount is not None and mount["dev"] in ids
                row.update(present=True, model=disk.get("model"), sizeBytes=disk.get("size"),
                           transport=disk.get("tran"), mounted=mounted,
                           mountpoint=info["mountpoint"] if mounted else None,
                           health=_health(disk["path"], disk.get("tran")), readErrors=_errors(disk["path"]))
                if mounted:
                    try:
                        space = os.statvfs(runtime.runtime_path(info["mountpoint"]))
                        row["usedBytes"] = (space.f_blocks - space.f_bfree) * space.f_frsize
                        row["freeBytes"] = space.f_bavail * space.f_frsize
                    except OSError:
                        raise runtime.Refusal("agathodaimon-nas-space-unavailable", "mount-space") from None
            receipt["drives"].append(row)
        receipt.update(ok=True, firstMissingSignal="none")
    except runtime.Refusal as failure:
        receipt["firstMissingSignal"] = failure.signal_name
    except (ValueError, KeyError, TypeError, UnicodeError):
        receipt["firstMissingSignal"] = "agathodaimon-nas-drive-census-invalid"
    return receipt


def main(argv=None):
    del argv
    request = None
    try:
        request = read(known_fields=())
        receipt = observe()
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"schema": SCHEMA, "ok": False, "drives": [], "firstMissingSignal": "agathodaimon-nas-request-invalid"}
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

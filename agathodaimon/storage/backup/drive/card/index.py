"""Read this box's mounted backup-drive facts without credential access."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import socket
import subprocess

from agathodaimon import _envelope

LSBLK = "/usr/bin/lsblk"
SMARTCTL = "/usr/sbin/smartctl"
ROLE = "homeserver-backup-nas"
MOUNT = "/mnt/nas_backup"
TRANSPORTS = frozenset(("usb", "sata", "ata", "nvme", "sas", "scsi", "mmc",
                        "virtio", "iscsi", "fc", "spi", "ieee1394"))
HOSTNAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*")


def own_box():
    try:
        info = json.loads(Path("/etc/appliance/ruyi.json").read_text(encoding="utf-8"))
        mac = info.get("self", {}).get("mac")
        host = socket.gethostname()
        if (not isinstance(mac, str) or not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", mac)
                or not isinstance(host, str) or len(host) > 253 or not HOSTNAME.fullmatch(host)):
            return None
        return {"mac": mac.lower(), "hostname": host}
    except (OSError, ValueError, UnicodeError, AttributeError, TypeError):
        return None


def _health(disk, transport):
    commands = [[SMARTCTL, "-H", "-j", disk]]
    if transport == "usb":
        commands.append([SMARTCTL, "-H", "-j", "-d", "sat", disk])
    for command in commands:
        try:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=15, check=False)
            data = json.loads(result.stdout)
            passed = data.get("smart_status", {}).get("passed")
            if isinstance(passed, bool):
                return "passed" if passed else "failed"
        except (OSError, subprocess.SubprocessError, ValueError, TypeError, AttributeError):
            pass
    return "unknown"


def _errors(disk):
    name = disk.removeprefix("/dev/")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return None
    try:
        text = Path("/sys/block", name, "device/ioerr_cnt").read_text(encoding="ascii").strip()
        value = int(text, 16)
        return value if value >= 0 else None
    except (OSError, ValueError, UnicodeError):
        return None


def observe():
    result = {"ok": False, "present": False, "model": None, "sizeBytes": None,
              "usedBytes": None, "freeBytes": None, "health": "unknown",
              "readErrors": None, "transport": None,
              "firstMissingSignal": "backup-drive-card-unavailable"}
    box = own_box()
    if box is not None:
        result["box"] = box
    try:
        if os.geteuid() != 0:
            return result
        census = subprocess.run([LSBLK, "--all", "--json", "--tree", "--bytes", "--paths", "--output",
                                 "PATH,TYPE,PARTLABEL,MAJ:MIN,MODEL,SIZE,TRAN"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=15, check=False)
        if census.returncode:
            return result
        tree = json.loads(census.stdout)["blockdevices"]
        if not isinstance(tree, list):
            return result
        lines = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
        if not lines:
            return result
        targets = [line.split() for line in lines if len(line.split()) >= 6 and line.split()[4] == MOUNT]
        mounted_id = None
        if targets:
            stat = os.stat(MOUNT)
            mounted_id = f"{os.major(stat.st_dev)}:{os.minor(stat.st_dev)}"
            if not any(row[2] == mounted_id for row in targets):
                mounted_id = None
        matches = []

        def descendants(node):
            ids = set()
            identity = node.get("maj:min")
            if isinstance(identity, str):
                ids.add(identity)
            for child in node.get("children", []) or []:
                ids.update(descendants(child))
            return ids

        def visit(row, disk=None):
            if not isinstance(row, dict):
                raise ValueError("invalid device")
            if row.get("type") == "disk":
                disk = row
            label = row.get("partlabel")
            if (row.get("type") == "part" and label is None and mounted_id is not None
                    and mounted_id in descendants(row)):
                path = row.get("path")
                if isinstance(path, str) and re.fullmatch(r"/dev/[A-Za-z0-9_.-]+", path):
                    try:
                        probe = subprocess.run(["/usr/sbin/blkid", "-p", "-s", "PART_ENTRY_NAME", "-o", "value", path],
                                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                               stderr=subprocess.DEVNULL, timeout=15, check=False)
                        if probe.returncode == 0:
                            label = probe.stdout.decode("utf-8").strip()
                    except (OSError, subprocess.SubprocessError, UnicodeError):
                        pass
            if row.get("type") == "part" and label == ROLE:
                if disk is None or not isinstance(disk.get("path"), str) or not disk["path"].startswith("/dev/"):
                    raise ValueError("invalid disk")
                matches.append((disk, row))
            children = row.get("children", []) or []
            if not isinstance(children, list):
                raise ValueError("invalid children")
            for child in children:
                visit(child, disk)

        for row in tree:
            visit(row)
        if len(matches) > 1:
            return result
        # Compare the active mount's device with the labelled partition tree,
        # including a mapped descendant such as a LUKS volume.
        result.update(ok=True, firstMissingSignal="none")
        if not matches or mounted_id is None:
            return result
        disk, partition = matches[0]
        if mounted_id not in descendants(partition):
            return result
        model = disk.get("model")
        if not isinstance(model, str) or len(model) > 64 or not re.fullmatch(r"[\x20-\x2e\x30-\x7e]*", model):
            model = None
        transport = disk.get("tran")
        if not isinstance(transport, str) or transport not in TRANSPORTS:
            transport = None
        size = disk.get("size")
        if type(size) is not int or size < 0:
            size = None
        result.update(present=True, model=model, sizeBytes=size, transport=transport,
                      health=_health(disk["path"], disk.get("tran")), readErrors=_errors(disk["path"]))
        try:
            space = os.statvfs(MOUNT)
            result["usedBytes"] = (space.f_blocks - space.f_bfree) * space.f_frsize
            result["freeBytes"] = space.f_bavail * space.f_frsize
        except OSError:
            pass
        return result
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        result.update(ok=False, present=False, model=None, sizeBytes=None, usedBytes=None,
                      freeBytes=None, health="unknown", readErrors=None, transport=None,
                      firstMissingSignal="backup-drive-card-unavailable")
        return result


def main(argv=None):
    del argv
    try:
        _envelope.read(known_fields=(), max_input_bytes=65536)
        result = observe()
    except (ValueError, UnicodeError):
        result = {"ok": False, "present": False, "model": None, "sizeBytes": None,
                  "usedBytes": None, "freeBytes": None, "health": "unknown",
                  "readErrors": None, "transport": None,
                  "firstMissingSignal": "backup-drive-card-unavailable"}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1

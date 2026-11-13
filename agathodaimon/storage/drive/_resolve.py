"""Read and classify whole drives for add, remove and storage/nas-import/run."""
from __future__ import annotations

import json
import os
import re
import stat

from agathodaimon.storage.drive import _drive
from agathodaimon.storage.nas import runtime as _runtime
from agathodaimon.storage.nas.setup import _setup

SUPPORTED_FSTYPES = frozenset({"ext3", "ext4", "xfs", "btrfs", "vfat", "exfat", "ntfs"})
LOCKED_FSTYPES = frozenset({"crypto_LUKS", "LVM2_member", "linux_raid_member"})
RESERVED_LABELS = frozenset({"nas", "nas_backup", "global", "homes", "printers", "print$"})
# Caduceus routes/storage/disk/census/index.rs SYSTEM_CRITICAL_MOUNTS, plus /vault.
SYSTEM_CRITICAL = frozenset({
    "/", "/boot", "/boot/efi", "/home", "/usr", "/var", "/etc", "/bin",
    "/sbin", "/lib", "/lib64", "/opt", "/srv", "/tmp", "/swap", "[SWAP]", "/vault",
})


def census(receipt: dict) -> list[dict]:
    result = _runtime._run([_setup.LSBLK, "--json", "--paths", "--output",
        "PATH,TYPE,MAJ:MIN,PKNAME,LABEL,PARTLABEL,FSTYPE,MODEL,SERIAL,TRAN,MOUNTPOINT"],
        step="drive-census", timeout=60)
    try:
        tree = json.loads(result.stdout.decode("utf-8"))
        devices = tree["blockdevices"]
        if result.returncode != 0 or not isinstance(devices, list) or not devices:
            raise ValueError("census")
        rows = []
        def walk(nodes):
            for node in nodes:
                if not isinstance(node, dict):
                    raise ValueError("node")
                parent = node.get("pkname")
                if parent and not parent.startswith("/dev/"):
                    parent = "/dev/" + parent
                rows.append({"path": node.get("path"), "type": node.get("type"),
                    "maj:min": node.get("maj:min"), "pkname": parent,
                    "label": node.get("label"), "partlabel": node.get("partlabel"),
                    "fstype": node.get("fstype"), "model": node.get("model"),
                    "serial": node.get("serial"), "transport": node.get("tran"),
                    "mountpoint": node.get("mountpoint")})
                children = node.get("children", [])
                if not isinstance(children, list):
                    raise ValueError("children")
                walk(children)
        walk(devices)
        return rows
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError):
        raise _runtime.Refusal("agathodaimon-drive-block-census-failed", "drive-census",
                               result.returncode, receipt) from None


def resolve_device(receipt: dict, device: str) -> dict:
    if not isinstance(device, str) or not re.fullmatch(r"/dev/[A-Za-z0-9._-]+", device):
        raise _runtime.Refusal("agathodaimon-drive-device-form-refused", "device-form", receipt=receipt)
    try:
        mapped = _runtime.runtime_path(device)
        real = os.path.realpath(mapped)
        dev_root = os.path.realpath(_runtime.runtime_path("/dev"))
        if os.path.commonpath((dev_root, real)) != dev_root or real == dev_root:
            raise ValueError("outside dev")
    except (ValueError, OSError):
        raise _runtime.Refusal("agathodaimon-drive-device-form-refused", "device-form", receipt=receipt) from None
    rows = census(receipt)
    matches = [row for row in rows if row["path"] == device]
    if not matches:
        raise _runtime.Refusal("agathodaimon-drive-device-not-in-block-census", "device-census", receipt=receipt)
    disk = matches[0]
    if len(matches) != 1 or disk["type"] not in {"disk", "loop"}:
        raise _runtime.Refusal("agathodaimon-drive-whole-disk-required", "device-census", receipt=receipt)
    try:
        st = os.stat(mapped)
        identity = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        if not stat.S_ISBLK(st.st_mode) or identity != disk["maj:min"]:
            raise ValueError("identity")
    except (OSError, ValueError):
        raise _runtime.Refusal("agathodaimon-drive-device-identity-mismatch", "device-identity", receipt=receipt) from None
    edges, _paths = _runtime._block_graph()
    component = _runtime._component(edges, identity)
    entries = _drive.mountinfo_entries()
    critical_mount = any(entry["target"] in SYSTEM_CRITICAL and entry["dev"] in component
                         for entry in entries)
    critical_census = any(row.get("mountpoint") in SYSTEM_CRITICAL
                          for row in rows
                          if row.get("maj:min") in component or row.get("path") == device
                          or row.get("pkname") == device)
    if critical_mount or critical_census:
        raise _runtime.Refusal("agathodaimon-drive-system-device-refused",
                               "protected-mount-preflight", receipt=receipt)
    nodes = [row for row in rows if row["type"] == "part" and row["pkname"] == device]
    data = None
    refusal = None
    if nodes:
        supported = [row for row in nodes if row["fstype"] in SUPPORTED_FSTYPES]
        if any(row["fstype"] in LOCKED_FSTYPES for row in nodes):
            refusal = "agathodaimon-drive-locked-refused"
        elif len(supported) == 1:
            data = supported[0]
        elif len(supported) > 1:
            refusal = "agathodaimon-drive-partition-ambiguous"
        elif all(not row["fstype"] for row in nodes):
            refusal = "agathodaimon-drive-no-filesystem"
        else:
            refusal = "agathodaimon-drive-filesystem-unsupported"
    elif disk["fstype"] in LOCKED_FSTYPES:
        refusal = "agathodaimon-drive-locked-refused"
    elif disk["fstype"] in SUPPORTED_FSTYPES:
        data = disk
    elif not disk["fstype"]:
        refusal = "agathodaimon-drive-no-filesystem"
    else:
        refusal = "agathodaimon-drive-filesystem-unsupported"
    return {"disk": device, "identity": identity, "model": disk["model"],
            "serial": disk["serial"], "transport": disk["transport"],
            "partlabels": [row["partlabel"] for row in nodes if row["partlabel"]],
            "nodes": nodes, "data": data, "dataRefusal": refusal}


def _sanitize(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")[:32].strip("-")


def label_for(resolved: dict) -> str:
    if resolved.get("data") is None:
        raise _runtime.Refusal("agathodaimon-drive-no-data-node", "drive-label")
    label = _sanitize(resolved["data"].get("label") or "")
    if not label:
        model = _sanitize(resolved.get("model") or "")
        serial = "".join(re.findall(r"[A-Za-z0-9]", resolved.get("serial") or ""))[-6:]
        label = _sanitize("-".join(part for part in (model, serial) if part))
    if not label:
        raise _runtime.Refusal("agathodaimon-drive-label-unobservable", "drive-label")
    if label.lower() in RESERVED_LABELS:
        raise _runtime.Refusal("agathodaimon-drive-label-reserved", "drive-label")
    return label


def mount_plan(fstype: str, uid: int, gid: int) -> tuple[str, str | None]:
    if fstype not in SUPPORTED_FSTYPES:
        raise _runtime.Refusal("agathodaimon-drive-filesystem-unsupported", "mount-plan")
    if fstype in {"ext3", "ext4", "xfs", "btrfs"}:
        return fstype, "nosuid,nodev"
    if type(uid) is not int or type(gid) is not int or uid < 0 or gid < 0:
        raise _runtime.Refusal("agathodaimon-drive-owner-unresolved", "mount-plan")
    options = f"nosuid,nodev,uid={uid},gid={gid}"
    if fstype == "ntfs":
        return "ntfs3", options + ",fmask=0022,dmask=0022"
    return fstype, options + ",umask=022"

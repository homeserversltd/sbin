"""Identity-first census for the three NAS role labels."""
from __future__ import annotations

import json
import re
from agathodaimon.storage.nas import runtime

LABELS = frozenset({"homeserver-primary-nas", "homeserver-backup-nas", "homeserver-nas-swap-tmp"})


def census():
    result = runtime._run(["/usr/bin/lsblk", "--json", "--paths", "--output", "PATH,TYPE,PARTLABEL,MAJ:MIN,PKNAME"], step="partlabel-census")
    if result.returncode != 0:
        raise runtime.Refusal("agathodaimon-nas-partlabel-unobservable", "partlabel-census", result.returncode)
    try:
        nodes = json.loads(result.stdout.decode("utf-8"))["blockdevices"]
        if not isinstance(nodes, list):
            raise ValueError("blockdevices")
        stack = list(nodes)
        partitions = {}
        while stack:
            node = stack.pop()
            if not isinstance(node, dict):
                raise ValueError("block row")
            children = node.get("children", []) or []
            if not isinstance(children, list):
                raise ValueError("block children")
            stack.extend(children)
            label = node.get("partlabel")
            if node.get("type") != "part" or label not in LABELS:
                continue
            path, identity = node.get("path"), node.get("maj:min")
            if (not isinstance(path, str) or not re.fullmatch(r"/dev/[A-Za-z0-9._+-]+", path)
                    or not isinstance(identity, str) or not re.fullmatch(r"\d+:\d+", identity)):
                raise ValueError("partition identity")
            existing = partitions.get(identity)
            if existing and (existing["label"] != label or existing["path"] != path):
                raise ValueError("contradictory identity")
            partitions[identity] = {"path": path, "identity": identity, "label": label}
        return list(partitions.values())
    except (UnicodeError, ValueError, KeyError, TypeError):
        raise runtime.Refusal("agathodaimon-nas-partlabel-unobservable", "partlabel-census", result.returncode) from None


def select(label, rows=None):
    if label not in LABELS:
        raise runtime.Refusal("agathodaimon-nas-partlabel-invalid", "partlabel-census")
    rows = census() if rows is None else rows
    found = [row for row in rows if row["label"] == label]
    if not found:
        raise runtime.Refusal("agathodaimon-nas-partlabel-absent", "partlabel-census")
    if len(found) != 1:
        raise runtime.Refusal("agathodaimon-nas-partlabel-duplicate", "partlabel-census")
    row = found[0]
    if runtime._device_identity(row["path"], "partition-readback") != row["identity"]:
        raise runtime.Refusal("agathodaimon-nas-partition-identity-mismatch", "partition-readback")
    result = runtime._run([runtime.BLKID, "-c", "/dev/null", "-s", "PARTLABEL", "-o", "value", "--", row["path"]], step="partlabel-readback")
    if result.returncode != 0 or runtime._decode_output(result, "partlabel-readback") != label:
        raise runtime.Refusal("agathodaimon-nas-partlabel-missing-or-mismatch", "partlabel-readback", result.returncode)
    return row

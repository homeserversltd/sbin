"""Observe one NAS role without changing its partition or mapper."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.nas import runtime

SCHEMA = "caduceus.nas.role.observe.v1"
LSBLK = "/usr/bin/lsblk"


def observe(role):
    receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete",
               "role": role, "partlabel": None, "partition": None, "steps": []}
    try:
        runtime._require_root(receipt)
        info = runtime._role_info(role)
        label = info["partlabel"]
        receipt["partlabel"] = label
        result = runtime._run([LSBLK, "--json", "--paths", "--output", "PATH,TYPE,PARTLABEL,MAJ:MIN"],
                              step="partlabel-census")
        if result.returncode != 0:
            runtime._fail(receipt, "agathodaimon-nas-partlabel-unobservable", "partlabel-census", result.returncode)
        try:
            tree = json.loads(result.stdout.decode("utf-8"))["blockdevices"]
            if not isinstance(tree, list):
                raise ValueError("blockdevices")
            stack = list(tree)
            matches = {}
            while stack:
                row = stack.pop()
                if not isinstance(row, dict):
                    raise ValueError("row")
                children = row.get("children", []) or []
                if not isinstance(children, list):
                    raise ValueError("children")
                stack.extend(children)
                if row.get("type") == "part" and row.get("partlabel") == label:
                    path, identity = row.get("path"), row.get("maj:min")
                    if not isinstance(path, str) or not path.startswith("/dev/") or not isinstance(identity, str) or not re.fullmatch(r"\d+:\d+", identity):
                        raise ValueError("partition identity")
                    matches[identity] = path
        except (ValueError, KeyError, TypeError, UnicodeError):
            runtime._fail(receipt, "agathodaimon-nas-partlabel-unobservable", "partlabel-census", result.returncode)
        if not matches:
            runtime._fail(receipt, "agathodaimon-nas-partlabel-absent", "partlabel-census", matches=0)
        if len(matches) != 1:
            runtime._fail(receipt, "agathodaimon-nas-partlabel-duplicate", "partlabel-census", matches=len(matches))
        identity, partition = next(iter(matches.items()))
        if runtime._device_identity(partition, "partition-readback") != identity:
            runtime._fail(receipt, "agathodaimon-nas-partition-identity-mismatch", "partition-readback")
        resolved = os.path.realpath(runtime.runtime_path(partition))
        scratch = runtime._scratch_root()
        if scratch is not None:
            try:
                resolved = "/" + str(Path(resolved).relative_to(scratch))
            except ValueError:
                runtime._fail(receipt, "agathodaimon-nas-partition-unavailable", "partition-readback")
        if not resolved.startswith("/dev/"):
            runtime._fail(receipt, "agathodaimon-nas-partition-unavailable", "partition-readback")
        label_check = runtime._run([runtime.BLKID, "-c", "/dev/null", "-s", "PARTLABEL", "-o", "value", "--", partition],
                                   step="partlabel-readback")
        if label_check.returncode != 0 or runtime._decode_output(label_check, "partlabel-readback") != label:
            runtime._fail(receipt, "agathodaimon-nas-partlabel-missing-or-mismatch", "partlabel-readback", label_check.returncode)
        receipt.update(partition=resolved, deviceIdentity=identity)
        runtime._record(receipt, "partition-readback", True, partition=resolved, identity=identity, partlabel=label)
        holders = []
        holder_ids = set()
        for kernel_name in runtime._list_holders(identity):
            node = runtime._safe_resolve(runtime.runtime_path("/sys/class/block") / kernel_name, "block-holder-readback")
            holder_id = runtime._sysfs_dev(node)
            if runtime._direct_slaves(holder_id) != {identity}:
                runtime._fail(receipt, "agathodaimon-nas-holder-backing-mismatch", "block-holder-readback", holder=kernel_name)
            try:
                name = (node / "dm" / "name").read_text(encoding="utf-8").strip()
            except (OSError, UnicodeError):
                runtime._fail(receipt, "agathodaimon-nas-holder-unobservable", "block-holder-readback", holder=kernel_name)
            if not re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", name):
                runtime._fail(receipt, "agathodaimon-nas-holder-invalid", "block-holder-readback")
            holders.append({"name": name, "identity": holder_id})
            holder_ids.add(holder_id)
        mounts = [{"mountpoint": entry["target"], "fstype": entry["fstype"], "source": entry["source"], "identity": entry["dev"]}
                  for entry in runtime._mountinfo() if entry["dev"] in holder_ids | {identity}]
        receipt.update(holders=holders, mapperOpen=bool(holders), mounts=mounts,
                       mountpoint=mounts[0]["mountpoint"] if len(mounts) == 1 else None,
                       fstype=mounts[0]["fstype"] if len(mounts) == 1 else None,
                       state="role-observed")
        runtime._record(receipt, "role-observed", True, holders=holders, mounts=mounts)
        receipt.update(ok=True, firstMissingSignal="none")
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
    return receipt


def main(argv=None):
    del argv
    request = None
    try:
        request = read(known_fields=("role",))
        receipt = observe(request.payload.get("role"))
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-request-invalid",
                   "failedStep": "request", "steps": [], "role": None, "partlabel": None, "partition": None}
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

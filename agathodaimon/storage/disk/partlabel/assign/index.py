"""Assign a NAS PARTLABEL to one observed, unheld GPT partition."""
from __future__ import annotations

import json
import re
import time
from _envelope import EnvelopeError, attach, read
from agathodaimon.storage.nas import deed, labels, runtime

SCHEMA = "caduceus.disk.partlabel.assign.v1"


def _disk_for(partition_identity):
    node = runtime._safe_resolve(runtime.runtime_path(runtime.SYS_DEV_BLOCK) / partition_identity, "partition-disk-readback")
    try:
        raw = (node / "partition").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise runtime.Refusal("agathodaimon-nas-partition-number-unobservable", "partition-disk-readback") from None
    if not re.fullmatch(r"[1-9][0-9]*", raw):
        raise runtime.Refusal("agathodaimon-nas-partition-number-invalid", "partition-disk-readback")
    parent = runtime._safe_resolve(node.parent, "partition-disk-readback")
    identity = runtime._sysfs_dev(parent)
    confirmed = runtime._safe_resolve(runtime.runtime_path(runtime.SYS_DEV_BLOCK) / identity, "partition-disk-readback")
    if confirmed != parent or not re.fullmatch(r"[A-Za-z0-9._+-]+", parent.name):
        raise runtime.Refusal("agathodaimon-nas-parent-identity-mismatch", "partition-disk-readback")
    disk = "/dev/" + parent.name
    if runtime._device_identity(disk, "partition-disk-readback") != identity:
        raise runtime.Refusal("agathodaimon-nas-parent-identity-mismatch", "partition-disk-readback")
    return disk, identity, int(raw)


def _preflight(current, target):
    if not isinstance(current, str) or not isinstance(target, str) or current not in labels.LABELS or target not in labels.LABELS:
        raise runtime.Refusal("agathodaimon-nas-partlabel-invalid", "request")
    rows = labels.census()
    row = labels.select(current, rows)
    if any(item["label"] == target for item in rows):
        raise runtime.Refusal("agathodaimon-nas-partlabel-already-taken", "target-label-preflight")
    identity = row["identity"]
    holders = runtime._list_holders(identity)
    if holders:
        raise runtime.Refusal("agathodaimon-nas-partition-held", "partition-holder-preflight")
    disk, disk_identity, number = _disk_for(identity)
    graph, _ = runtime._block_graph()
    component = runtime._component(graph, disk_identity)
    mounts = [entry for entry in runtime._mountinfo() if entry["dev"] in component]
    if mounts:
        raise runtime.Refusal("agathodaimon-nas-partition-mounted", "partition-mount-preflight")
    return row, disk, disk_identity, number


def perform(current, target, *, request=None):
    receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete",
               "current_label": current, "label": target, "steps": []}
    started = time.monotonic()
    attempted = False
    try:
        runtime._require_root(receipt)
        with runtime.drive_guard():
            row, disk, disk_identity, number = _preflight(current, target)
            runtime._record(receipt, "partlabel-preflight", True, partition=row["path"], identity=row["identity"], disk=disk, diskIdentity=disk_identity, partitionNumber=number)
            again, disk_again, disk_id_again, number_again = _preflight(current, target)
            if (again["identity"], disk_again, disk_id_again, number_again) != (row["identity"], disk, disk_identity, number):
                raise runtime.Refusal("agathodaimon-nas-partition-identity-mismatch", "partlabel-preflight")
            attempted = True
            result = runtime._run(["/usr/sbin/sgdisk", f"--change-name={number}:{target}", "--", disk], step="partlabel-write", timeout=60)
            runtime._record(receipt, "partlabel-write", result.returncode == 0, rc=result.returncode)
            if result.returncode != 0:
                raise runtime.Refusal("agathodaimon-nas-partlabel-write-failed", "partlabel-write", result.returncode)
            settle = runtime._run(["/usr/bin/udevadm", "settle", "--timeout=30"], step="udev-settle")
            runtime._record(receipt, "udev-settle", settle.returncode == 0, rc=settle.returncode)
            if settle.returncode != 0:
                raise runtime.Refusal("agathodaimon-nas-udev-settle-failed", "udev-settle", settle.returncode)
            if runtime._device_identity(row["path"], "partlabel-readback") != row["identity"]:
                raise runtime.Refusal("agathodaimon-nas-partition-identity-mismatch", "partlabel-readback")
            check = runtime._run([runtime.BLKID, "-c", "/dev/null", "-s", "PARTLABEL", "-o", "value", "--", row["path"]], step="partlabel-readback")
            if check.returncode != 0 or runtime._decode_output(check, "partlabel-readback") != target:
                raise runtime.Refusal("agathodaimon-nas-partlabel-readback-mismatch", "partlabel-readback", check.returncode)
            runtime._record(receipt, "partlabel-readback", True, partition=row["path"], identity=row["identity"], label=target)
            receipt.update(ok=True, firstMissingSignal="none", state="partlabel-assigned", partition=row["path"], deviceIdentity=row["identity"])
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
    if attempted or receipt.get("ok") is not True:
        deed.finish("partlabel-assign", "nas-partition", receipt, started, request=request)
    return receipt


def main(argv=None):
    request = None
    try:
        request = read(known_fields=("current_label", "label"))
        receipt = perform(request.payload.get("current_label"), request.payload.get("label"), request=request.intent_id)
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-request-invalid", "failedStep": "request", "steps": []}
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

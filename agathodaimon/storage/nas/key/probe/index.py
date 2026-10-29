"""Prove a role key matches a labelled partition without opening a mapper."""
from __future__ import annotations

import json
import os
from _envelope import EnvelopeError, attach, read
from agathodaimon.lib.keyman_export.index import KeymanExportError
from agathodaimon.storage.nas import labels, runtime

SCHEMA = "caduceus.nas.key.probe.v1"


def perform(key_role, partition):
    receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-not-complete",
               "key_role": key_role, "partition": partition, "steps": []}
    material = None
    guard = None
    entered = False
    try:
        runtime._require_root(receipt)
        guard = runtime.drive_guard()
        guard.__enter__()
        entered = True
        runtime._record(receipt, "sync-lock", True, acquired=True)
        runtime._role_info(key_role)
        if not isinstance(partition, str) or not partition.startswith("/dev/") or "\x00" in partition or os.path.normpath(partition) != partition:
            raise runtime.Refusal("agathodaimon-nas-partition-invalid", "partition-preflight")
        identity = runtime._device_identity(partition, "partition-preflight")
        rows = labels.census()
        matches = [row for row in rows if row["identity"] == identity]
        if len(matches) != 1:
            raise runtime.Refusal("agathodaimon-nas-partlabel-invalid", "partition-preflight")
        row = labels.select(matches[0]["label"], rows)
        runtime._record(receipt, "partition-preflight", True, identity=identity, partlabel=row["label"])
        try:
            material = runtime._export_for_role(key_role, runtime._scratch_root())
        except KeymanExportError:
            raise runtime.Refusal("agathodaimon-nas-key-export-failed", "key-export") from None
        runtime._record(receipt, "key-export", True, present=True)
        if runtime._device_identity(partition, "partition-preflight") != identity:
            raise runtime.Refusal("agathodaimon-nas-partition-identity-mismatch", "partition-preflight")
        command = runtime._run([runtime.CRYPTSETUP, "open", "--test-passphrase", "--key-file", "-", "--", partition],
                               input_data=material, timeout=120, step="key-probe", suppress_output=True)
        if command.returncode != 0:
            signal = "agathodaimon-nas-key-mismatched" if command.returncode == 2 else "agathodaimon-nas-key-probe-failed"
            receipt["state"] = "key-mismatched" if command.returncode == 2 else "key-unobserved"
            raise runtime.Refusal(signal, "key-probe", command.returncode)
        runtime._record(receipt, "key-probe", True, identity=identity, keyMatched=True, mapperCreated=False)
        receipt.update(ok=True, firstMissingSignal="none", state="key-matched")
    except runtime.Refusal as failure:
        runtime._attach_failure(receipt, failure)
    finally:
        if material is not None:
            for index in range(len(material)):
                material[index] = 0
        if entered and guard is not None:
            guard.__exit__(None, None, None)
    return receipt


def main(argv=None):
    request = None
    try:
        request = read(known_fields=("key_role", "partition"))
        receipt = perform(request.payload.get("key_role"), request.payload.get("partition"))
    except (EnvelopeError, ValueError, UnicodeError):
        receipt = {"schema": SCHEMA, "ok": False, "firstMissingSignal": "agathodaimon-nas-request-invalid", "failedStep": "request", "steps": []}
    if request is not None:
        receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

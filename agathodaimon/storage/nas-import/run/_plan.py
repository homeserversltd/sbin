"""Read-only preflight for a detached NAS import."""
from __future__ import annotations

from datetime import datetime, timezone
import importlib
import os
import re
import stat

from agathodaimon.storage.nas import runtime


def build(receipt: dict, device: str) -> dict:
    try:
        resolver = importlib.import_module("agathodaimon.storage.drive._resolve")
    except ImportError:
        raise runtime.Refusal("agathodaimon-nas-import-resolver-unavailable", "import-resolver") from None
    resolved = resolver.resolve_device(receipt, device)
    node = resolved.get("data")
    if node is None:
        signal = resolved.get("dataRefusal") or "agathodaimon-drive-no-filesystem"
        raise runtime.Refusal(signal, "import-source")
    graph, _ = runtime._block_graph()
    component = runtime._component(graph, resolved["identity"])
    if any(row["dev"] in component for row in runtime._mountinfo()):
        runtime._fail(receipt, "agathodaimon-nas-device-mounted", "import-source-mounted")
    runtime._record(receipt, "import-source-mounted", True)

    result = runtime._run(["/usr/bin/systemctl", "show", "agathodaimon-disk-test.service",
                           "--property=ActiveState,Description"], step="drive-test-unit", timeout=30)
    if result.returncode != 0:
        raise runtime.Refusal("agathodaimon-nas-import-test-state-unavailable", "drive-test-unit", result.returncode)
    fields = dict(line.split("=", 1) for line in runtime._decode_output(result, "drive-test-unit").splitlines() if "=" in line)
    state = fields.get("ActiveState")
    if state not in {"active", "activating", "deactivating", "reloading", "inactive", "failed"} or "Description" not in fields:
        raise runtime.Refusal("agathodaimon-nas-import-test-state-unavailable", "drive-test-unit")
    if state in {"active", "activating", "deactivating", "reloading"}:
        parts = fields["Description"].split()
        if len(parts) != 3 or parts[0] != "disk-test" or not re.fullmatch(r"/dev/[A-Za-z0-9._-]+", parts[1]):
            raise runtime.Refusal("agathodaimon-nas-import-test-state-unavailable", "drive-test-unit")
        try:
            test_identity = runtime._device_identity(parts[1], "drive-test-unit")
        except runtime.Refusal:
            raise runtime.Refusal("agathodaimon-nas-import-test-state-unavailable", "drive-test-unit") from None
        if test_identity not in graph:
            raise runtime.Refusal("agathodaimon-nas-import-test-state-unavailable", "drive-test-unit")
        if test_identity in component:
            runtime._fail(receipt, "agathodaimon-drive-disk-test-running", "drive-test-unit")
    runtime._record(receipt, "drive-test-unit", True, activeState=state)

    label = resolver.label_for(resolved)
    if not isinstance(label, str) or not label:
        raise runtime.Refusal("agathodaimon-nas-import-label-unavailable", "import-label")
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", label):
        raise runtime.Refusal("agathodaimon-nas-import-label-invalid", "import-label")
    primary = runtime._info_for("primary", runtime.role_partition("primary"))
    readback = runtime._mount_readback(primary)
    if not readback.get("mounted"):
        raise runtime.Refusal("agathodaimon-nas-not-attached", "import-nas-readback")
    if not readback.get("sourceMatches"):
        raise runtime.Refusal("agathodaimon-nas-mounted-state-mismatch", "import-nas-readback")
    mapper = runtime._device_identity("/dev/mapper/" + primary["mapper"], "import-nas-readback")
    if not runtime._direct_slaves(mapper):
        raise runtime.Refusal("agathodaimon-nas-not-attached", "import-nas-readback")
    backing = runtime._mapper_state(receipt, primary)
    if not backing.get("exists") or not backing.get("backingMatches"):
        raise runtime.Refusal("agathodaimon-nas-mounted-state-mismatch", "import-nas-readback")
    runtime._record(receipt, "import-nas-readback", True)

    parent = "/mnt/nas/Imports"
    physical_parent = runtime.runtime_path(parent)
    try:
        metadata = os.lstat(physical_parent)
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISDIR(metadata.st_mode):
            raise runtime.Refusal("agathodaimon-nas-import-destination-not-directory", "import-destination")
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    destination = parent + "/" + label + " " + date
    if os.path.lexists(runtime.runtime_path(destination)):
        runtime._fail(receipt, "agathodaimon-nas-import-destination-exists", "import-destination", destination=destination)
    runtime._record(receipt, "import-destination", True, destination=destination)
    return {"device": device, "dataPath": node["path"], "identity": node["maj:min"],
            "fstype": node["fstype"], "fstypeArg": resolver.mount_plan(node["fstype"], 0, 0)[0],
            "label": label, "dateUtc": date, "nasMountpoint": "/mnt/nas",
            "destinationDir": parent, "destination": destination,
            "sourceMountpoint": "/run/homeserver-nas-import/source"}

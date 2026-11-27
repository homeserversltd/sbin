"""Read a candidate disk's partitions and signatures without changing it."""
import json
import os
import re
import stat
import subprocess

from agathodaimon import _envelope, _seat
from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon.storage.nas import runtime


class ObservationError(Exception):
    def __init__(self, signal):
        self.signal = signal


def _run(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise ObservationError("nas-prefire-command-failed") from None


def _signatures(device):
    result = _run(["/usr/sbin/wipefs", "--noheadings", "--output", "TYPE", "--", device])
    if result.returncode:
        raise ObservationError("nas-prefire-command-failed")
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _fields():
    try:
        catalog = _seat.read_intent_seats(appliance_runtime_path("seats"))
        if catalog is None:
            raise KeyError("intent seats unavailable")
        fields = catalog[0]["storage/nas/setup/prefire"]["payload"]["fields"]
        return json.loads(_seat.dump_intent_projection(fields))
    except (TypeError, KeyError, IndexError, ValueError):
        raise ObservationError("nas-prefire-command-failed") from None


def observe(device, role):
    fields = _fields()
    try:
        valid = (isinstance(device, str) and len(device) <= int(fields["device"]["maxLength"])
                 and re.fullmatch(fields["device"]["pattern"], device) is not None
                 and isinstance(role, str) and role in fields["role"]["enum"] and role in runtime.ROLE)
    except (KeyError, TypeError, ValueError, re.error):
        raise ObservationError("nas-prefire-command-failed") from None
    if not valid:
        raise ObservationError("nas-prefire-device-invalid")
    try:
        metadata = os.stat(device)
    except FileNotFoundError:
        raise ObservationError("nas-prefire-device-unobservable") from None
    except OSError:
        raise ObservationError("nas-prefire-command-failed") from None
    if not stat.S_ISBLK(metadata.st_mode):
        raise ObservationError("nas-prefire-device-invalid")
    result = _run(["/usr/bin/lsblk", "--json", "--bytes", "--paths", "--output",
                   "PATH,TYPE,MAJ:MIN,PKNAME,PARTLABEL,PARTUUID,SIZE", "--", device])
    if result.returncode:
        if not os.path.exists(device):
            raise ObservationError("nas-prefire-device-unobservable")
        raise ObservationError("nas-prefire-command-failed")
    try:
        nodes = json.loads(result.stdout)["blockdevices"]
        if not isinstance(nodes, list):
            raise ValueError
        flat = []
        def visit(row):
            if not isinstance(row, dict):
                raise ValueError
            flat.append(row)
            children = row.get("children") or []
            if not isinstance(children, list):
                raise ValueError
            for child in children:
                visit(child)
        for row in nodes:
            visit(row)
        matches = [row for row in flat if isinstance(row.get("path"), str)
                   and os.path.realpath(row["path"]) == os.path.realpath(device)]
        if not matches:
            raise ObservationError("nas-prefire-device-unobservable")
        if len(matches) != 1:
            raise ValueError
        disk = matches[0]
        if disk.get("type") not in ("disk", "loop"):
            raise ObservationError("nas-prefire-device-invalid")
        disk_path = disk["path"]
        disk_size = disk["size"]
        if not isinstance(disk_path, str) or type(disk_size) is not int or disk_size < 0:
            raise ValueError
        parts = [row for row in flat if row.get("type") == "part"
                 and row.get("pkname") in (disk_path, os.path.basename(disk_path))]
        signatures = _signatures(device)
        contents = [{"partition": disk_path, "partlabel": None, "type": sig,
                     "sizeBytes": disk_size} for sig in signatures]
        part_uuid = None
        for part in parts:
            path, size = part["path"], part["size"]
            if not isinstance(path, str) or type(size) is not int or size < 0:
                raise ValueError
            types = _signatures(path)
            label = part.get("partlabel")
            if label is not None and not isinstance(label, str):
                raise ValueError
            contents.append({"partition": path, "partlabel": label,
                             "type": types[0] if types else None, "sizeBytes": size})
            if label == runtime.ROLE[role]["partlabel"]:
                part_uuid = part.get("partuuid")
                if part_uuid is not None and not isinstance(part_uuid, str):
                    raise ValueError
        return {"ok": True, "sizeBytes": disk_size, "blank": not parts and not signatures,
                "contents": contents, "partUuid": part_uuid, "firstMissingSignal": "none"}
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        raise ObservationError("nas-prefire-command-failed") from None


def main(argv=None):
    del argv
    request = None
    try:
        request = _envelope.read_fields("device", "role")
        receipt = observe(request.payload.get("device"), request.payload.get("role"))
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "sizeBytes": None, "blank": None, "contents": [],
                   "partUuid": None, "firstMissingSignal": "nas-prefire-device-invalid"}
    except ObservationError as error:
        receipt = {"ok": False, "sizeBytes": None, "blank": None, "contents": [],
                   "partUuid": None, "firstMissingSignal": error.signal}
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

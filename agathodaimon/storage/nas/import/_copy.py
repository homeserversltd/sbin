"""Copy one planned data filesystem into a new NAS directory."""

import json
import os
import re
import stat
from typing import NoReturn

from agathodaimon.storage.nas import runtime


_BLOCK = "/usr/sbin/blockdev"
_FIND = "/usr/bin/findmnt"
_RSYNC = "/usr/bin/rsync"
_PREFIX = "agathodaimon-nas-import-"


def _fail(receipt, signal, step, rc=None, **values) -> NoReturn:
    if signal == "source-dirty":
        receipt["sourceRecoveryHint"] = "Open the drive or repair it on its own machine first."
    runtime._record(receipt, step, False, **values)
    raise runtime.Refusal(_PREFIX + signal, step, rc, receipt)


def _checked(receipt, argv, step, signal, timeout=60):
    result = runtime._run(argv, step=step, timeout=timeout)
    if result.returncode != 0:
        _fail(receipt, signal, step, result.returncode)
    runtime._record(receipt, step, True, rc=result.returncode)
    return result


def _ro_state(receipt, device, step):
    result = _checked(receipt, [_BLOCK, "--getro", device], step, "source-protection-failed")
    value = result.stdout.strip()
    if value not in (b"0", b"1"):
        _fail(receipt, "source-protection-failed", step)
    return value == b"1"


def _clean_source(plan, receipt):
    device = plan["dataPath"]
    kind = plan["fstype"]
    step = "import-source-cleanliness"
    if kind in ("ext3", "ext4"):
        result = _checked(receipt, ["/usr/sbin/dumpe2fs", "-h", device], step,
                          "source-inspection-failed", 180)
        text = result.stdout.decode("utf-8", "replace")
        features = re.search(r"^Filesystem features:\s*(.*)$", text, re.MULTILINE)
        state = re.search(r"^Filesystem state:\s*(.*)$", text, re.MULTILINE)
        if not features or not state:
            _fail(receipt, "source-inspection-failed", step)
        if "needs_recovery" in features.group(1).split() or state.group(1).strip() != "clean":
            _fail(receipt, "source-dirty", step)
    elif kind == "xfs":
        result = runtime._run(["/usr/sbin/xfs_repair", "-n", device], step=step, timeout=86400)
        if result.returncode == 2:
            _fail(receipt, "source-dirty", step, result.returncode)
        if result.returncode != 0:
            _fail(receipt, "source-inspection-failed", step, result.returncode)
        runtime._record(receipt, step, True, rc=result.returncode)
    elif kind == "btrfs":
        result = _checked(receipt, ["/usr/bin/btrfs", "inspect-internal", "dump-super", device],
                          step, "source-inspection-failed", 180)
        match = re.search(rb"^\s*log_root\s+(0x[0-9a-fA-F]+|[0-9]+)\b", result.stdout, re.MULTILINE)
        if not match:
            _fail(receipt, "source-inspection-failed", step)
        if int(match.group(1), 0) != 0:
            _fail(receipt, "source-dirty", step)
    else:
        runtime._record(receipt, step, True, inspection="not-applicable")


def _mount_options(kind):
    options = {
        "ext3": "ro,noload,nosuid,nodev,noexec",
        "ext4": "ro,noload,nosuid,nodev,noexec",
        "xfs": "ro,norecovery,nosuid,nodev,noexec",
        "btrfs": "ro,nologreplay,nosuid,nodev,noexec",
        "vfat": "ro,nosuid,nodev,noexec",
        "exfat": "ro,nosuid,nodev,noexec",
        "ntfs": "ro,nosuid,nodev,noexec",
    }
    return options.get(kind)


def _unmount(receipt, mp):
    step = "import-source-unmount"
    result = runtime._run(["/usr/bin/umount", mp], step=step, timeout=60)
    if result.returncode != 0:
        receipt["sourceStillMounted"] = True
        _fail(receipt, "source-unmount-failed", step, result.returncode)
    runtime._record(receipt, step, True, rc=result.returncode)
    step = "import-source-unmount-readback"
    result = runtime._run([_FIND, "--noheadings", "--mountpoint", mp], step=step)
    if result.returncode != 1:
        receipt["sourceStillMounted"] = True
        _fail(receipt, "source-unmount-failed", step, result.returncode)
    receipt["sourceStillMounted"] = False
    runtime._record(receipt, step, True, rc=result.returncode)
    os.rmdir(mp)


def _owner_tree(dest, imports, imports_made, uid, gid):
    if imports_made:
        os.lchown(imports, uid, gid)
    os.lchown(dest, uid, gid)

    def raise_walk(error):
        raise error

    for root, dirs, files in os.walk(dest, followlinks=False, onerror=raise_walk):
        for name in dirs + files:
            os.lchown(os.path.join(root, name), uid, gid)


def act(plan: dict, receipt: dict) -> dict:
    device = plan["dataPath"]
    parent = str(runtime.runtime_path("/run/homeserver-nas-import"))
    mp = str(runtime.runtime_path(plan["sourceMountpoint"]))
    nas = str(runtime.runtime_path(plan["nasMountpoint"]))
    imports = str(runtime.runtime_path(plan["destinationDir"]))
    dest = str(runtime.runtime_path(plan["destination"]))
    receipt.update(ok=False, firstMissingSignal=_PREFIX + "not-complete",
                   device=plan["device"], partition=device, label=plan["label"],
                   destination=plan["destination"], mountpoint=plan["nasMountpoint"],
                   sourceFilesystem=plan["fstype"], sourceBytesUsed=None,
                   nasBytesFree=None, transferredBytes=None, changed=False,
                   mutationPerformed=False, sourceStillMounted=False)
    original_ro = None
    protection_attempted = False
    mounted = False
    mp_made = False
    failure = None
    imports_made = False
    try:
        options = _mount_options(plan["fstype"])
        if options is None:
            _fail(receipt, "source-filesystem-unsupported", "import-source-protection")
        original_ro = _ro_state(receipt, device, "import-source-protection-before")
        receipt["sourceInitiallyReadOnly"] = original_ro
        protection_attempted = True
        _checked(receipt, [_BLOCK, "--setro", device], "import-source-protection", "source-protection-failed")
        if not _ro_state(receipt, device, "import-source-protection-readback"):
            _fail(receipt, "source-protection-failed", "import-source-protection-readback")
        _clean_source(plan, receipt)
        try:
            metadata = os.lstat(parent)
        except FileNotFoundError:
            os.mkdir(parent, 0o700)
        else:
            if not stat.S_ISDIR(metadata.st_mode):
                _fail(receipt, "source-mountpoint-busy", "import-source-mountpoint")
        if os.path.dirname(mp) != parent:
            _fail(receipt, "source-mountpoint-busy", "import-source-mountpoint")
        try:
            os.mkdir(mp, 0o755)
        except FileExistsError:
            _fail(receipt, "source-mountpoint-busy", "import-source-mountpoint")
        mp_made = True
        runtime._record(receipt, "import-source-mountpoint", True)
        result = runtime._run(["/usr/bin/mount", "-t", plan["fstypeArg"], "-o", options,
                               device, mp], step="import-source-mount", timeout=180)
        if result.returncode != 0:
            _fail(receipt, "source-mount-failed", "import-source-mount", result.returncode)
        mounted = True
        receipt["sourceStillMounted"] = True
        runtime._record(receipt, "import-source-mount", True, rc=result.returncode)
        result = runtime._run([_FIND, "--json", "--mountpoint", mp, "--output",
                               "SOURCE,MAJ:MIN,OPTIONS,FSTYPE,TARGET"], step="import-source-readback")
        try:
            rows = json.loads(result.stdout).get("filesystems", [])
            row = rows[0] if len(rows) == 1 else {}
            valid = (result.returncode == 0 and row.get("source") == device
                     and row.get("maj:min") == plan["identity"] and row.get("target") == mp
                     and "ro" in row.get("options", "").split(","))
        except (ValueError, TypeError, AttributeError):
            valid = False
            row = {}
        if not valid:
            _fail(receipt, "source-mount-readback-mismatch", "import-source-readback", result.returncode)
        runtime._record(receipt, "import-source-readback", True, options=row["options"])
        source_stat = os.statvfs(mp)
        nas_stat = os.statvfs(nas)
        used = (source_stat.f_blocks - source_stat.f_bfree) * source_stat.f_frsize
        free = nas_stat.f_bavail * nas_stat.f_frsize
        receipt.update(sourceBytesUsed=used, nasBytesFree=free)
        if used * 11 > free * 10:
            _fail(receipt, "no-room", "import-space", sourceBytesUsed=used, nasBytesFree=free)
        runtime._record(receipt, "import-space", True, sourceBytesUsed=used, nasBytesFree=free)
        try:
            metadata = os.lstat(imports)
        except FileNotFoundError:
            receipt.update(changed=True, mutationPerformed=True)
            os.mkdir(imports, 0o755)
            imports_made = True
        else:
            if not stat.S_ISDIR(metadata.st_mode):
                _fail(receipt, "destination-not-directory", "import-destination")
        try:
            receipt.update(changed=True, mutationPerformed=True)
            os.mkdir(dest, 0o755)
        except FileExistsError:
            receipt.update(changed=imports_made, mutationPerformed=imports_made)
            _fail(receipt, "destination-exists", "import-destination")
        runtime._record(receipt, "import-destination", True, importsMade=imports_made)
        base = [_RSYNC, "-rlpt", "--no-owner", "--no-group", "--chmod=u+rwX"]
        result = runtime._run(base + ["--stats", mp + "/", dest + "/"], step="import-copy", timeout=86400)
        if result.returncode != 0:
            _fail(receipt, "copy-failed", "import-copy", result.returncode)
        match = re.search(rb"^Total transferred file size:\s*([0-9][0-9,]*) bytes", result.stdout, re.MULTILINE)
        receipt["transferredBytes"] = int(match.group(1).replace(b",", b"")) if match else None
        runtime._record(receipt, "import-copy", True, transferredBytes=receipt["transferredBytes"])
        result = runtime._run(base + ["--dry-run", "--itemize-changes", "--out-format=%i %n",
                                      mp + "/", dest + "/"], step="import-readback", timeout=86400)
        count = sum(bool(line.strip()) for line in result.stdout.splitlines())
        receipt["itemizeRows"] = count
        if result.returncode != 0 or count:
            _fail(receipt, "readback-mismatch", "import-readback", result.returncode, itemizeRows=count)
        runtime._record(receipt, "import-readback", True, itemizeRows=count)
    except runtime.Refusal as error:
        failure = error
    except OSError:
        failure = runtime.Refusal(_PREFIX + "operation-failed", "import-operation", receipt=receipt)
    finally:
        if mounted:
            try:
                _unmount(receipt, mp)
                mounted = False
                mp_made = False
            except (runtime.Refusal, OSError) as error:
                receipt["sourceStillMounted"] = True
                failure = error if isinstance(error, runtime.Refusal) else runtime.Refusal(
                    _PREFIX + "source-unmount-failed", "import-source-unmount", receipt=receipt)
        elif mp_made:
            try:
                result = runtime._run([_FIND, "--noheadings", "--mountpoint", mp],
                                      step="import-source-unmount-readback")
                if result.returncode == 1:
                    os.rmdir(mp)
                elif result.returncode == 0:
                    receipt["sourceStillMounted"] = True
                    _unmount(receipt, mp)
                else:
                    receipt["sourceStillMounted"] = True
                    failure = runtime.Refusal(_PREFIX + "source-unmount-failed",
                                              "import-source-unmount-readback", result.returncode, receipt)
            except (runtime.Refusal, OSError):
                receipt["sourceStillMounted"] = True
                failure = runtime.Refusal(_PREFIX + "source-unmount-failed", "import-source-unmount-readback", receipt=receipt)
        if protection_attempted and original_ro is False and not receipt["sourceStillMounted"]:
            try:
                _checked(receipt, [_BLOCK, "--setrw", device], "import-source-protection-restore", "source-protection-failed")
                if _ro_state(receipt, device, "import-source-protection-restore-readback"):
                    _fail(receipt, "source-protection-failed", "import-source-protection-restore-readback")
            except runtime.Refusal as error:
                failure = error
    if failure is not None:
        raise runtime._attach_failure(receipt, failure) from None
    try:
        metadata = os.stat(nas)
        _owner_tree(dest, imports, imports_made, metadata.st_uid, metadata.st_gid)
        runtime._record(receipt, "import-ownership", True)
    except OSError:
        failure = runtime.Refusal(_PREFIX + "ownership-failed", "import-ownership", receipt=receipt)
        raise runtime._attach_failure(receipt, failure) from None
    receipt.update(ok=True, firstMissingSignal="none")
    return receipt

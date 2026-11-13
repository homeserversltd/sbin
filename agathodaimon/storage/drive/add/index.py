"""Mount and share one member of the opened data-drive collection."""
from __future__ import annotations

import io
import json
import os
import stat
import sys
import time
from typing import Any, NoReturn, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.storage.drive import deed
from agathodaimon.storage.nas import runtime


def _receipt(device):
    return {"ok": False, "firstMissingSignal": "none", "device": device,
            "partition": None, "disk": None, "fstype": None, "label": None,
            "mount": None, "share": None, "uri": None, "unc": None,
            "ownerWritable": False, "alreadyMounted": False,
            "mutationPerformed": False, "shareServed": False,
            "rolledBack": False, "directMountStarted": False,
            "createdMountpoint": False, "failedStep": None, "mountLeftStanding": False,
            "rollbackSignal": None, "mutationUnknown": False, "steps": []}


def _step(receipt, step, ok, readback):
    receipt["steps"].append({"step": step, "ok": ok, "readback": readback})


def _drive_signal(signal):
    if signal.startswith("agathodaimon-nas-command-"):
        return "agathodaimon-drive-command-failed"
    if signal == "sync-hold-refused-running":
        return "agathodaimon-drive-sync-running"
    return signal


def _refuse(signal, step, code=None) -> NoReturn:
    raise runtime.Refusal(signal, step, code)


def _seat_defaults(rebuild_shares, ledger):
    if rebuild_shares is None:
        try:
            from agathodaimon.storage.drive._shares import rebuild as rebuild_shares
        except ImportError:
            pass
    if ledger is None:
        try:
            from agathodaimon.storage.drive import _opened as ledger
        except ImportError:
            pass
    if not callable(rebuild_shares) or not all(callable(getattr(ledger, n, None)) for n in ("record", "forget", "rows")):
        _refuse("agathodaimon-drive-shares-unavailable", "drive-seats")
    return rebuild_shares, ledger


def _test_unit(device, receipt):
    try:
        result = runtime._run(["/usr/bin/systemctl", "show", "agathodaimon-disk-test.service",
                               "--property=ActiveState,Description"], step="drive-test-unit", timeout=30)
    except runtime.Refusal as failure:
        raise runtime.Refusal(_drive_signal(failure.signal_name), failure.step, failure.return_code) from None
    if result.returncode != 0:
        _refuse("agathodaimon-drive-test-unit-unavailable", "drive-test-unit", result.returncode)
    try:
        fields = dict(line.split("=", 1) for line in result.stdout.decode("utf-8").splitlines() if "=" in line)
    except UnicodeError:
        _refuse("agathodaimon-drive-test-unit-unavailable", "drive-test-unit")
    active = fields.get("ActiveState")
    if active not in {"active", "activating", "deactivating", "reloading", "inactive", "failed"}:
        _refuse("agathodaimon-drive-test-unit-unavailable", "drive-test-unit")
    _step(receipt, "drive-test-unit", True, {"activeState": active})
    description = fields.get("Description", "").split()
    if active in {"active", "activating", "deactivating", "reloading"} and len(description) == 3 and description[:2] == ["disk-test", device]:
        _refuse("agathodaimon-drive-disk-test-running", "drive-test-unit")


def _mount_readback(entries, path, data, fstype, uid):
    entry = next((item for item in entries if item.get("target") == path), None)
    valid_types = {"ntfs", "ntfs3"} if fstype == "ntfs3" else {fstype}
    if not entry or entry.get("dev") != data["maj:min"] or entry.get("fstype") not in valid_types:
        _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
    if data["fstype"] in {"vfat", "exfat", "ntfs"}:
        options = str(entry.get("superOptions", "")).split(",")
        if "uid=" + str(uid) not in options:
            _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
        masks = {key: value for option in options if "=" in option
                 for key, value in [option.split("=", 1)] if key in {"fmask", "dmask", "umask"}}
        try:
            for mask in masks.values():
                if int(mask, 8) & 0o200:
                    _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
        except ValueError:
            _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
        if data["fstype"] == "vfat" and not ("umask" in masks or {"fmask", "dmask"} <= masks.keys()):
            _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
        return True
    try:
        info = os.stat(path)
        return info.st_uid == uid and bool(info.st_mode & stat.S_IWUSR)
    except OSError:
        _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")


def _rmdir(path, receipt):
    try:
        result = runtime._run(["/usr/bin/rmdir", path], step="drive-rmdir")
        ok = result.returncode == 0
        _step(receipt, "drive-rmdir", ok, {"returnCode": result.returncode})
        return ok
    except runtime.Refusal:
        _step(receipt, "drive-rmdir", False, {})
        return False


def _forget_unmounted(receipt, ledger):
    try:
        ledger.forget(receipt["label"])
        _step(receipt, "drive-ledger-forget", True, {})
        return True
    except Exception:
        _step(receipt, "drive-ledger-forget", False, {})
        receipt["rollbackSignal"] = "agathodaimon-drive-ledger-unavailable"
        return False


def _rollback(receipt, ledger, rebuild_shares, expected_identity, *, unreaped=False):
    from agathodaimon.storage.drive import _drive
    path = receipt["mount"]
    if receipt["alreadyMounted"]:
        receipt["mountLeftStanding"] = True
        return

    def observe():
        try:
            return [row for row in _drive.mountinfo_entries() if row.get("target") == path]
        except Exception:
            receipt.update(mutationUnknown=True, rollbackSignal="agathodaimon-drive-mount-readback-mismatch")
            return None

    entries = observe()
    if entries:
        receipt.update(mutationPerformed=True, mountLeftStanding=True)
    if unreaped:
        receipt["mutationUnknown"] = True
        return
    if entries is None:
        return
    if entries:
        if len(entries) != 1 or entries[0].get("dev") != expected_identity:
            receipt["rollbackSignal"] = "agathodaimon-drive-mount-readback-mismatch"
            return
        try:
            result = runtime._run(["/usr/bin/umount", path], step="drive-rollback-umount", timeout=180)
            _step(receipt, "drive-rollback-umount", result.returncode == 0, {"returnCode": result.returncode})
            if result.returncode != 0:
                raise runtime.Refusal("agathodaimon-drive-busy", "drive-rollback-umount", result.returncode)
        except runtime.Refusal as failure:
            unreaped_umount = failure.signal_name.endswith("command-group-unreaped")
            if unreaped_umount:
                receipt["mutationUnknown"] = True
            entries = observe()
            if entries:
                receipt.update(firstMissingSignal="agathodaimon-drive-busy", failedStep="drive-rollback-umount",
                               unmounted=path, mutationPerformed=True, mountLeftStanding=True)
                return
            if entries is None or unreaped_umount:
                return
        else:
            entries = observe()
        if entries is None:
            return
        if entries:
            receipt.update(firstMissingSignal="agathodaimon-drive-busy", failedStep="drive-rollback-umount",
                           unmounted=path, mutationPerformed=True, mountLeftStanding=True)
            return
    receipt.update(mutationPerformed=False, mountLeftStanding=False)
    clean = _forget_unmounted(receipt, ledger)
    try:
        reply = rebuild_shares(exclude_mountpoints=(path,))
        share_clean = isinstance(reply, dict) and reply.get("ok") is True
        _step(receipt, "drive-share-cleanup", share_clean, {})
        if not share_clean:
            receipt["rollbackSignal"] = receipt["rollbackSignal"] or "agathodaimon-drive-shares-refused"
            clean = False
    except Exception:
        _step(receipt, "drive-share-cleanup", False, {})
        receipt["rollbackSignal"] = receipt["rollbackSignal"] or "agathodaimon-drive-shares-refused"
        clean = False
    if receipt["createdMountpoint"] and not _rmdir(path, receipt):
        receipt["rollbackSignal"] = receipt["rollbackSignal"] or "agathodaimon-drive-mountpoint-cleanup-failed"
        clean = False
    receipt["rolledBack"] = clean


def _act_body(device, dry_run, rebuild_shares, ledger, receipt, context):
    if os.geteuid() != 0:
        _refuse("agathodaimon-drive-root-required", "drive-root")
    try:
        from agathodaimon.storage.drive import _drive, _resolve
    except ImportError:
        _refuse("agathodaimon-drive-resolver-unavailable", "drive-resolver")
    uid, gid = _drive.owner_identity()
    resolved = _resolve.resolve_device(receipt, device)
    receipt["disk"] = resolved["disk"]
    if any(value in {"homeserver-primary-nas", "homeserver-backup-nas"} for value in resolved["partlabels"]):
        _refuse("agathodaimon-drive-nas-labelled-refused", "drive-device")
    _test_unit(device, receipt)
    data = resolved["data"]
    if not data:
        _refuse(resolved["dataRefusal"], "drive-data")
    label = _resolve.label_for(resolved)
    path = str(runtime.runtime_path("/mnt/" + label))
    receipt.update(partition=data["path"], fstype=data["fstype"], label=label, mount=path,
                   share={"name": label, "path": path}, uri="smb://home.arpa/" + label,
                   unc="\\\\home.arpa\\" + label)
    existing = _drive.mount_of(data)
    if existing and existing.get("target") != path:
        _refuse("agathodaimon-drive-mounted-elsewhere", "drive-mount-state")
    receipt["alreadyMounted"] = bool(existing)
    absent = False
    if not existing:
        try:
            mode = os.lstat(path).st_mode
            if not stat.S_ISDIR(mode):
                _refuse("agathodaimon-drive-mountpoint-not-directory", "drive-mountpoint")
        except FileNotFoundError:
            absent = True
        if any(row.get("target") == path for row in _drive.mountinfo_entries()):
            _refuse("agathodaimon-drive-mountpoint-in-use", "drive-mountpoint")
        if not absent and os.listdir(path):
            _refuse("agathodaimon-drive-mountpoint-not-empty", "drive-mountpoint")
    fstype, options = _resolve.mount_plan(data["fstype"], uid, gid)
    rebuild_shares, ledger = _seat_defaults(rebuild_shares, ledger)
    context.update(ledger=ledger, rebuild_shares=rebuild_shares, identity=data["maj:min"])
    if dry_run:
        receipt.update(ok=True, planned={"fstype": fstype, "options": options, "mount": path,
                                         "label": label, "share": receipt["share"]})
        return
    if not existing:
        try:
            ledger.record(label, data["maj:min"])
        except runtime.Refusal:
            raise
        except Exception:
            _refuse("agathodaimon-drive-ledger-unavailable", "drive-ledger-record")
        _step(receipt, "drive-ledger-record", True, {"beforeMount": True})
        if absent:
            try:
                os.mkdir(path, 0o755)
                receipt["createdMountpoint"] = True
                if not stat.S_ISDIR(os.lstat(path).st_mode):
                    _refuse("agathodaimon-drive-mountpoint-not-directory", "drive-mountpoint")
            except (OSError, runtime.Refusal):
                _forget_unmounted(receipt, ledger)
                if receipt["createdMountpoint"]:
                    _rmdir(path, receipt)
                _refuse("agathodaimon-drive-mountpoint-not-directory", "drive-mountpoint")
        argv = ["/usr/bin/mount", "-t", fstype] + (["-o", options] if options is not None else []) + [data["path"], path]
        try:
            info = os.stat(data["path"])
            if not stat.S_ISBLK(info.st_mode) or f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}" != data["maj:min"]:
                raise ValueError("device identity changed")
        except (OSError, ValueError):
            _forget_unmounted(receipt, ledger)
            if receipt["createdMountpoint"] and not _rmdir(path, receipt):
                receipt["rollbackSignal"] = "agathodaimon-drive-mountpoint-cleanup-failed"
            _refuse("agathodaimon-drive-device-identity-mismatch", "drive-device-identity")
        receipt["directMountStarted"] = True
        result = runtime._run(argv, step="drive-mount", timeout=180)
        _step(receipt, "drive-mount", result.returncode == 0, {"returnCode": result.returncode})
        if result.returncode != 0:
            _refuse("agathodaimon-drive-mount-failed", "drive-mount", result.returncode)
        receipt["mutationPerformed"] = True
    try:
        receipt["ownerWritable"] = _mount_readback(_drive.mountinfo_entries(), path, data, fstype, uid)
        _step(receipt, "drive-mount-readback", True, {"ownerWritable": receipt["ownerWritable"]})
        if existing:
            try:
                ledger.record(label, data["maj:min"])
            except Exception:
                _refuse("agathodaimon-drive-ledger-unavailable", "drive-ledger-record")
            _step(receipt, "drive-ledger-record", True, {"beforeMount": False})
        try:
            reply = rebuild_shares(exclude_mountpoints=())
        except runtime.Refusal as failure:
            if failure.signal_name.endswith("command-group-unreaped"):
                raise
            _refuse("agathodaimon-drive-shares-refused", "drive-shares")
        except Exception:
            _refuse("agathodaimon-drive-shares-refused", "drive-shares")
        if not isinstance(reply, dict) or reply.get("ok") is not True:
            receipt["shareFailure"] = reply.get("firstMissingSignal") if isinstance(reply, dict) else None
            if isinstance(receipt["shareFailure"], str) and receipt["shareFailure"].endswith("command-group-unreaped"):
                raise runtime.Refusal(receipt["shareFailure"], reply.get("failedStep") or "drive-shares")
            _refuse("agathodaimon-drive-shares-refused", "drive-shares")
        if reply.get("includedBySmbConf") is not True:
            _refuse("agathodaimon-drive-share-not-served", "drive-shares")
        if not any(item.get("name") == label for item in reply.get("shares", []) if isinstance(item, dict)):
            _refuse("agathodaimon-drive-shares-refused", "drive-shares")
        receipt["shareServed"] = True
        _step(receipt, "drive-shares", True, {"includedBySmbConf": True})
        receipt["ok"] = True
    except runtime.Refusal:
        raise


@runtime.guarded_drive
def _act(device, dry_run, rebuild_shares, ledger, receipt, context):
    try:
        _act_body(device, dry_run, rebuild_shares, ledger, receipt, context)
    except Exception as failure:
        if isinstance(failure, runtime.Refusal):
            signal, step, code = _drive_signal(failure.signal_name), failure.step, failure.return_code
            unreaped = failure.signal_name.endswith("command-group-unreaped")
        else:
            signal, step, code, unreaped = "agathodaimon-drive-operation-unavailable", "drive-operation", None, False
        receipt.update(firstMissingSignal=signal, failedStep=step)
        if code is not None:
            receipt["returnCode"] = code
        _step(receipt, step, False, {})
        if receipt["directMountStarted"] or (receipt["alreadyMounted"] and context):
            _rollback(receipt, context["ledger"], context["rebuild_shares"], context["identity"], unreaped=unreaped)


def add_drive(device, *, dry_run=False, rebuild_shares=None, ledger=None) -> dict:
    started = time.monotonic()
    receipt = _receipt(device)
    context = {}
    try:
        if os.geteuid() != 0:
            _refuse("agathodaimon-drive-root-required", "drive-root")
        _act(device, dry_run, rebuild_shares, ledger, receipt, context)
    except runtime.Refusal as failure:
        receipt.update(firstMissingSignal=_drive_signal(failure.signal_name), failedStep=failure.step)
        if failure.return_code is not None:
            receipt["returnCode"] = failure.return_code
        _step(receipt, failure.step, False, {})
    except Exception:
        receipt.update(firstMissingSignal="agathodaimon-drive-operation-unavailable", failedStep="drive-operation")
        if receipt["directMountStarted"] and context:
            try:
                with runtime.drive_guard():
                    _rollback(receipt, context["ledger"], context["rebuild_shares"], context["identity"])
            except Exception:
                receipt["mutationUnknown"] = True
    if receipt["directMountStarted"] and receipt["mutationPerformed"]:
        try:
            logged = deed.record("drive-add", receipt["ok"], int((time.monotonic() - started) * 1000),
                                 signal=None if receipt["ok"] else receipt["firstMissingSignal"])
        except Exception:
            logged = False
        if not logged:
            receipt["deedLogSignal"] = "caduceus-deed-post-failed"
    return receipt


def dispatch(request: Any) -> dict[str, Any]:
    payload = getattr(request, "payload", None)
    payload = payload if isinstance(payload, dict) else {}
    dry_run = payload.get("dry-run", False)
    if type(dry_run) is not bool:
        receipt = _receipt(payload.get("device"))
        receipt.update(firstMissingSignal="agathodaimon-drive-dry-run-invalid", failedStep="request")
    else:
        receipt = add_drive(payload.get("device"), dry_run=dry_run)
    return attach_envelope(receipt, request)


def _read_request():
    raw = sys.stdin.buffer.read(runtime.MAX_INPUT + 1)
    if not raw or len(raw) > runtime.MAX_INPUT:
        raise ValueError("request-size-invalid")
    previous = sys.stdin
    try:
        sys.stdin = io.StringIO(raw.decode("utf-8"))
        return read_envelope(known_fields=("device", "dry-run"))
    finally:
        sys.stdin = previous


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        receipt = dispatch(_read_request())
    except (ValueError, UnicodeError, json.JSONDecodeError, EnvelopeError):
        receipt = _receipt(None)
        receipt.update(firstMissingSignal="agathodaimon-drive-request-invalid", failedStep="request")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

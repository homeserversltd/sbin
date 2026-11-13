"""Unshare and unmount one staff-opened data drive."""
from __future__ import annotations

import io
import json
import os
import re
import sys
import time
from typing import Any, NoReturn, Sequence

from _envelope import EnvelopeError, attach as attach_envelope, read as read_envelope
from agathodaimon.storage.drive import _drive, _opened, _resolve, _shares, deed
from agathodaimon.storage.drive.add.index import _test_unit
from agathodaimon.storage.nas import runtime


def _receipt(device):
    return {"ok": False, "firstMissingSignal": "none", "device": device,
            "partition": None, "mount": None, "share": None, "changed": False,
            "mutationPerformed": False, "unmounted": False, "alreadyRemoved": False,
            "pruned": [], "failedStep": None, "mountLeftStanding": False,
            "rollbackSignal": None, "mutationUnknown": False, "steps": []}


def _step(receipt, name, ok, readback):
    receipt["steps"].append({"step": name, "ok": ok, "readback": readback})


def _refuse(signal, step, code=None) -> NoReturn:
    raise runtime.Refusal(signal, step, code)


def _observe(receipt, node, target):
    try:
        entries = _drive.mountinfo_entries()
        matching = [entry for entry in entries if (target and entry.get("target") == target)
                    or (node and entry.get("dev") == node.get("maj:min"))]
        nested = [entry["target"] for entry in entries
                  if target and entry.get("target", "").startswith(target + "/")]
        receipt["mountLeftStanding"] = bool(matching or nested)
        return matching, nested
    except Exception:
        receipt["mutationUnknown"] = True
        receipt["rollbackSignal"] = "agathodaimon-drive-mount-census-unavailable"
        return None, None


def _merge_share(receipt, reply):
    if isinstance(reply, dict):
        receipt["changed"] = receipt["changed"] or reply.get("changed") is True
        receipt["mutationPerformed"] = receipt["mutationPerformed"] or reply.get("mutationPerformed") is True
        receipt["pruned"] = reply.get("pruned", [])


def _restore(receipt, target):
    try:
        reply = _shares.rebuild(exclude_mountpoints=())
        _merge_share(receipt, reply)
        ok = isinstance(reply, dict) and reply.get("ok") is True
        rows = reply.get("shares", []) if isinstance(reply, dict) else []
        present = isinstance(rows, list) and any(
            isinstance(row, dict) and row.get("path") == target for row in rows)
        included = reply.get("includedBySmbConf") if isinstance(reply, dict) else None
        reloaded = reply.get("reloaded") if isinstance(reply, dict) else None
        changed = reply.get("changed") if isinstance(reply, dict) else None
        confirmed = ok and present and (included is False or (included is True and (changed is True and reloaded is True)))
        receipt["sharesRestored"] = confirmed
        receipt["shareRestoreIncluded"] = included
        if not confirmed:
            signal = reply.get("firstMissingSignal") if isinstance(reply, dict) else None
            receipt["rollbackSignal"] = signal if signal and signal != "none" else "agathodaimon-drive-share-restore-unconfirmed"
    except Exception:
        receipt["sharesRestored"] = False
        receipt["rollbackSignal"] = "agathodaimon-drive-shares-refused"
    _step(receipt, "drive-shares-restore", receipt["sharesRestored"], {})


def _missing_device(device):
    """Find exactly one recorded mount whose original source names this absent disk."""
    if not isinstance(device, str) or not re.fullmatch(r"/dev/(?:sd[a-z]+|nvme[0-9]+n[0-9]+|loop[0-9]+)", device):
        return None
    if os.path.lexists(runtime.runtime_path(device)):
        return None
    suffix = r"(?:p[1-9][0-9]*)?" if device[-1].isdigit() else r"(?:[1-9][0-9]*)?"
    source = re.compile(re.escape(device) + suffix + r"\Z")
    entries = _drive.mountinfo_entries()
    candidates = []
    for row in _opened.rows():
        label, identity, target = row.get("label"), row.get("device_identity"), row.get("mountpoint")
        if not (isinstance(label, str) and _opened.valid_label(label) and isinstance(identity, str) and _opened._ID.fullmatch(identity)
                and target == "/mnt/" + label):
            continue
        if runtime.runtime_path("/sys/dev/block/" + identity).exists():
            continue
        matches = [entry for entry in entries if entry.get("target") == target and entry.get("dev") == identity
                   and isinstance(entry.get("source"), str) and source.fullmatch(entry["source"])]
        if len(matches) == 1 and sum(entry.get("target") == target for entry in entries) == 1:
            candidates.append((row, matches[0]))
    return candidates[0] if len(candidates) == 1 else None


def _guard_missing(device, node, receipt, entries):
    """Refuse protected mounts and swap even when the device census lost them."""
    suffix = r"(?:p[1-9][0-9]*)?" if device[-1].isdigit() else r"(?:[1-9][0-9]*)?"
    source = re.compile(re.escape(device) + suffix + r"\Z")
    related = [entry for entry in entries if entry.get("dev") == node["maj:min"]
               or (isinstance(entry.get("source"), str) and source.fullmatch(entry["source"]))]
    if any(entry.get("target") in _resolve.SYSTEM_CRITICAL for entry in related):
        _refuse("agathodaimon-drive-system-device-refused", "protected-mount-preflight")
    try:
        swaps = runtime.runtime_path("/proc/swaps").read_text(encoding="utf-8").splitlines()[1:]
    except (OSError, UnicodeError):
        _refuse("agathodaimon-drive-protected-census-unavailable", "protected-mount-preflight")
    if any(line.split() and source.fullmatch(line.split()[0]) for line in swaps):
        _refuse("agathodaimon-drive-system-device-refused", "protected-mount-preflight")
    if any(entry.get("target") in {"/mnt/nas", "/mnt/nas_backup"} for entry in related):
        receipt["instead"] = "storage nas detach"
        _refuse("agathodaimon-drive-nas-role-refused", "protected-mount-preflight")


def _act_body(device, dry_run, receipt, context):
    missing = None
    resolved = None
    mount = None
    try:
        resolved = _resolve.resolve_device(receipt, device)
    except runtime.Refusal as failure:
        if failure.signal_name != "agathodaimon-drive-device-not-in-block-census":
            raise
        missing = _missing_device(device)
        if missing is None:
            raise
    _step(receipt, "drive-device", True, {})
    if missing is not None:
        row, mount = missing
        label = row["label"]
        node = {"path": mount["source"], "maj:min": row["device_identity"]}
        context.update(node=node, target=mount["target"])
        receipt.update(partition=node["path"], mount=mount["target"], mountLeftStanding=True)
        _guard_missing(device, node, receipt, _drive.mountinfo_entries())
    else:
        if resolved is None:
            _refuse("agathodaimon-drive-device-not-in-block-census", "device-census")
        if any(label in {"homeserver-primary-nas", "homeserver-backup-nas"} for label in resolved["partlabels"]):
            receipt["instead"] = "storage nas detach"
            _refuse("agathodaimon-drive-nas-role-refused", "drive-device")
        node = resolved["data"]
        if node is None:
            _refuse(resolved["dataRefusal"], "drive-data")
        label = _resolve.label_for(resolved)
    _test_unit(device, receipt)
    if missing is None:
        mount = _drive.mount_of(node)
    target = "/mnt/" + label
    context.update(node=node, target=target)
    receipt["partition"] = node["path"]
    if mount is None:
        receipt["alreadyRemoved"] = True
        receipt["mount"] = None
    else:
        target = mount["target"]
        context["target"] = target
        receipt["mount"] = target
        receipt["mountLeftStanding"] = True
        if target in {"/mnt/nas", "/mnt/nas_backup"}:
            receipt["instead"] = "storage nas detach"
            _refuse("agathodaimon-drive-nas-role-refused", "drive-mount-state")
        if target != "/mnt/" + label:
            _refuse("agathodaimon-drive-mounted-elsewhere", "drive-mount-state")
        rows = _opened.rows()
        if not any(row.get("label") == label and row.get("device_identity") == node["maj:min"]
                   and row.get("mountpoint") == target for row in rows):
            _refuse("agathodaimon-drive-not-opened-here", "drive-ledger")
        nested = [entry["target"] for entry in _drive.mountinfo_entries()
                  if entry.get("target", "").startswith(target + "/")]
        if nested:
            receipt["nestedMounts"] = nested
            _refuse("agathodaimon-drive-busy", "drive-mount-state")
    _step(receipt, "drive-mount-state", True, {"mount": receipt["mount"]})
    if dry_run:
        receipt.update(ok=True, planned={"mount": receipt["mount"], "share": label,
                       "sharesRebuildWithout": mount is not None, "unmount": mount is not None})
        return
    context["shares_attempted"] = mount is not None
    reply = _shares.rebuild(exclude_mountpoints=(target,), force_reload=True) if mount is not None else _shares.rebuild(exclude_mountpoints=())
    _merge_share(receipt, reply)
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        signal = reply.get("firstMissingSignal") if isinstance(reply, dict) else None
        receipt["sharesSignal"] = signal
        if isinstance(signal, str) and signal.endswith("command-group-unreaped"):
            receipt["mutationUnknown"] = True
            context["unreaped"] = True
        if mount is not None and isinstance(reply, dict) and reply.get("failedStep") == "reload":
            _refuse("agathodaimon-drive-share-unconfirmed", "drive-shares")
        _refuse("agathodaimon-drive-shares-refused", "drive-shares")
    _step(receipt, "drive-shares", True, {"includedBySmbConf": reply.get("includedBySmbConf"),
                                           "reloaded": reply.get("reloaded")})
    if mount is None:
        receipt["ok"] = True
        return
    shares = reply.get("shares")
    if (not isinstance(shares, list)
            or any(not isinstance(item, dict) or item.get("path") == target for item in shares)
            or reply.get("includedBySmbConf") not in (True, False)
            or (reply.get("includedBySmbConf") is True and reply.get("reloaded") is not True)):
        _refuse("agathodaimon-drive-share-unconfirmed", "drive-shares")
    receipt["share"] = {"name": label, "closedBeforeUnmount": True,
                        "includedBySmbConf": reply.get("includedBySmbConf"), "reloaded": reply.get("reloaded")}
    # Recheck both the target and identity immediately before issuing umount.
    entries = _drive.mountinfo_entries()
    if missing is not None:
        _guard_missing(device, node, receipt, entries)
    at_target = [entry for entry in entries if entry.get("target") == target]
    nested = [entry["target"] for entry in entries if entry.get("target", "").startswith(target + "/")]
    if len(at_target) != 1 or at_target[0].get("dev") != node["maj:min"] or nested:
        if nested:
            receipt["nestedMounts"] = nested
        _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-pre-unmount")
    outcome = None
    context["unmount_started"] = True
    try:
        result = runtime._run(["/usr/bin/umount", target], step="drive-umount", timeout=180)
        receipt["unmountRc"] = result.returncode
        outcome = result.returncode
    except runtime.Refusal as failure:
        receipt["unmountSignal"] = failure.signal_name
        if failure.signal_name.endswith("command-group-unreaped"):
            receipt["mutationUnknown"] = True
            context["unreaped"] = True
    _step(receipt, "drive-umount", outcome == 0, {"returnCode": outcome})
    matching, nested = _observe(receipt, node, target)
    if matching is None or context.get("unreaped"):
        _refuse("agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
    if matching or nested:
        if nested:
            receipt["nestedMounts"] = nested
        _refuse("agathodaimon-drive-busy" if outcome != 0 else "agathodaimon-drive-mount-readback-mismatch", "drive-mount-readback")
    receipt.update(unmounted=True, changed=True, mutationPerformed=True)
    _step(receipt, "drive-mount-readback", True, {})
    try:
        _opened.forget(label)
        _step(receipt, "drive-ledger-forget", True, {})
    except Exception:
        receipt["ledgerSignal"] = "agathodaimon-drive-ledger-forget-failed"
        _step(receipt, "drive-ledger-forget", False, {})
    receipt["ok"] = True


@runtime.guarded_drive
def _act(device, dry_run, receipt, context):
    try:
        _act_body(device, dry_run, receipt, context)
    except Exception as failure:
        if isinstance(failure, runtime.Refusal):
            signal, step, code = failure.signal_name, failure.step, failure.return_code
            if signal.startswith("agathodaimon-nas-command-"):
                signal = "agathodaimon-drive-command-failed"
            elif signal == "sync-hold-refused-running":
                signal = "agathodaimon-drive-sync-running"
            if failure.signal_name.endswith("command-group-unreaped"):
                context["unreaped"] = True
                receipt["mutationUnknown"] = True
        else:
            signal, step, code = "agathodaimon-drive-operation-unavailable", "drive-operation", None
        receipt.update(firstMissingSignal=signal, failedStep=step)
        if code is not None:
            receipt["returnCode"] = code
        _step(receipt, step, False, {})
        matching, nested = _observe(receipt, context.get("node"), context.get("target"))
        if context.get("shares_attempted") and not context.get("unreaped"):
            if matching is None or matching or nested:
                _restore(receipt, context["target"])
            elif context.get("unmount_started"):
                receipt.update(unmounted=True, changed=True, mutationPerformed=True)
            else:
                receipt["mutationUnknown"] = True


def remove_drive(device, *, dry_run=False):
    started = time.monotonic()
    receipt = _receipt(device)
    context = {}
    try:
        if os.geteuid() != 0:
            _refuse("agathodaimon-drive-root-required", "drive-root")
        _step(receipt, "drive-root", True, {})
        _act(device, dry_run, receipt, context)
    except runtime.Refusal as failure:
        signal = failure.signal_name
        if signal == "sync-hold-refused-running":
            signal = "agathodaimon-drive-sync-running"
        receipt.update(firstMissingSignal=signal, failedStep=failure.step)
        _step(receipt, failure.step, False, {})
        _observe(receipt, context.get("node"), context.get("target"))
    except Exception:
        receipt.update(firstMissingSignal="agathodaimon-drive-operation-unavailable", failedStep="drive-operation")
        _observe(receipt, context.get("node"), context.get("target"))
    if receipt["ok"] is not True or receipt["unmounted"] or receipt["mutationPerformed"]:
        try:
            logged = deed.record("drive-remove", receipt["ok"], int((time.monotonic() - started) * 1000),
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
        receipt = remove_drive(payload.get("device"), dry_run=dry_run)
    return attach_envelope(receipt, request)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        raw = sys.stdin.buffer.read(runtime.MAX_INPUT + 1)
        if not raw or len(raw) > runtime.MAX_INPUT:
            raise ValueError("request-size-invalid")
        previous = sys.stdin
        try:
            sys.stdin = io.StringIO(raw.decode("utf-8"))
            request = read_envelope(known_fields=("device", "dry-run"))
        finally:
            sys.stdin = previous
        receipt = dispatch(request)
    except (ValueError, UnicodeError, json.JSONDecodeError, EnvelopeError):
        receipt = _receipt(None)
        receipt.update(firstMissingSignal="agathodaimon-drive-request-invalid", failedStep="request")
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

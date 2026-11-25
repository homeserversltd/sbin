"""Re-key a labelled NAS partition without exposing either passphrase."""
from __future__ import annotations

from dataclasses import replace
import json
import os
import selectors
import signal
import subprocess
import time

from _envelope import EnvelopeError, attach, read, wipe_bytes
from agathodaimon.lib.keyman_export.index import KeymanExportError
from agathodaimon.storage.nas import deed, labels, runtime

# Helper refusals are translated once, at the boundary. Prefix entries cover
# all members of the partition/device/label helper families.
REFUSAL_SIGNALS = {
    "agathodaimon-nas-root-required": "nas-rekey-root-required",
    "agathodaimon-nas-drive-operation-running": "nas-rekey-drive-busy",
    "sync-hold-refused-running": "nas-rekey-drive-busy",
    "agathodaimon-nas-role-invalid": "nas-rekey-request-invalid",
    "agathodaimon-nas-request-invalid": "nas-rekey-request-invalid",
    "agathodaimon-envelope-": "nas-rekey-request-invalid",
    "agathodaimon-nas-partition-": "nas-rekey-partition-invalid",
    "agathodaimon-nas-partlabel-": "nas-rekey-partition-invalid",
    "agathodaimon-nas-device-": "nas-rekey-partition-invalid",
    "agathodaimon-nas-key-export-failed": "nas-rekey-own-key-unavailable",
    "agathodaimon-nas-command-timeout": "nas-rekey-timeout",
}


def _translate(name, writing):
    if name.startswith("nas-rekey-"):
        return name
    if name in REFUSAL_SIGNALS:
        return REFUSAL_SIGNALS[name]
    for prefix, signal in REFUSAL_SIGNALS.items():
        if prefix.endswith("-") and name.startswith(prefix):
            return signal
    return "nas-rekey-slot-write-failed" if writing else "nas-rekey-partition-invalid"


def _receipt(role=None, partition=None):
    return {"ok": False, "key_role": role, "partition": partition, "steps": [],
            "failedStep": None, "returnCode": None, "keptSlot": None,
            "ownSlots": [], "changed": False, "firstMissingSignal": "none"}


def _refuse(signal, step, code=None):
    raise runtime.Refusal(signal, step, code)


def _dump(partition):
    result = runtime._run([runtime.CRYPTSETUP, "luksDump", "--dump-json-metadata", "--", partition],
                          timeout=120, step="slot-census")
    if result.returncode:
        _refuse("nas-rekey-partition-invalid", "slot-census", result.returncode)
    try:
        data = json.loads(result.stdout)
        slots = data["keyslots"]
        if not isinstance(slots, dict) or not slots:
            raise ValueError()
        used = {int(k) for k in slots}
        if len(used) != len(slots) or any(str(n) not in slots or not 0 <= n < 32 for n in used):
            raise ValueError()
        sizes = [int(row["area"]["size"]) for row in slots.values()]
        offsets = [int(row["area"]["offset"]) for row in slots.values()]
        capacity = int(data["config"]["keyslots_size"])
        if min(sizes) <= 0 or min(offsets) < 0 or capacity <= 0 or sum(sizes) > capacity:
            raise ValueError()
        return used, max(0, (capacity - sum(sizes)) // max(sizes))
    except (ValueError, KeyError, TypeError, OverflowError, ZeroDivisionError):
        _refuse("nas-rekey-partition-invalid", "slot-census")


def _matches(partition, key, slot, step):
    result = runtime._run([runtime.CRYPTSETUP, "open", "--test-passphrase", "--key-file", "-",
                           "--key-slot", str(slot), "--", partition],
                          input_data=key, timeout=120, step=step, suppress_output=True)
    if result.returncode not in (0, 2):
        _refuse("nas-rekey-readback-failed", step, result.returncode)
    return result.returncode == 0


def _stop_add(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _add(partition, old_key, new_key, slot):
    """Give cryptsetup two independent streams; neither key appears in argv."""
    read_fd, write_fd = os.pipe()
    process = None
    try:
        command = runtime.command_argv([runtime.CRYPTSETUP, "luksAddKey", "--key-file", "-",
                                        "--new-key-slot", str(slot), "--", partition,
                                        "/dev/fd/" + str(read_fd)])
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, pass_fds=(read_fd,), env={},
                                   start_new_session=True)
        os.close(read_fd)
        read_fd = -1
        deadline = time.monotonic() + 120
        assert process.stdin is not None
        streams = {process.stdin.fileno(): (process.stdin, old_key, 0),
                   write_fd: (None, new_key, 0)}
        with selectors.DefaultSelector() as selector:
            for fd in streams:
                os.set_blocking(fd, False)
                selector.register(fd, selectors.EVENT_WRITE)
            while streams:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, 120)
                for event, _ in selector.select(remaining):
                    fd = event.fd
                    stream, data, offset = streams[fd]
                    with memoryview(data) as view:
                        count = os.write(fd, view[offset:])
                    offset += count
                    if offset == len(data):
                        selector.unregister(fd)
                        del streams[fd]
                        if stream is None:
                            os.close(fd)
                            write_fd = -1
                        else:
                            stream.close()
                    else:
                        streams[fd] = (stream, data, offset)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        return process.returncode
    except subprocess.TimeoutExpired:
        if process is not None:
            _stop_add(process)
        _refuse("nas-rekey-timeout", "slot-add")
    except OSError:
        if process is not None:
            _stop_add(process)
        _refuse("nas-rekey-slot-write-failed", "slot-add")
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def perform(role, partition, old, keep):
    receipt = _receipt(role, partition)
    material = None
    guard = None
    entered = False
    writing = False
    try:
        if (not isinstance(old, bytearray) or not 1 <= len(old) <= 511
                or any(c in old for c in (0, 10, 13, 34)) or type(keep) is not bool):
            _refuse("nas-rekey-request-invalid", "request")
        runtime._require_root(receipt)
        guard = runtime.drive_guard()
        guard.__enter__()
        entered = True
        runtime._record(receipt, "sync-lock", True, acquired=True)
        runtime._role_info(role)
        if (not isinstance(partition, str) or not partition.startswith("/dev/")
                or "\x00" in partition or os.path.normpath(partition) != partition):
            _refuse("nas-rekey-partition-invalid", "partition-preflight")
        identity = runtime._device_identity(partition, "partition-preflight")
        rows = labels.census()
        matches = [row for row in rows if row["identity"] == identity]
        if len(matches) != 1:
            _refuse("nas-rekey-partition-invalid", "partition-preflight")
        row = labels.select(matches[0]["label"], rows)
        runtime._record(receipt, "partition-preflight", True, identity=identity, partlabel=row["label"])
        try:
            material = runtime._export_for_role(role, runtime._scratch_root())
        except KeymanExportError:
            _refuse("nas-rekey-own-key-unavailable", "key-export")
        if not isinstance(material, bytearray) or not material:
            _refuse("nas-rekey-own-key-unavailable", "key-export")
        runtime._record(receipt, "key-export", True, present=True)
        if runtime._device_identity(partition, "partition-preflight") != identity:
            _refuse("nas-rekey-partition-invalid", "partition-preflight")
        used, room = _dump(partition)
        own = {slot for slot in used if _matches(partition, material, slot, "own-census")}
        old_open = {slot for slot in used if _matches(partition, old, slot, "old-census")}
        old_only = old_open - own
        same = bool(old_open) and old == material
        receipt["ownSlots"] = sorted(own)
        runtime._record(receipt, "slot-census", True, used=sorted(used), ownSlots=sorted(own))
        if not old_open and (not own or keep):
            _refuse("nas-rekey-old-password-mismatched", "old-census")
        if own == {0, 1} and not old_only and (not keep or same):
            receipt.update(ok=True, firstMissingSignal="none")
            return receipt
        preserve = keep and not same
        kept = min((s for s in old_only if s >= 2), default=None) if preserve else None
        need_old = preserve and kept is None
        need_own = not own
        free = sorted(set(range(32)) - used)
        need = int(need_old) + int(need_own)
        if len(free) < need or room < need or (need_old and not any(s >= 2 for s in free)):
            _refuse("nas-rekey-no-free-slot", "slot-space")

        def add(slot, authorizer, new_key, kind):
            nonlocal writing
            writing = True
            receipt["changed"] = True  # an interrupted write can have landed
            rc = _add(partition, authorizer, new_key, slot)
            if rc != 0:
                _refuse("nas-rekey-slot-write-failed", kind, rc)
            used.add(slot)
            if not _matches(partition, new_key, slot, kind + "-readback"):
                _refuse("nas-rekey-readback-failed", kind + "-readback", 2)
            runtime._record(receipt, kind, True, slot=slot, readback=True)

        def kill(slot):
            nonlocal writing
            alternatives = [n for n in sorted(own) if n != slot]
            if not any(_matches(partition, material, n, "kill-guard") for n in alternatives):
                _refuse("nas-rekey-readback-failed", "kill-guard")
            writing = True
            receipt["changed"] = True
            result = runtime._run([runtime.CRYPTSETUP, "luksKillSlot", "--verify-passphrase", "--key-file", "-", "--", partition, str(slot)],
                                  input_data=material, timeout=120, step="slot-kill", suppress_output=True)
            if result.returncode:
                _refuse("nas-rekey-slot-write-failed", "slot-kill", result.returncode)
            used.remove(slot)
            own.discard(slot)
            old_only.discard(slot)
            runtime._record(receipt, "slot-kill", True, slot=slot)

        if need_old:
            kept = min(s for s in free if s >= 2)
            add(kept, old, old, "keep-old")
            old_only.add(kept)
        receipt["keptSlot"] = kept
        if not own:
            temp = min(set(range(32)) - used)
            add(temp, old, material, "own-temporary")
            own.add(temp)
        for slot in (0, 1):
            if slot not in own:
                if slot in used:
                    kill(slot)
                add(slot, material, material, "own-slot")
                own.add(slot)
        for slot in sorted(own - {0, 1}):
            kill(slot)
        for slot in sorted(old_only - ({kept} if kept is not None else set())):
            if slot in used:
                kill(slot)
        used, _ = _dump(partition)
        final_own = {slot for slot in used if _matches(partition, material, slot, "final-own")}
        final_old = {slot for slot in used if _matches(partition, old, slot, "final-old")}
        receipt["ownSlots"] = sorted(final_own)
        if final_own != {0, 1} or (preserve and kept not in final_old) or (not preserve and not same and final_old):
            _refuse("nas-rekey-readback-failed", "final-readback")
        runtime._record(receipt, "final-readback", True, ownSlots=sorted(final_own), keptSlot=kept)
        receipt.update(ok=True, firstMissingSignal="none")
    except runtime.Refusal as failure:
        signal = _translate(failure.signal_name, writing)
        receipt.update(ok=False, firstMissingSignal=signal, failedStep=failure.step,
                       returnCode=failure.return_code)
        runtime._record(receipt, failure.step, False, signal=signal)
    finally:
        if material is not None and isinstance(material, bytearray):
            wipe_bytes(material)
        if entered and guard is not None:
            guard.__exit__(None, None, None)
    return receipt


def main(argv=None):
    started = time.monotonic()
    request = None
    secret = None
    receipt = _receipt()
    try:
        if argv:
            raise ValueError("arguments refused")
        request = read(known_fields=("key_role", "partition", "keepOld"),
                       secret_bytes=("oldPassword",), max_input_bytes=65536)
        secret = request.secret_bytes.get("oldPassword")
        if request.envelope and not isinstance(request.value.get("payload"), dict):
            raise ValueError("invalid payload")
        receipt = perform(request.payload.get("key_role"), request.payload.get("partition"),
                          secret, request.payload.get("keepOld", False))
    except (EnvelopeError, ValueError, UnicodeError, OSError):
        receipt.update(ok=False, firstMissingSignal="nas-rekey-request-invalid", failedStep="request")
    finally:
        if secret is not None:
            wipe_bytes(secret)
    if receipt["changed"] or not receipt["ok"]:
        try:
            deed.record("nas-rekey", "nas-partition", receipt, started)
        except (OSError, ValueError, runtime.Refusal):
            pass
    if request is not None:
        receipt = attach(receipt, replace(request, secret_fields=(), secret_bytes={}))
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

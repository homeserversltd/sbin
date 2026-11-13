"""Start one detached, guarded block-device test."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from agathodaimon._deed import send
from agathodaimon._nidus.run import run
from agathodaimon._nidus import unit
from agathodaimon.storage.nas import runtime

_MAX_INPUT_BYTES = 64 * 1024
_TEST = "/usr/local/sbin/harddrive_test.sh"
_RESULTS = Path("/var/harddriveTest.txt")
_UNIT = "agathodaimon-disk-test.service"
_ACTIVE = {"activating", "active", "deactivating", "reloading"}
_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._+-]*$")
_TEST_TYPES = {"quick", "full"}


class Refusal(ValueError):
    def __init__(self, signal: str, **details: Any):
        super().__init__(signal)
        self.signal = signal
        self.details = details


def _refuse(signal: str, **details: Any) -> int:
    print(json.dumps({"ok": False, "firstMissingSignal": signal, **details}, separators=(",", ":")))
    return 1


def _request_object() -> dict[str, Any]:
    try:
        stream = getattr(sys.stdin, "buffer", None)
        raw = stream.read(_MAX_INPUT_BYTES + 1) if stream is not None else sys.stdin.read(_MAX_INPUT_BYTES + 1)
    except (OSError, UnicodeError) as error:
        raise Refusal("disk-test-request-invalid") from error
    if isinstance(raw, str):
        try:
            raw = raw.encode("utf-8")
        except UnicodeEncodeError as error:
            raise Refusal("disk-test-request-invalid") from error
    if len(raw) > _MAX_INPUT_BYTES:
        raise Refusal("disk-test-request-too-large")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal("disk-test-request-invalid") from error
    if not isinstance(value, dict):
        raise Refusal("disk-test-request-invalid")
    payload = value.get("payload") if "payload" in value else value
    if not isinstance(payload, dict):
        raise Refusal("disk-test-request-invalid")
    return payload


def _device_form(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/") or not _SEGMENT.fullmatch(value[5:]):
        raise Refusal("disk-test-device-invalid")
    return value


def _device_path(value: Any) -> str:
    value = _device_form(value)
    try:
        resolved = Path(value).resolve(strict=True)
        segments = resolved.relative_to(Path("/dev")).parts
        if not segments or any(_SEGMENT.fullmatch(segment) is None for segment in segments):
            raise Refusal("disk-test-device-invalid")
        if not stat.S_ISBLK(resolved.stat().st_mode):
            raise Refusal("disk-test-device-invalid")
    except Refusal:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise Refusal("disk-test-device-invalid") from error
    return value


def _mode(value: Any) -> str:
    if not isinstance(value, str) or value not in _TEST_TYPES:
        raise Refusal("disk-test-test-type-invalid")
    return value


def _holder() -> tuple[str, str]:
    try:
        result = unit.systemctl("show", _UNIT, "--property=ActiveState", "--property=Description")
        fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if result.returncode or not fields.get("ActiveState") or "Description" not in fields:
            raise ValueError("unobservable unit")
        return fields["ActiveState"], fields["Description"]
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise Refusal("disk-test-start-unobservable") from error


def _running(description: str, device: str) -> Refusal:
    parts = description.split()
    running_device, running_mode = (parts[1], parts[2]) if len(parts) == 3 and parts[0] == "disk-test" else (None, None)
    return Refusal("disk-test-already-running", device=device, runningDevice=running_device, runningMode=running_mode)


def _mounted(device: str) -> None:
    try:
        result = run(["lsblk", "-J", "-o", "NAME,PATH,MOUNTPOINTS", device], timeout=30)
        if result.returncode:
            raise ValueError("lsblk failed")
        tree = json.loads(result.stdout)
        nodes = tree["blockdevices"]
        if not isinstance(nodes, list) or len(nodes) != 1:
            raise ValueError("missing device tree")
        mounted = []
        def visit(node: Any) -> None:
            if not isinstance(node, dict) or not isinstance(node.get("name"), str) or not isinstance(node.get("path"), str):
                raise ValueError("invalid node")
            points = node.get("mountpoints")
            if not isinstance(points, list) or any(p is not None and not isinstance(p, str) for p in points):
                raise ValueError("invalid mountpoints")
            for point in points:
                if point:
                    mounted.append({"node": node["path"], "mountpoint": point})
            children = node.get("children", [])
            if not isinstance(children, list):
                raise ValueError("invalid children")
            for child in children:
                visit(child)
        visit(nodes[0])
        if nodes[0]["path"] != device and Path(nodes[0]["path"]).resolve() != Path(device).resolve():
            raise ValueError("wrong device")
    except (OSError, ValueError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        raise Refusal("disk-test-device-unobservable", device=device) from error
    if mounted:
        raise Refusal("disk-test-device-mounted", device=device, mounted=mounted)


def _check_imports(device: str) -> None:
    try:
        result = run(["/usr/bin/systemctl", "list-units", "--type=service", "--state=active",
                      "--no-legend", "--no-pager", "--plain", "homeserver-nas-import-*"], timeout=30)
        if result.returncode:
            raise ValueError("systemctl failed")
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) < 4 or not fields[0].startswith("homeserver-nas-import-") or not fields[0].endswith(".service") or fields[2] != "active":
                raise ValueError("invalid unit census")
            raise Refusal("disk-test-import-running", device=device)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        if isinstance(error, Refusal):
            raise
        raise Refusal("disk-test-command-failed", device=device) from error


def _deed(device: str, started: float, ok: bool, signal: str) -> None:
    recorded = send("sbin", "disk-test", ok, target=Path(device).name, duration_ms=int((time.monotonic() - started) * 1000), signal=signal)
    print("disk-test-deed recorded" if recorded else "disk-test-deed unrecorded", file=sys.stderr)


def _verdict(device: str, mode: str) -> tuple[bool, str]:
    try:
        lines = _RESULTS.read_text(encoding="utf-8").splitlines()
        if f"# Device: {device}" not in lines or "Test Summary" not in lines:
            raise ValueError("missing header or summary")
        summary = lines[lines.index("Test Summary") + 1:]
        required = ["Filesystem Check"] if mode == "quick" else ["Badblocks Test", "Filesystem Check"]
        results = {}
        for line in summary:
            for name in ("Badblocks Test", "Filesystem Check"):
                if line.startswith(name + ":"):
                    if name in results:
                        raise ValueError("duplicate summary")
                    results[name] = line.partition(":")[2].strip()
        if any(name not in results for name in required) or any(value not in {"PASSED", "FAILED"} for value in results.values()):
            raise ValueError("missing summary")
        if "FAILED" in results.values():
            return False, "disk-test-verdict-failed"
        return True, "operation-failed"
    except (OSError, UnicodeError, ValueError):
        return False, "disk-test-verdict-unreadable"


def _worker(device: str, mode: str) -> int:
    started = time.monotonic()
    ok = False
    signal = "operation-failed"
    try:
        _device_form(device)
        _mode(mode)
        if os.geteuid() != 0:
            raise Refusal("disk-test-root-required")
        _device_path(device)
        _mounted(device)
        result = subprocess.run([_TEST, device, mode], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if result.returncode:
            signal = "disk-test-script-failed"
        else:
            ok, signal = _verdict(device, mode)
    except Refusal as error:
        signal = error.signal
    except OSError:
        signal = "disk-test-script-failed"
    _deed(device, started, ok, signal)
    return 0 if ok else 1


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args:
        if len(args) == 3 and args[0] == "--worker":
            return _worker(args[1], args[2])
        return _refuse("disk-test-request-invalid")
    started = time.monotonic()
    device = None
    try:
        payload = _request_object()
        if "device" not in payload or "test_type" not in payload:
            raise Refusal("disk-test-request-invalid")
        device = _device_form(payload["device"])
        mode = _mode(payload["test_type"])
        if os.geteuid() != 0:
            raise Refusal("disk-test-root-required", device=device)
        _device_path(device)
        with runtime.drive_guard():
            state, description = _holder()
            if state in _ACTIVE:
                raise _running(description, device)
            _check_imports(device)
            _mounted(device)
            try:
                result = run(["/usr/bin/systemd-run", "--unit=agathodaimon-disk-test", "--collect", f"--description=disk-test {device} {mode}", "--property=Type=exec", "--working-directory=/usr/local/sbin", "--", sys.executable, "-m", "agathodaimon.storage.disk.test.index", "--worker", device, mode], timeout=30)
            except (OSError, subprocess.SubprocessError):
                result = None
            if result is None or result.returncode:
                try:
                    state, description = _holder()
                    if state in _ACTIVE and description.split()[:2] == ["disk-test", device]:
                        raise _running(description, device)
                except Refusal as error:
                    if error.signal == "disk-test-already-running":
                        raise
                _deed(device, started, False, "disk-test-start-refused")
                raise Refusal("disk-test-start-refused", device=device)
            state, description = _holder()
            if state != "active":
                raise Refusal("disk-test-start-unobservable", device=device)
        print(json.dumps({"ok": True, "started": True, "unit": _UNIT, "device": device, "mode": mode, "firstMissingSignal": "none"}, separators=(",", ":")))
        return 0
    except runtime.Refusal as error:
        if error.signal_name == "agathodaimon-nas-drive-operation-running":
            signal = "disk-test-drive-operation-running"
        elif error.signal_name.startswith("agathodaimon-nas-command-"):
            signal = "disk-test-command-failed"
        else:
            signal = "disk-test-guard-unavailable"
        return _refuse(signal, device=device)
    except Refusal as error:
        details = dict(error.details)
        if device is not None:
            details.setdefault("device", device)
        return _refuse(error.signal, **details)


if __name__ == "__main__":
    raise SystemExit(main())

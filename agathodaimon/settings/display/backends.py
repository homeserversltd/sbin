"""Owner-process backend selection and bounded Sway IPC operations."""
from __future__ import annotations

import json
import os
import pwd
import selectors
import stat
import subprocess
import time
from decimal import Decimal, ROUND_HALF_UP
from fractions import Fraction
from pathlib import Path
from typing import Any, Collection, Mapping, Sequence

from agathodaimon.settings.display import policy

OWNER = "owner"
MAX_PROC_SCAN = 16384
MAX_ENV_BYTES = 64 * 1024
MAX_RUNTIME_ENTRIES = 128
MAX_COMMAND_BYTES = 256 * 1024
COMMAND_TIMEOUT = 3.0


def _owner_uid() -> int:
    return pwd.getpwnam(OWNER).pw_uid


def _owner_processes(name: str | Collection[str]) -> list[int] | None:
    names = {name} if isinstance(name, str) else set(name)
    try:
        uid = _owner_uid()
        found: list[int] = []
        with os.scandir("/proc") as proc:
            for index, entry in enumerate(proc):
                if index >= MAX_PROC_SCAN:
                    return None
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)
                try:
                    if os.stat(entry.path).st_uid != uid:
                        continue
                    with open(f"/proc/{pid}/comm", "rb") as stream:
                        command = stream.read(128).decode("utf-8", "replace").strip()
                except (OSError, ValueError):
                    continue
                if command in names:
                    found.append(pid)
        return sorted(found)
    except (OSError, KeyError):
        return None


def _process_coordinates(pid: int) -> dict[str, str] | None:
    """Read only Sway's IPC/runtime coordinates; never retain or return its environment."""
    wanted = {b"SWAYSOCK", b"XDG_RUNTIME_DIR"}
    try:
        with open(f"/proc/{pid}/environ", "rb") as stream:
            raw = stream.read(MAX_ENV_BYTES + 1)
        if len(raw) > MAX_ENV_BYTES:
            return None
        coordinates: dict[str, str] = {}
        for item in raw.split(b"\0"):
            key, separator, value = item.partition(b"=")
            if separator and key in wanted:
                coordinates[key.decode("ascii")] = value.decode("utf-8")
        return coordinates
    except (OSError, UnicodeDecodeError):
        return None


def _socket_is_owned(socket_path: Path, runtime: Path, uid: int, pid: int) -> bool:
    try:
        if not socket_path.is_absolute() or socket_path.parent != runtime:
            return False
        if any(part in {".", ".."} for part in socket_path.parts):
            return False
        if str(pid) not in socket_path.name.split(".") or str(uid) not in socket_path.name.split("."):
            return False
        metadata = socket_path.lstat()
        return stat.S_ISSOCK(metadata.st_mode) and metadata.st_uid == uid
    except OSError:
        return False


def _sway_socket_for(pid: int, uid: int) -> str | None:
    runtime = Path(f"/run/user/{uid}")
    try:
        runtime_info = runtime.lstat()
        if not stat.S_ISDIR(runtime_info.st_mode) or runtime_info.st_uid != uid:
            return None
    except OSError:
        return None
    coordinates = _process_coordinates(pid) or {}
    if coordinates.get("XDG_RUNTIME_DIR") not in {None, str(runtime)}:
        return None
    advertised = coordinates.get("SWAYSOCK")
    if advertised:
        candidate = Path(advertised)
        if _socket_is_owned(candidate, runtime, uid, pid):
            return str(candidate)
    matches: list[Path] = []
    try:
        with os.scandir(runtime) as entries:
            for index, entry in enumerate(entries):
                if index >= MAX_RUNTIME_ENTRIES:
                    break
                if "sway-ipc" not in entry.name or str(pid) not in entry.name.split("."):
                    continue
                candidate = Path(entry.path)
                if _socket_is_owned(candidate, runtime, uid, pid):
                    matches.append(candidate)
    except OSError:
        return None
    return str(matches[0]) if len(matches) == 1 else None








def _parse_json_list(result: Mapping[str, Any]) -> tuple[list[Any] | None, str | None]:
    if result.get("ok") is not True:
        return None, str(result.get("signal") or "sway-command-failed")
    try:
        value = json.loads(str(result.get("stdout", "")))
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None, "sway-json-invalid"
    if not isinstance(value, list) or len(value) > policy.MAX_CONNECTORS:
        return None, "sway-output-array-invalid"
    return value, None


def _mode_match(left: Mapping[str, Any], right: Mapping[str, Any]) -> bool:
    if left.get("width") != right.get("width") or left.get("height") != right.get("height"):
        return False
    left_rate = policy._rate_fraction(left)
    right_rate = policy._rate_fraction(right)
    if left_rate is None or right_rate is None:
        return False
    return abs(left_rate - right_rate) <= Fraction(1, 2000)


def _merge_kms_modes(sway_connectors: list[dict[str, Any]], kms: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(kms, Mapping) or kms.get("ok") is not True:
        return sway_connectors
    kms_connectors = kms.get("connectors")
    if not isinstance(kms_connectors, list):
        return sway_connectors
    by_name = {
        str(connector.get("connector_name")): connector
        for connector in kms_connectors if isinstance(connector, dict)
    }
    for connector in sway_connectors:
        kms_connector = by_name.get(str(connector.get("connector_name")))
        if not isinstance(kms_connector, dict):
            continue
        connector["device"] = kms_connector.get("device")
        connector["connector_id"] = kms_connector.get("connector_id")
        connector["kms_current_mode"] = kms_connector.get("current_mode")
        kms_modes_value = kms_connector.get("modes")
        kms_modes = kms_modes_value if isinstance(kms_modes_value, list) else []
        sway_modes_value = connector.get("modes")
        sway_modes = sway_modes_value if isinstance(sway_modes_value, list) else []
        for mode in sway_modes:
            if not isinstance(mode, dict):
                continue
            match = next((candidate for candidate in kms_modes
                          if isinstance(candidate, dict) and _mode_match(mode, candidate)), None)
            if match is not None:
                mode["interlaced"] = match.get("interlaced")
                mode["preferred"] = match.get("preferred")
                mode["kms_current"] = match.get("current")
    return sway_connectors






def _refresh_hz_text(rate: Fraction) -> str:
    value = (Decimal(rate.numerator) / Decimal(rate.denominator)).quantize(
        Decimal("0.001"), rounding=ROUND_HALF_UP)
    return format(value, "f").rstrip("0").rstrip(".")


def _expected_millihz(mode: Mapping[str, Any]) -> int | None:
    raw = mode.get("refresh_millihz")
    if isinstance(raw, int) and not isinstance(raw, bool) and raw > 0:
        return raw
    rate = policy._rate_fraction(mode)
    if rate is None:
        return None
    scaled = rate * 1000
    return int(scaled + Fraction(1, 2))


def _find_live_output(connectors: Sequence[Mapping[str, Any]], name: str) -> Mapping[str, Any] | None:
    return next((connector for connector in connectors
                 if connector.get("connector_name") == name and connector.get("connected") is True), None)


def apply_sway_mode(socket_path: str, connector: Mapping[str, Any], mode: Mapping[str, Any],
                    kms: Mapping[str, Any] | None = None) -> dict[str, Any]:
    name = connector.get("connector_name") or connector.get("name")
    width, height = mode.get("width"), mode.get("height")
    rate = policy._rate_fraction(mode)
    if (not isinstance(name, str) or not isinstance(width, int) or isinstance(width, bool)
            or not isinstance(height, int) or isinstance(height, bool) or rate is None):
        return {"ok": False, "mutation_performed": False, "signal": "resolved-sway-mode-invalid"}
    command = f"output {_escape_sway_name(name)} mode {width}x{height}@{_refresh_hz_text(rate)}Hz"
    argv, runtime, _uid = _sway_argv(socket_path, [command])
    applied = _bounded_command(argv, runtime=runtime, socket_path=socket_path)
    command_responses: Any = None
    if applied.get("ok") is True:
        try:
            command_responses = json.loads(str(applied.get("stdout", "")))
        except (json.JSONDecodeError, TypeError, ValueError):
            command_responses = None
    command_ok = (
        applied.get("ok") is True and isinstance(command_responses, list)
        and bool(command_responses)
        and all(isinstance(item, dict) and item.get("success") is True for item in command_responses)
    )
    command_receipt: dict[str, Any] = {
        "argv": argv, "ok": command_ok,
        "returncode": applied.get("returncode"),
        "signal": applied.get("signal") if not command_ok else None,
    }
    if not command_ok:
        return {"ok": False, "mutation_performed": applied.get("returncode") is not None,
                "signal": str(applied.get("signal") or "sway-command-refused"),
                "command": command_receipt, "current_mode": None,
                "physical_mode_verified": False}
    after = observe_sway(socket_path, kms)
    if after.get("ok") is not True:
        return {"ok": False, "mutation_performed": True,
                "signal": str(after.get("signal") or "sway-readback-failed"),
                "command": command_receipt, "current_mode": None,
                "physical_mode_verified": False}
    live = _find_live_output(after.get("connectors", []), str(name))
    current = live.get("current_mode") if isinstance(live, Mapping) else None
    expected_millihz = _expected_millihz(mode)
    same = (
        isinstance(current, dict)
        and current.get("width") == width and current.get("height") == height
        and isinstance(current.get("refresh"), int) and not isinstance(current.get("refresh"), bool)
        and expected_millihz is not None
        and abs(int(current["refresh"]) - expected_millihz) <= 1
    )
    return {
        "ok": bool(same), "mutation_performed": True,
        "signal": None if same else "sway-mode-readback-mismatch",
        "command": command_receipt,
        "current_mode": dict(current) if isinstance(current, dict) else None,
        "expected_millihz": expected_millihz,
        "physical_mode_verified": bool(same),
        "connectors": after.get("connectors", []),
    }

from agathodaimon.settings._sway import (select_backend, _sway_argv, _bounded_command,
                                        observe_sway, _escape_sway_name)

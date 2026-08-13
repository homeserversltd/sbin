"""Caduceus household-time resolver and local clock actuators.

The resolver deliberately discards the public address returned by its provider:
only a validated timezone and provenance cross the state membrane.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Sequence
from urllib.request import Request, urlopen

SCHEMA = "caduceus.household-time.state.v1"
RECEIPT_SCHEMA = "caduceus.household-time.receipt.v1"
PROVIDER = "ip-api.com"
PROVIDER_URL = "http://ip-api.com/json/"
DEFAULT_TTL_SECONDS = 24 * 60 * 60
DEFAULT_HOLD_SECONDS = 24 * 60 * 60
MAX_HOLD_SECONDS = 7 * 24 * 60 * 60
ZONEINFO_ROOT = "/usr/share/zoneinfo"
ZONE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._+-]*(?:/[A-Za-z0-9._+-]+)+$")


def _root() -> Path:
    return Path(os.environ.get("CADUCEUS_ROOT", "/"))


def state_path() -> Path:
    override = os.environ.get("CADUCEUS_HOUSEHOLD_TIME_STATE_PATH")
    if override:
        return Path(override)
    return _root() / "var/lib/caduceus/household-time/state.json"


def zoneinfo_root() -> Path:
    override = os.environ.get("CADUCEUS_ZONEINFO_ROOT")
    if override:
        return Path(override)
    return _root() / ZONEINFO_ROOT.lstrip("/")


def now() -> datetime:
    return datetime.now(UTC)


def stamp(value: datetime | None = None) -> str:
    return (value or now()).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_stamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def validated_timezone(value: Any) -> str:
    if not isinstance(value, str) or not ZONE_RE.fullmatch(value):
        raise ValueError("caduceus-household-time-timezone-invalid")
    candidate = (zoneinfo_root() / value).resolve()
    try:
        candidate.relative_to(zoneinfo_root().resolve())
    except ValueError as exc:
        raise ValueError("caduceus-household-time-timezone-invalid") from exc
    if not candidate.is_file():
        raise ValueError("caduceus-household-time-timezone-not-installed")
    return value


def read_state() -> dict[str, Any]:
    path = state_path()
    if not path.is_file():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("caduceus-household-time-state-invalid") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise ValueError("caduceus-household-time-state-invalid")
    return value


def atomic_write(value: dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".household-time.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _base_state(previous: dict[str, Any]) -> dict[str, Any]:
    value = {
        "schema_version": 1,
        "timezone": previous.get("timezone"),
        "observed_at": previous.get("observed_at"),
        "valid_until": previous.get("valid_until"),
        "provider": previous.get("provider"),
        "validation_status": previous.get("validation_status"),
    }
    for key in ("applied_timezone", "pending_timezone", "pending_observed_at"):
        if key in previous:
            value[key] = previous[key]
    return value


def sanitized_state() -> dict[str, Any]:
    value = read_state()
    allowed = {
        "schema_version", "timezone", "observed_at", "valid_until", "provider",
        "validation_status", "applied_timezone", "pending_timezone", "pending_observed_at",
    }
    return {key: value[key] for key in sorted(value) if key in allowed}


def resolve() -> dict[str, Any]:
    previous = read_state()
    request = Request(
        os.environ.get("CADUCEUS_TIME_GEOIP_URL", PROVIDER_URL),
        headers={"Accept": "application/json", "User-Agent": "caduceus-household-time/1"},
    )
    try:
        with urlopen(request, timeout=8) as response:  # nosec B310: fixed provider has no free HTTPS endpoint
            payload = json.loads(response.read().decode("utf-8"))
        timezone = validated_timezone(payload.get("timezone"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        # Preserve last-known-good state exactly.  The public IP is neither stored nor returned.
        return receipt(
            "resolve", ok=False, changed=False,
            first_missing_signal="caduceus-household-time-provider-unavailable",
            detail=str(exc), state=sanitized_state() if previous else {},
        )
    observed = now()
    value = _base_state(previous)
    value.update({
        "timezone": timezone,
        "observed_at": stamp(observed),
        "valid_until": stamp(observed + timedelta(seconds=DEFAULT_TTL_SECONDS)),
        "provider": PROVIDER,
        "validation_status": "installed-iana-zone",
    })
    atomic_write(value)
    return receipt("resolve", ok=True, changed=value != previous, state=sanitized_state())


def _hold_seconds() -> int:
    raw = os.environ.get("CADUCEUS_TIMEZONE_HOLD_SECONDS")
    if raw is None:
        return DEFAULT_HOLD_SECONDS
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("caduceus-household-time-hold-invalid") from exc
    if not 60 <= value <= MAX_HOLD_SECONDS:
        raise ValueError("caduceus-household-time-hold-invalid")
    return value


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def timedatectl() -> str:
    return os.environ.get("CADUCEUS_TIMEDATECTL_BIN", "timedatectl")


def systemctl() -> str:
    return os.environ.get("CADUCEUS_SYSTEMCTL_BIN", "systemctl")


def timedatectl_readback() -> dict[str, Any]:
    result = _run([timedatectl(), "show", "--property=NTPSynchronized,NTP,Timezone"])
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    status = _run([timedatectl(), "status"])
    for line in status.stdout.splitlines():
        if ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if key == "System clock synchronized" and "NTPSynchronized" not in values:
            values["NTPSynchronized"] = value
        elif key == "NTP service" and "NTP" not in values:
            values["NTP"] = value
        elif key == "Time zone" and "Timezone" not in values:
            values["Timezone"] = value.split(" ", 1)[0]
    return {
        "command": [timedatectl(), "show", "--property=NTPSynchronized,NTP,Timezone"],
        "show_exit": result.returncode,
        "show_stdout": result.stdout.strip(),
        "show_stderr": result.stderr.strip(),
        "status_exit": status.returncode,
        "values": values,
    }


def _truth(value: str | None) -> bool:
    return (value or "").strip().lower() in {"yes", "true", "1", "active"}


def ensure_ntp() -> dict[str, Any]:
    providers = [
        ("systemd-timesyncd", "systemd-timesyncd.service"),
        ("chrony", "chronyd.service"),
        ("ntpd", "ntpd.service"),
    ]
    candidates: list[tuple[str, str, bool]] = []
    for name, unit in providers:
        listed = _run([systemctl(), "list-unit-files", unit, "--no-legend", "--no-pager"])
        present = any(line.split(maxsplit=1)[0] == unit for line in listed.stdout.splitlines() if line.split())
        candidates.append((name, unit, present))
    selected = next((item for item in candidates if item[2]), None)
    if selected is None:
        return receipt("ensure-ntp", ok=False, changed=False,
                       first_missing_signal="caduceus-household-time-ntp-provider-missing", providers=[name for name, _, _ in candidates])
    provider, unit, _ = selected
    enable = _run([systemctl(), "enable", "--now", unit])
    readback = timedatectl_readback()
    synchronized = _truth(readback["values"].get("NTPSynchronized"))
    return receipt(
        "ensure-ntp", ok=synchronized, changed=enable.returncode == 0,
        provider=provider, unit=unit, enable_exit=enable.returncode,
        post_apply=readback, first_missing_signal="none" if synchronized else "caduceus-household-time-ntp-not-synchronized",
    )


def set_timezone(candidate: str) -> dict[str, Any]:
    requested = validated_timezone(candidate)
    state = read_state()
    previous = state.get("applied_timezone")
    if previous is not None:
        previous = validated_timezone(previous)
    if previous == requested:
        return receipt("set-timezone", ok=True, changed=False, requested_timezone=requested,
                       previously_applied_timezone=previous, applied_timezone=previous,
                       debounce_gated=False, post_apply=timedatectl_readback())
    hold = _hold_seconds()
    observed = now()
    first_application = previous is None
    pending = state.get("pending_timezone")
    pending_at = parse_stamp(state.get("pending_observed_at"))
    gated = not first_application and (pending != requested or pending_at is None or (observed - pending_at).total_seconds() < hold)
    if gated:
        if pending != requested or pending_at is None:
            state["pending_timezone"] = requested
            state["pending_observed_at"] = stamp(observed)
            atomic_write(_base_state(state))
        return receipt("set-timezone", ok=True, changed=False, requested_timezone=requested,
                       previously_applied_timezone=previous, applied_timezone=previous,
                       debounce_gated=True, hold_seconds=hold, post_apply=timedatectl_readback())
    result = _run([timedatectl(), "set-timezone", requested])
    post_apply = timedatectl_readback()
    applied = post_apply["values"].get("Timezone")
    if result.returncode != 0 or applied != requested:
        return receipt("set-timezone", ok=False, changed=False, requested_timezone=requested,
                       previously_applied_timezone=previous, applied_timezone=previous,
                       debounce_gated=False, post_apply=post_apply,
                       first_missing_signal="caduceus-household-time-timezone-readback-failed")
    state["applied_timezone"] = requested
    state.pop("pending_timezone", None)
    state.pop("pending_observed_at", None)
    atomic_write(_base_state(state))
    return receipt("set-timezone", ok=True, changed=True, requested_timezone=requested,
                   previously_applied_timezone=previous, applied_timezone=requested,
                   debounce_gated=False, post_apply=post_apply)


def receipt(primitive: str, *, ok: bool, changed: bool, first_missing_signal: str = "none", **fields: Any) -> dict[str, Any]:
    return {"schema": RECEIPT_SCHEMA, "primitive": primitive, "ok": ok, "changed": changed,
            "firstMissingSignal": first_missing_signal, **fields}


def _emit(call) -> int:
    try:
        value = call()
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        value = receipt("invalid", ok=False, changed=False, first_missing_signal=str(error))
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-household-time")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("resolve")
    sub.add_parser("state")
    sub.add_parser("ensure-ntp")
    timezone = sub.add_parser("set-timezone")
    timezone.add_argument("timezone")
    args = parser.parse_args(argv)
    if args.command == "resolve":
        return _emit(resolve)
    if args.command == "state":
        return _emit(lambda: receipt("state", ok=True, changed=False, state=sanitized_state()))
    if args.command == "ensure-ntp":
        return _emit(ensure_ntp)
    return _emit(lambda: set_timezone(args.timezone))


if __name__ == "__main__":
    raise SystemExit(main())

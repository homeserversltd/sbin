"""Read-only Samba service status for Caduceus staff."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Sequence

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon._nidus.run import run as nidus_run

SYSTEMCTL = "/usr/bin/systemctl"
UNITS = (("smbd", "smbd.service"), ("nmbd", "nmbd.service"))
LOAD_STATES = {"loaded", "masked", "merged", "stub"}
ACTIVE_STATES = {
    "active", "inactive", "failed", "activating", "deactivating",
    "reloading", "maintenance", "refreshing",
}
ENABLED_STATES = {
    "enabled", "enabled-runtime", "linked", "linked-runtime", "alias",
    "masked", "masked-runtime", "static", "indirect", "disabled",
    "generated", "transient",
}


class ObservationFailure(RuntimeError):
    def __init__(self, signal: str) -> None:
        super().__init__(signal)
        self.signal = signal


def _run(command: list[str], launch_signal: str) -> subprocess.CompletedProcess[str]:
    try:
        return nidus_run(command, timeout=None, encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ObservationFailure(launch_signal) from exc


def _single_value(output: str, accepted: set[str], signal: str) -> str:
    values = [line.strip() for line in output.splitlines() if line.strip()]
    if len(values) != 1 or values[0] not in accepted:
        raise ObservationFailure(signal)
    return values[0]


def _load_state(name: str, unit: str) -> str:
    load_result = _run(
        [SYSTEMCTL, "show", "--property=LoadState", "--value", unit],
        f"agathodaimon-settings-samba-{name}-load-state-launch-failed",
    )
    if load_result.returncode != 0:
        raise ObservationFailure(
            f"agathodaimon-settings-samba-{name}-load-state-command-failed"
        )
    return _single_value(
        load_result.stdout,
        LOAD_STATES | {"not-found"},
        f"agathodaimon-settings-samba-{name}-load-state-unusable",
    )


def _unit_status(name: str, unit: str) -> dict[str, Any]:
    if _load_state(name, unit) == "not-found":
        # Only an explicit LoadState=not-found proves the fixed unit absent.
        return {
            "unit": unit,
            "active": False,
            "activeState": "inactive",
            "enabled": False,
            "enabledState": "unknown",
        }

    active_result = _run(
        [SYSTEMCTL, "is-active", unit],
        f"agathodaimon-settings-samba-{name}-active-state-launch-failed",
    )
    active_state = _single_value(
        active_result.stdout,
        ACTIVE_STATES,
        f"agathodaimon-settings-samba-{name}-active-state-unusable",
    )
    enabled_result = _run(
        [SYSTEMCTL, "is-enabled", unit],
        f"agathodaimon-settings-samba-{name}-enabled-state-launch-failed",
    )
    enabled_state = _single_value(
        enabled_result.stdout,
        ENABLED_STATES,
        f"agathodaimon-settings-samba-{name}-enabled-state-unusable",
    )
    return {
        "unit": unit,
        "active": active_state == "active",
        "activeState": active_state,
        "enabled": enabled_state == "enabled",
        "enabledState": enabled_state,
    }


def _receipt(*, ok: bool, signal: str, readback: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "ok": ok,
        "state": "status",
        "firstMissingSignal": signal,
        "readback": readback,
    }


def status() -> dict[str, Any]:
    try:
        services = {name: _unit_status(name, unit) for name, unit in UNITS}
    except ObservationFailure as exc:
        return _receipt(ok=False, signal=exc.signal, readback=None)
    return _receipt(
        ok=True,
        signal="none",
        readback={"services": services, "running": services["smbd"]["active"]},
    )

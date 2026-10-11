"""Read-only Samba service status for Caduceus staff."""
from __future__ import annotations

import json
import subprocess
import sys
from typing import Any, Sequence

from agathodaimon._envelope import EnvelopeError, attach, read

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
STATUS_VERBS = {"status", "read", "get"}


class ObservationFailure(RuntimeError):
    def __init__(self, signal: str) -> None:
        super().__init__(signal)
        self.signal = signal


def _run(command: list[str], launch_signal: str) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        raise ObservationFailure(launch_signal) from exc


def _single_value(output: str, accepted: set[str], signal: str) -> str:
    values = [line.strip() for line in output.splitlines() if line.strip()]
    if len(values) != 1 or values[0] not in accepted:
        raise ObservationFailure(signal)
    return values[0]


def _unit_status(name: str, unit: str) -> dict[str, Any]:
    load_result = _run(
        [SYSTEMCTL, "show", "--property=LoadState", "--value", unit],
        f"agathodaimon-settings-samba-{name}-load-state-launch-failed",
    )
    if load_result.returncode != 0:
        raise ObservationFailure(
            f"agathodaimon-settings-samba-{name}-load-state-command-failed"
        )
    load_state = _single_value(
        load_result.stdout,
        LOAD_STATES | {"not-found"},
        f"agathodaimon-settings-samba-{name}-load-state-unusable",
    )
    if load_state == "not-found":
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


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments != ["status"]:
        receipt = _receipt(
            ok=False,
            signal="agathodaimon-settings-samba-unsupported-operation",
            readback=None,
        )
        print(json.dumps(receipt, sort_keys=True))
        return 1

    try:
        request = read(known_fields=("state", "action", "operation"))
    except EnvelopeError:
        receipt = _receipt(
            ok=False,
            signal="agathodaimon-settings-samba-envelope-read-failed",
            readback=None,
        )
        print(json.dumps(receipt, sort_keys=True))
        return 1

    if (
        any(
            field in request.payload
            and request.payload[field] is not None
            and request.payload[field] != "status"
            for field in ("state", "action", "operation")
        )
        or (request.envelope and request.verb not in STATUS_VERBS | {"samba"})
    ):
        receipt = _receipt(
            ok=False,
            signal="agathodaimon-settings-samba-unsupported-operation",
            readback=None,
        )
    else:
        receipt = status()
    receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

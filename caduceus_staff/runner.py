from __future__ import annotations

import os
import subprocess
import sys
from typing import Sequence

from .actuators import Actuator
from .receipts import emit, path_state


def status(actuator: Actuator) -> int:
    legacy = path_state(str(actuator.legacy_path))
    return emit({
        "schema": actuator.receipt_schema,
        "action": "status",
        "actuator": actuator.id,
        "family": actuator.family,
        "launcher": actuator.launcher,
        "legacy": legacy,
        "mode": "additive-python-membrane",
        "ok": legacy["exists"],
        "firstMissingSignal": "none" if legacy["exists"] else "legacy-script-missing",
    })


def plan(actuator: Actuator, forwarded: Sequence[str]) -> int:
    args = list(forwarded) or list(actuator.default_args)
    return emit({
        "schema": actuator.receipt_schema,
        "action": "plan",
        "actuator": actuator.id,
        "legacyScript": str(actuator.legacy_path),
        "argv": args,
        "wouldExecute": [str(actuator.legacy_path), *args],
        "mutationPerformed": False,
        "ok": actuator.legacy_path.exists(),
        "firstMissingSignal": "none" if actuator.legacy_path.exists() else "legacy-script-missing",
    })


def apply_legacy_bridge(actuator: Actuator, forwarded: Sequence[str]) -> int:
    if not actuator.legacy_path.exists():
        return emit({
            "schema": actuator.receipt_schema,
            "action": "apply",
            "actuator": actuator.id,
            "ok": False,
            "firstMissingSignal": "legacy-script-missing",
        })
    args = list(forwarded) or list(actuator.default_args)
    cmd = [str(actuator.legacy_path), *args]
    if actuator.legacy_path.suffix == ".py":
        cmd = [sys.executable, str(actuator.legacy_path), *args]
    os.execvpe(cmd[0], cmd, os.environ.copy())
    return 127


def run(actuator: Actuator, forwarded: Sequence[str], *, apply: bool, legacy_bridge: bool) -> int:
    if not apply:
        return plan(actuator, forwarded)
    if not legacy_bridge:
        return emit({
            "schema": actuator.receipt_schema,
            "action": "apply",
            "actuator": actuator.id,
            "ok": False,
            "mutationPerformed": False,
            "firstMissingSignal": "legacy-bridge-confirmation-required",
            "message": "Pass --legacy-bridge with --apply to execute the preserved legacy script through this additive membrane.",
        })
    return apply_legacy_bridge(actuator, forwarded)

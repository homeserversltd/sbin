"""Ordered, reload-only service convergence for Caduceus staff actuators."""
from __future__ import annotations

import hashlib
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

SCHEMA = "caduceus.staff.reload.v1"
SystemctlRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class FingerprintGate:
    """Reload a service only when its watched material differs from saved state."""

    paths: Sequence[Path]
    state_path: Path


def _fingerprint(paths: Sequence[Path]) -> str:
    material: list[str] = []
    for path in paths:
        if path.is_symlink():
            material.append(f"link {path} {os.readlink(path)}")
        elif path.is_file():
            material.append(f"file {path} {hashlib.sha256(path.read_bytes()).hexdigest()}")
        else:
            material.append(f"absent {path}")
    return hashlib.sha256(("\n".join(material) + "\n").encode()).hexdigest()


def _systemctl(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def reload_services(
    services: Sequence[str],
    *,
    dry_run: bool = False,
    fingerprint_gates: Mapping[str, FingerprintGate] | None = None,
    command_runner: SystemctlRunner | None = None,
) -> dict:
    """Reload services in caller order and return the shared staff receipt."""
    gates = fingerprint_gates or {}
    runner = command_runner or _systemctl
    entries: list[dict] = []
    first_missing_signal = "none"

    for service in services:
        if not isinstance(service, str) or not service:
            entry = {"service": service, "changed": False, "reload_outcome": "failed"}
            entries.append(entry)
            if first_missing_signal == "none":
                first_missing_signal = "reload-service-invalid"
            continue

        gate = gates.get(service)
        changed = True
        fingerprint: str | None = None
        if gate is not None:
            try:
                fingerprint = _fingerprint(gate.paths)
                prior = gate.state_path.read_text(encoding="utf-8").strip() if gate.state_path.is_file() else ""
                changed = fingerprint != prior
            except OSError as exc:
                entries.append({"service": service, "changed": False, "reload_outcome": "failed"})
                if first_missing_signal == "none":
                    first_missing_signal = f"reload-fingerprint-failed:{service}:{exc}"
                continue

        entry = {"service": service, "changed": changed, "reload_outcome": "not-needed"}
        if dry_run:
            entry["planned"] = changed
            entries.append(entry)
            continue
        if not changed:
            entries.append(entry)
            continue

        command = [os.environ.get("CADUCEUS_SYSTEMCTL_BIN", "systemctl"), "reload", service]
        try:
            completed = runner(command)
        except (OSError, subprocess.SubprocessError) as exc:
            entry["reload_outcome"] = "failed"
            entries.append(entry)
            if first_missing_signal == "none":
                first_missing_signal = f"reload-command-failed:{service}:{exc}"
            continue
        if completed.returncode != 0:
            entry["reload_outcome"] = "failed"
            entries.append(entry)
            detail = (completed.stderr or completed.stdout).strip() or f"exit {completed.returncode}"
            if first_missing_signal == "none":
                first_missing_signal = f"reload-command-failed:{service}:{detail}"
            continue
        if gate is not None and fingerprint is not None:
            try:
                gate.state_path.parent.mkdir(parents=True, exist_ok=True)
                gate.state_path.write_text(fingerprint + "\n", encoding="utf-8")
            except OSError as exc:
                entry["reload_outcome"] = "failed"
                entries.append(entry)
                if first_missing_signal == "none":
                    first_missing_signal = f"reload-fingerprint-state-failed:{service}:{exc}"
                continue
        entry["reload_outcome"] = "reloaded"
        entries.append(entry)

    return {
        "schema": SCHEMA,
        "ok": first_missing_signal == "none",
        "services": entries,
        "firstMissingSignal": first_missing_signal,
    }

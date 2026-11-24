"""Shared appliance runtime path resolver."""
from __future__ import annotations

import os
from pathlib import Path

_PRODUCTION_ROOT = Path("/")
_RUNTIME_PATHS = {
    "config": (Path("/etc/appliance/config.json"), ("etc", "appliance", "config.json")),
    "factory": (Path("/etc/appliance/config.factory"), ("etc", "appliance", "config.factory")),
    "identity-lock": (Path("/var/lib/caduceus/network-identity-claim.lock"), ("var", "lib", "caduceus", "network-identity-claim.lock")),
    "profile": (Path("/etc/appliance/profile.json"), ("etc", "appliance", "profile.json")),
    "seats": (Path("/opt/caduceus/source/schema"), ("opt", "caduceus", "source", "schema")),
    "model-engine": (Path("/usr/local/bin/llama-server"), ("usr", "local", "bin", "llama-server")),
    "skeleton": (Path("/root/key/skeleton.key"), ("root", "key", "skeleton.key")),
}


def _has_dot_segments(raw: str) -> bool:
    return any(part in (".", "..") for part in raw.split("/"))


def runtime_root() -> Path:
    """Return the one absolute appliance root, or refuse an invalid selection."""
    primary = os.environ.get("CADUCEUS_ROOT")
    legacy = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    if primary is not None:
        if not primary.startswith("/") or "\x00" in primary or _has_dot_segments(primary):
            raise ValueError("invalid CADUCEUS_ROOT")
        # Linux treats repeated leading slashes as a single root separator.
        root = _PRODUCTION_ROOT / primary.lstrip("/")
        if legacy is not None and (
            not legacy.startswith("/")
            or _has_dot_segments(legacy)
            or _PRODUCTION_ROOT / legacy.lstrip("/") != root
        ):
            raise ValueError("conflicting CADUCEUS_ROOT and AGATHODAIMON_SCRATCH_ROOT")
        return root
    if legacy is None:
        return _PRODUCTION_ROOT
    root = Path(legacy)
    if not root.is_absolute() or root == _PRODUCTION_ROOT or _has_dot_segments(legacy):
        raise ValueError("invalid AGATHODAIMON_SCRATCH_ROOT")
    return root


def appliance_runtime_path(coordinate: str) -> Path:
    """Return one production path or its isolated absolute fake-root coordinate."""
    if coordinate not in _RUNTIME_PATHS:
        raise ValueError("unknown appliance runtime coordinate")
    production, relative = _RUNTIME_PATHS[coordinate]
    root = runtime_root()
    if root == _PRODUCTION_ROOT:
        return production
    return root.joinpath(*relative)


def _bridge_legacy_scratch_root() -> None:
    primary = os.environ.get("CADUCEUS_ROOT")
    if primary is None or "AGATHODAIMON_SCRATCH_ROOT" in os.environ:
        return
    try:
        root = runtime_root()
    except ValueError:
        # Let the front door report invalid roots through its seat-read refusal.
        return
    if root != _PRODUCTION_ROOT:
        os.environ["AGATHODAIMON_SCRATCH_ROOT"] = primary


# Remove this import-time bridge when the last old-variable reader has moved.
_bridge_legacy_scratch_root()

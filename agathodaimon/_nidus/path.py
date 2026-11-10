"""Shared appliance runtime path resolver."""
from __future__ import annotations

import os
from pathlib import Path

_RUNTIME_PATHS = {
    "config": (Path("/etc/appliance/config.json"), ("etc", "appliance", "config.json")),
    "factory": (Path("/etc/appliance/config.factory"), ("etc", "appliance", "config.factory")),
    "profile": (Path("/etc/appliance/profile.json"), ("etc", "appliance", "profile.json")),
    "seats": (Path("/opt/caduceus/source/schema"), ("opt", "caduceus", "source", "schema")),
    "skeleton": (Path("/root/key/skeleton.key"), ("root", "key", "skeleton.key")),
}


def appliance_runtime_path(coordinate: str) -> Path:
    """Return one production path or its isolated absolute fake-root coordinate."""
    if coordinate not in _RUNTIME_PATHS:
        raise ValueError("unknown appliance runtime coordinate")
    production, relative = _RUNTIME_PATHS[coordinate]
    scratch = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    if scratch is None:
        return production
    root = Path(scratch)
    if (
        not root.is_absolute()
        or root == Path("/")
        or any(part in {".", ".."} for part in scratch.split("/") if part)
    ):
        raise ValueError("invalid AGATHODAIMON_SCRATCH_ROOT")
    return root.joinpath(*relative)

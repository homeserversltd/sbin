"""Shared systemctl command construction and service verbs."""
from __future__ import annotations

import os
import subprocess
from typing import Callable, Sequence

from agathodaimon._nidus.run import run

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def systemctl(*args: str, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    command = [os.environ.get("CADUCEUS_SYSTEMCTL_BIN") or "/usr/bin/systemctl", *args]
    return runner(command) if runner is not None else run(command, timeout=None)


def restart(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("restart", unit, runner=runner)


def reload(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("reload", unit, runner=runner)


def is_active(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("is-active", unit, runner=runner)


def status(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("status", unit, "--no-pager", runner=runner)

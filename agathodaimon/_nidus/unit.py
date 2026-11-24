"""Shared systemctl command construction and service verbs."""
from __future__ import annotations

import os
import subprocess
from typing import Callable, Literal, Sequence, overload

from agathodaimon._nidus.run import run

CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


@overload
def systemctl(
    *args: str, runner: CommandRunner | None = None, text: Literal[True] = True
) -> subprocess.CompletedProcess[str]: ...


@overload
def systemctl(
    *args: str, runner: None = None, text: Literal[False]
) -> subprocess.CompletedProcess[bytes]: ...


@overload
def systemctl(
    *args: str, runner: CommandRunner | None = None, text: bool
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]: ...


def systemctl(
    *args: str, runner: CommandRunner | None = None, text: bool = True
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Capture text by default; an injected runner supplies its own result."""
    command = [os.environ.get("CADUCEUS_SYSTEMCTL_BIN") or "/usr/bin/systemctl", *args]
    if runner is not None:
        return runner(command)
    if not text:
        return subprocess.run(command, capture_output=True, check=False)
    return run(command, timeout=None)


def restart(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("restart", unit, runner=runner)


def reload(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("reload", unit, runner=runner)


def is_active(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("is-active", unit, runner=runner)


def status(unit: str, *, runner: CommandRunner | None = None) -> subprocess.CompletedProcess[str]:
    return systemctl("status", unit, "--no-pager", runner=runner)

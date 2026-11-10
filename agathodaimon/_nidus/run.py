from __future__ import annotations

import subprocess
from typing import Sequence


def run(command: Sequence[str], *, timeout: float | None = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(list(command), capture_output=True, text=True, timeout=timeout, check=False)

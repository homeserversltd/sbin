from __future__ import annotations

import os
import signal
import subprocess
from typing import IO, Mapping, Sequence


def run(
    command: Sequence[str],
    *,
    timeout: float | None = 30,
    input: str | None = None,
    stdin: int | IO[str] | IO[bytes] | None = None,
    env: Mapping[str, str] | Mapping[bytes, bytes] | None = None,
    encoding: str | None = None,
    errors: str | None = None,
    kill_group: bool = False,
) -> subprocess.CompletedProcess[str]:
    """Capture both streams as text; optionally own a fresh process group."""
    argv = list(command)
    if not kill_group:
        return subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
            input=input, stdin=stdin, env=env, encoding=encoding, errors=errors,
        )

    if input is not None:
        if stdin is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        stdin = subprocess.PIPE

    with subprocess.Popen(
        argv, stdin=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=env, encoding=encoding, errors=errors, start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except BaseException:
            # The leader may have exited while a descendant still holds a pipe.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

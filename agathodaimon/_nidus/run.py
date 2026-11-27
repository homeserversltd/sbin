from __future__ import annotations

import os
import signal
import subprocess
from typing import IO, Literal, Mapping, Sequence, overload


@overload
def run(
    command: Sequence[str], *, timeout: float | None = 30,
    input: str | None = None, stdin: int | IO[str] | IO[bytes] | None = None,
    env: Mapping[str, str] | Mapping[bytes, bytes] | None = None,
    encoding: str | None = None, errors: str | None = None,
    kill_group: bool = False, discard_stdout: bool = False,
    discard_stderr: bool = False, text: Literal[True] = True, check: bool = False,
) -> subprocess.CompletedProcess[str]: ...


@overload
def run(
    command: Sequence[str], *, timeout: float | None = 30,
    input: bytes | None = None, stdin: int | IO[str] | IO[bytes] | None = None,
    env: Mapping[str, str] | Mapping[bytes, bytes] | None = None,
    encoding: str | None = None, errors: str | None = None,
    kill_group: bool = False, discard_stdout: bool = False,
    discard_stderr: bool = False, text: Literal[False], check: bool = False,
) -> subprocess.CompletedProcess[bytes]: ...


@overload
def run(
    command: Sequence[str], *, timeout: float | None = 30,
    input: str | bytes | None = None, stdin: int | IO[str] | IO[bytes] | None = None,
    env: Mapping[str, str] | Mapping[bytes, bytes] | None = None,
    encoding: str | None = None, errors: str | None = None,
    kill_group: bool = False, discard_stdout: bool = False,
    discard_stderr: bool = False, text: bool, check: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]: ...


def run(
    command: Sequence[str],
    *,
    timeout: float | None = 30,
    input: str | bytes | None = None,
    stdin: int | IO[str] | IO[bytes] | None = None,
    env: Mapping[str, str] | Mapping[bytes, bytes] | None = None,
    encoding: str | None = None,
    errors: str | None = None,
    kill_group: bool = False,
    discard_stdout: bool = False,
    discard_stderr: bool = False,
    text: bool = True,
    check: bool = False,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    """Capture streams as text by default; optionally discard, use bytes or check."""
    if not text and (encoding is not None or errors is not None):
        raise ValueError("encoding and errors cannot be used in bytes mode")
    argv = list(command)
    stdout_target = subprocess.DEVNULL if discard_stdout else subprocess.PIPE
    stderr_target = subprocess.DEVNULL if discard_stderr else subprocess.PIPE
    if not kill_group:
        return subprocess.run(
            argv, stdout=stdout_target, stderr=stderr_target, text=text,
            timeout=timeout, check=check, input=input, stdin=stdin, env=env,
            encoding=encoding, errors=errors,
        )

    if input is not None:
        if stdin is not None:
            raise ValueError("stdin and input arguments may not both be used.")
        stdin = subprocess.PIPE

    with subprocess.Popen(
        argv, stdin=stdin, stdout=stdout_target, stderr=stderr_target,
        text=text, env=env, encoding=encoding, errors=errors, start_new_session=True,
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
        if check and process.returncode:
            raise subprocess.CalledProcessError(process.returncode, argv, output=stdout, stderr=stderr)
        return subprocess.CompletedProcess(argv, process.returncode, stdout, stderr)

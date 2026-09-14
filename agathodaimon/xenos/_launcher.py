"""Root-only, consumed-in-place launcher for a Xenia guest clone."""
from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shlex
import signal
import stat
import subprocess
import sys
from typing import Callable, Iterable, Sequence

XENIA_ROOT = Path("/var/lib/xenia")
STAFF_USER = "caduceus"
XENIA_USER = "xenia"
STAFF_HOME = "/var/lib/caduceus"
PYTHON3 = "/usr/bin/python3"
VISUDO_CANDIDATES = ("/usr/sbin/visudo", "/usr/bin/visudo")
SAFE_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
TIMEOUT_SECONDS = 30
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
GRANT_PATTERN = re.compile(
    r"^\s*caduceus\s+ALL\s*=\s*\(\s*root\s*\)\s+NOPASSWD\s*:\s*(\S(?:.*\S)?)\s*$"
)


class Refusal(RuntimeError):
    """A stable public refusal, optionally tied to one grant-table line."""

    def __init__(self, first_missing_signal: str, line_number: int | None = None):
        super().__init__(first_missing_signal)
        self.first_missing_signal = first_missing_signal
        self.line_number = line_number

    def receipt(self) -> dict[str, object]:
        receipt: dict[str, object] = {
            "ok": False,
            "firstMissingSignal": self.first_missing_signal,
        }
        if self.line_number is not None:
            receipt["lineNumber"] = self.line_number
        return receipt


def _emit(receipt: dict[str, object]) -> None:
    print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))


def _validate_id(xenos_id: str) -> None:
    if ID_PATTERN.fullmatch(xenos_id) is None:
        raise Refusal("xenos-id-invalid")


def _lstat(path: Path, signal_name: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as exc:
        raise Refusal(signal_name) from exc


def _clone(xenos_id: str) -> Path:
    _validate_id(xenos_id)
    clone = XENIA_ROOT / xenos_id
    metadata = _lstat(clone, "xenos-clone-missing")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise Refusal("xenos-clone-invalid")
    return clone


def _minimal_environment(xenos_id: str, clone: Path, home: str) -> dict[str, str]:
    environment = {
        "HOME": home,
        "PATH": SAFE_PATH,
        "XENIA_ID": xenos_id,
        "XENIA_SEAT": str(clone),
    }
    if "XENIA_SCHEMA_BASE" in os.environ:
        environment["XENIA_SCHEMA_BASE"] = os.environ["XENIA_SCHEMA_BASE"]
    return environment


def _staff_identity() -> pwd.struct_passwd:
    try:
        return pwd.getpwnam(STAFF_USER)
    except KeyError as exc:
        raise Refusal("xenos-staff-identity-missing") from exc


def _drop_to_staff(staff: pwd.struct_passwd) -> Callable[[], None]:
    def drop() -> None:
        os.setgroups([])
        os.setgid(staff.pw_gid)
        os.setuid(staff.pw_uid)

    return drop


def _stdin_bytes() -> bytes:
    stream = sys.stdin
    if hasattr(stream, "buffer"):
        return stream.buffer.read()
    return stream.read().encode("utf-8")


def _run(
    argv: Sequence[str],
    stdin_bytes: bytes,
    *,
    cwd: Path,
    environment: dict[str, str],
    preexec_fn: Callable[[], None] | None = None,
) -> tuple[int | None, bytes, bytes, bool]:
    process = subprocess.Popen(
        list(argv),
        cwd=cwd,
        env=environment,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        preexec_fn=preexec_fn,
    )
    try:
        stdout, stderr = process.communicate(stdin_bytes, timeout=TIMEOUT_SECONDS)
        return process.returncode, stdout, stderr, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            process.kill()
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr, True


def _execution_receipt(
    verb: str,
    returncode: int | None,
    stdout: bytes,
    stderr: bytes,
    timed_out: bool,
) -> dict[str, object]:
    if timed_out:
        return {"ok": False, "firstMissingSignal": "xenos-run-timeout"}
    receipt: dict[str, object] = {
        "ok": returncode == 0,
        "verb": verb,
        "exitCode": returncode,
        "stdout": stdout.decode("utf-8", errors="replace"),
        "stderr": stderr.decode("utf-8", errors="replace"),
    }
    if returncode != 0:
        receipt["firstMissingSignal"] = f"xenos-{verb}-exit-nonzero"
    return receipt


def _validate_band(band: str) -> None:
    parts = band.split("/")
    if (
        not band
        or band.startswith("/")
        or band.endswith("/")
        or any(
            not part
            or part in {".", ".."}
            or any(not (char.isascii() and (char.isalnum() or char in "-_")) for char in part)
            for part in parts
        )
    ):
        raise Refusal("xenos-band-invalid")


def run_band(xenos_id: str, band: str, stdin_bytes: bytes) -> dict[str, object]:
    clone = _clone(xenos_id)
    _validate_band(band)
    cli = clone / "staff" / "cli.py"
    metadata = _lstat(cli, "xenos-staff-cli-missing")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise Refusal("xenos-staff-cli-invalid")
    staff = _staff_identity()
    try:
        returncode, stdout, stderr, timed_out = _run(
            [PYTHON3, str(cli), band],
            stdin_bytes,
            cwd=clone,
            environment=_minimal_environment(xenos_id, clone, STAFF_HOME),
            preexec_fn=_drop_to_staff(staff),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("xenos-band-launch-failed") from exc
    return _execution_receipt("band", returncode, stdout, stderr, timed_out)


def _visudo() -> str:
    for candidate in VISUDO_CANDIDATES:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise Refusal("xenia-visudo-unavailable")


def _allowed_owner_uids() -> set[int]:
    owners = {0}
    try:
        owners.add(pwd.getpwnam(XENIA_USER).pw_uid)
    except KeyError:
        pass
    return owners


def _contains_parent_segment(value: str) -> bool:
    return ".." in PurePosixPath(value).parts


def _inside_clone(path: str, clone: Path) -> bool:
    candidate_parts = PurePosixPath(path).parts
    clone_parts = PurePosixPath(str(clone)).parts
    return len(candidate_parts) > len(clone_parts) and candidate_parts[: len(clone_parts)] == clone_parts


def _parse_grants(lines: Iterable[str], clone: Path) -> list[list[str]]:
    grants: list[list[str]] = []
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split(None, 1)[0]
        if first != STAFF_USER:
            raise Refusal("xenia-grant-grantee-refused", line_number)
        match = GRANT_PATTERN.fullmatch(raw_line.rstrip("\r\n"))
        if match is None:
            raise Refusal("xenia-grant-line-invalid", line_number)
        command_spec = match.group(1)
        if "*" in command_spec:
            raise Refusal("xenia-grant-wildcard-refused", line_number)
        try:
            argv = shlex.split(command_spec, posix=True)
        except ValueError as exc:
            raise Refusal("xenia-grant-line-invalid", line_number) from exc
        if not argv or not os.path.isabs(argv[0]):
            raise Refusal("xenia-grant-path-not-absolute", line_number)
        if not _inside_clone(argv[0], clone):
            raise Refusal("xenia-grant-path-outside-clone", line_number)
        if "ALL" in argv[0]:
            raise Refusal("xenia-grant-all-refused", line_number)
        if ".." in argv[0]:
            raise Refusal("xenia-grant-parent-segment-refused", line_number)
        grants.append(argv)
    return grants


def _load_grants(clone: Path) -> list[list[str]]:
    permissions = clone / "permissions"
    directory_metadata = _lstat(permissions, "xenia-permissions-directory-missing")
    if stat.S_ISLNK(directory_metadata.st_mode) or not stat.S_ISDIR(directory_metadata.st_mode):
        raise Refusal("xenia-permissions-directory-invalid")

    grant_file = permissions / "xenia"
    metadata = _lstat(grant_file, "xenia-grant-file-missing")
    if stat.S_ISLNK(metadata.st_mode):
        raise Refusal("xenia-grant-file-symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise Refusal("xenia-grant-file-not-regular")
    if metadata.st_uid not in _allowed_owner_uids():
        raise Refusal("xenia-grant-file-owner-refused")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise Refusal("xenia-grant-file-writable")
    if directory_metadata.st_mode & stat.S_IWOTH:
        raise Refusal("xenia-permissions-directory-world-writable")
    if clone.lstat().st_mode & stat.S_IWOTH:
        raise Refusal("xenos-clone-world-writable")

    validation = subprocess.run(
        [_visudo(), "-c", "-f", str(grant_file)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if validation.returncode != 0:
        raise Refusal("xenia-visudo-invalid")
    try:
        lines = grant_file.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise Refusal("xenia-grant-file-unreadable") from exc
    post = _lstat(grant_file, "xenia-grant-file-missing")
    if (post.st_dev, post.st_ino, post.st_mode, post.st_uid) != (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
    ):
        raise Refusal("xenia-grant-file-changed")
    return _parse_grants(lines, clone)


def _authorized_argv(clone: Path, requested: Sequence[str]) -> list[str]:
    argv = list(requested)
    if not argv or not os.path.isabs(argv[0]):
        raise Refusal("xenos-exec-path-not-absolute")
    if not _inside_clone(argv[0], clone):
        raise Refusal("xenos-exec-path-outside-clone")
    if _contains_parent_segment(argv[0]):
        raise Refusal("xenos-exec-parent-segment-refused")
    grants = _load_grants(clone)
    if argv not in grants:
        raise Refusal("xenia-grant-argument-mismatch")
    try:
        resolved_clone = clone.resolve(strict=True)
        resolved_command = Path(argv[0]).resolve(strict=True)
        resolved_command.relative_to(resolved_clone)
    except FileNotFoundError as exc:
        raise Refusal("xenos-exec-path-missing") from exc
    except (OSError, ValueError) as exc:
        raise Refusal("xenos-exec-path-outside-clone") from exc
    if not resolved_command.is_file():
        raise Refusal("xenos-exec-path-not-regular")
    return argv


def run_exec(xenos_id: str, requested: Sequence[str], stdin_bytes: bytes) -> dict[str, object]:
    clone = _clone(xenos_id)
    argv = _authorized_argv(clone, requested)
    try:
        returncode, stdout, stderr, timed_out = _run(
            argv,
            stdin_bytes,
            cwd=clone,
            environment=_minimal_environment(xenos_id, clone, "/root"),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("xenos-exec-launch-failed") from exc
    return _execution_receipt("exec", returncode, stdout, stderr, timed_out)


def main(argv: Sequence[str] | None = None) -> int:
    if os.geteuid() != 0:
        _emit({"ok": False, "firstMissingSignal": "xenos-run-root-required"})
        return 1
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 3:
        _emit({"ok": False, "firstMissingSignal": "xenos-run-arguments-invalid"})
        return 0
    xenos_id, verb, *remainder = args
    try:
        if verb == "band" and len(remainder) == 1:
            receipt = run_band(xenos_id, remainder[0], _stdin_bytes())
        elif verb == "exec" and remainder:
            receipt = run_exec(xenos_id, remainder, _stdin_bytes())
        elif verb in {"band", "exec"}:
            receipt = {"ok": False, "firstMissingSignal": "xenos-run-arguments-invalid"}
        else:
            receipt = {"ok": False, "firstMissingSignal": "xenos-run-verb-invalid"}
    except Refusal as refusal:
        receipt = refusal.receipt()
    _emit(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

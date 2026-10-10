"""Root-only, consumed-in-place launcher for a Xenia guest clone."""
from __future__ import annotations

import grp
import ipaddress
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
REGISTER_PATH = Path("/etc/appliance/xenia.json")
SEAT_ROOT = Path("/var/lib/xenia")
CGROUP_ROOT = Path("/sys/fs/cgroup")
PROC_ROOT = Path("/proc")
SYSTEMCTL_PATH = "/usr/bin/systemctl"
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


def _xenia_group_identity() -> grp.struct_group:
    try:
        return grp.getgrnam(XENIA_USER)
    except KeyError as exc:
        raise Refusal("xenos-xenia-group-missing") from exc


def _drop_to_staff(
    staff: pwd.struct_passwd, xenia: grp.struct_group
) -> Callable[[], None]:
    def drop() -> None:
        os.setgroups([xenia.gr_gid])
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
    xenia = _xenia_group_identity()
    try:
        returncode, stdout, stderr, timed_out = _run(
            [PYTHON3, str(cli), band],
            stdin_bytes,
            cwd=clone,
            environment=_minimal_environment(xenos_id, clone, STAFF_HOME),
            preexec_fn=_drop_to_staff(staff, xenia),
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


def _open_absolute_directory(
    path: Path, missing_signal: str, invalid_signal: str, observation_signal: str
) -> int:
    """Open each absolute path component without following a symlink."""
    path = Path(path)
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts[1:]):
        raise Refusal(invalid_signal)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        current = os.open("/", flags)
    except OSError as exc:
        raise Refusal(observation_signal) from exc
    try:
        for part in path.parts[1:]:
            try:
                child = os.open(part, flags, dir_fd=current)
            except FileNotFoundError as exc:
                raise Refusal(missing_signal) from exc
            except OSError as exc:
                raise Refusal(invalid_signal) from exc
            os.close(current)
            current = child
        if not stat.S_ISDIR(os.fstat(current).st_mode):
            raise Refusal(invalid_signal)
        return current
    except Exception:
        os.close(current)
        raise


def _open_child_directory(parent_fd: int, name: str, signal_name: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    except OSError as exc:
        raise Refusal(signal_name) from exc


def _read_relative_file(root: Path, parts: Sequence[str], signal_name: str) -> str:
    root_fd = _open_absolute_directory(
        root, signal_name, signal_name, signal_name
    )
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child_fd = _open_child_directory(current_fd, part, signal_name)
            os.close(current_fd)
            current_fd = child_fd
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            file_fd = os.open(parts[-1], flags, dir_fd=current_fd)
            with os.fdopen(file_fd, "r", encoding="utf-8") as stream:
                return stream.read()
        except (OSError, UnicodeError) as exc:
            raise Refusal(signal_name) from exc
    finally:
        os.close(current_fd)
        os.close(root_fd)


def _registered_entry(xenos_id: str) -> dict[str, object]:
    _validate_id(xenos_id)
    try:
        register = json.loads(Path(REGISTER_PATH).read_bytes())
    except FileNotFoundError as exc:
        raise Refusal("xenos-register-missing") from exc
    except (OSError, ValueError) as exc:
        raise Refusal("xenos-register-unreadable") from exc
    if not isinstance(register, dict) or not isinstance(register.get("xenoi"), dict):
        raise Refusal("xenos-register-map-invalid")
    entry = register["xenoi"].get(xenos_id)
    if entry is None:
        raise Refusal("xenos-not-registered")
    if not isinstance(entry, dict):
        raise Refusal("xenos-register-entry-invalid")
    return entry


def _registered_owner(entry: dict[str, object]) -> tuple[str, pwd.struct_passwd]:
    install = entry.get("install")
    owner = install.get("owner") if isinstance(install, dict) else None
    if not isinstance(owner, str) or not owner:
        raise Refusal("xenos-owner-missing")
    try:
        identity = pwd.getpwnam(owner)
    except KeyError as exc:
        raise Refusal("xenos-install-owner-unknown") from exc
    except (OSError, ValueError) as exc:
        raise Refusal("xenos-owner-lookup-failed") from exc
    if identity.pw_uid == 0:
        raise Refusal("xenos-owner-root-refused")
    return owner, identity


def seat_xenos(xenos_id: str) -> dict[str, object]:
    entry = _registered_entry(xenos_id)
    owner, identity = _registered_owner(entry)
    try:
        install_group = grp.getgrnam(XENIA_USER)
    except KeyError:
        try:
            install_group = grp.getgrgid(identity.pw_gid)
        except KeyError as exc:
            raise Refusal("xenos-install-group-unknown") from exc
        except (OSError, ValueError) as exc:
            raise Refusal("xenos-install-group-lookup-failed") from exc
    except (OSError, ValueError) as exc:
        raise Refusal("xenos-install-group-lookup-failed") from exc
    root_fd = _open_absolute_directory(
        SEAT_ROOT,
        "xenos-seat-root-missing",
        "xenos-seat-root-invalid",
        "xenos-seat-root-unavailable",
    )
    try:
        root_metadata = os.fstat(root_fd)
        if root_metadata.st_uid != 0 or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise Refusal("xenos-seat-root-untrusted")
        try:
            before = os.stat(xenos_id, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise Refusal("xenos-seat-missing") from exc
        except OSError as exc:
            raise Refusal("xenos-seat-observation-failed") from exc
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise Refusal("xenos-seat-not-a-directory")

        child_fd = _open_child_directory(root_fd, xenos_id, "xenos-seat-open-failed")
        try:
            current = os.fstat(child_fd)
            if (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino):
                raise Refusal("xenos-seat-changed-during-open")
            changed = (
                current.st_uid != identity.pw_uid
                or current.st_gid != install_group.gr_gid
                or stat.S_IMODE(current.st_mode) != 0o750
            )
            try:
                if current.st_uid != identity.pw_uid or current.st_gid != install_group.gr_gid:
                    os.fchown(child_fd, identity.pw_uid, install_group.gr_gid)
                if stat.S_IMODE(current.st_mode) != 0o750:
                    os.fchmod(child_fd, 0o750)
                final = os.fstat(child_fd)
                linked = os.stat(xenos_id, dir_fd=root_fd, follow_symlinks=False)
            except OSError as exc:
                raise Refusal("xenos-seat-update-failed") from exc
            if (
                (linked.st_dev, linked.st_ino) != (final.st_dev, final.st_ino)
                or not stat.S_ISDIR(linked.st_mode)
                or final.st_uid != identity.pw_uid
                or final.st_gid != install_group.gr_gid
                or stat.S_IMODE(final.st_mode) != 0o750
            ):
                raise Refusal("xenos-seat-final-state-mismatch")
            return {
                "ok": True,
                "id": xenos_id,
                "path": str(Path(SEAT_ROOT) / xenos_id),
                "owner": owner,
                "group": install_group.gr_name,
                "mode": "0750",
                "changed": changed,
            }
        finally:
            os.close(child_fd)
    finally:
        os.close(root_fd)


def _systemd_control_group(xenos_id: str) -> tuple[str, str] | None:
    try:
        result = subprocess.run(
            [
                SYSTEMCTL_PATH,
                "show",
                "--no-pager",
                "--property=LoadState,ActiveState,ControlGroup",
                "--",
                f"{xenos_id}.service",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"LC_ALL": "C", "PATH": SAFE_PATH},
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise Refusal("xenos-systemd-timeout") from exc
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("xenos-systemd-observation-failed") from exc
    try:
        text = result.stdout.decode("utf-8")
    except UnicodeError as exc:
        raise Refusal("xenos-systemd-output-invalid") from exc
    properties = {
        key: value
        for line in text.splitlines()
        if (separator := line.find("=")) >= 0
        for key, value in [(line[:separator], line[separator + 1 :])]
    }
    if properties.get("LoadState") == "not-found":
        return None
    if result.returncode != 0:
        raise Refusal("xenos-systemd-observation-failed")
    if any(key not in properties for key in ("LoadState", "ActiveState", "ControlGroup")):
        raise Refusal("xenos-systemd-property-missing")
    return properties["ControlGroup"], properties["ActiveState"]


def _read_cgroup_pids(directory_fd: int, pids: set[int]) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        file_fd = os.open("cgroup.procs", flags, dir_fd=directory_fd)
        with os.fdopen(file_fd, "r", encoding="ascii") as stream:
            lines = stream.read().splitlines()
    except (OSError, UnicodeError) as exc:
        raise Refusal("xenos-cgroup-procs-unreadable") from exc
    for line in lines:
        try:
            pid = int(line, 10)
        except ValueError as exc:
            raise Refusal("xenos-cgroup-pid-invalid") from exc
        if pid <= 0:
            raise Refusal("xenos-cgroup-pid-invalid")
        pids.add(pid)
    try:
        names = os.listdir(directory_fd)
    except OSError as exc:
        raise Refusal("xenos-cgroup-list-failed") from exc
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for name in names:
        if name == "cgroup.procs":
            continue
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise Refusal("xenos-cgroup-observation-failed") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise Refusal("xenos-cgroup-symlink-refused")
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        try:
            child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
        except OSError as exc:
            raise Refusal("xenos-cgroup-observation-failed") from exc
        try:
            opened = os.fstat(child_fd)
            if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise Refusal("xenos-cgroup-changed-during-open")
            _read_cgroup_pids(child_fd, pids)
        finally:
            os.close(child_fd)


def _cgroup_pids(control_group: str, active_state: str) -> set[int]:
    if not control_group:
        if active_state == "active":
            raise Refusal("xenos-active-unit-cgroup-absent")
        return set()
    group = PurePosixPath(control_group)
    if (
        not control_group.startswith("/")
        or group == PurePosixPath("/")
        or ".." in group.parts
        or group.as_posix() != control_group
    ):
        raise Refusal("xenos-cgroup-path-invalid")
    root_fd = _open_absolute_directory(
        CGROUP_ROOT,
        "xenos-cgroup-root-missing",
        "xenos-cgroup-root-invalid",
        "xenos-cgroup-root-unavailable",
    )
    current_fd = os.dup(root_fd)
    try:
        for part in group.parts[1:]:
            child_fd = _open_child_directory(current_fd, part, "xenos-cgroup-path-unavailable")
            os.close(current_fd)
            current_fd = child_fd
        pids: set[int] = set()
        _read_cgroup_pids(current_fd, pids)
        return pids
    finally:
        os.close(current_fd)
        os.close(root_fd)


def _process_socket_inodes(pids: set[int]) -> set[int]:
    proc_fd = _open_absolute_directory(
        PROC_ROOT,
        "xenos-proc-root-missing",
        "xenos-proc-root-invalid",
        "xenos-proc-root-unavailable",
    )
    result: set[int] = set()
    try:
        for pid in sorted(pids):
            pid_fd = _open_child_directory(proc_fd, str(pid), "xenos-proc-pid-unavailable")
            try:
                fd_dir = _open_child_directory(pid_fd, "fd", "xenos-proc-fd-unavailable")
                try:
                    try:
                        descriptors = os.listdir(fd_dir)
                    except OSError as exc:
                        raise Refusal("xenos-proc-fd-unreadable") from exc
                    for descriptor in descriptors:
                        if not descriptor.isdecimal():
                            raise Refusal("xenos-proc-fd-entry-invalid")
                        try:
                            target = os.readlink(descriptor, dir_fd=fd_dir)
                        except OSError as exc:
                            raise Refusal("xenos-proc-fd-readlink-failed") from exc
                        if target.startswith("socket:[") and target.endswith("]"):
                            try:
                                inode = int(target[8:-1], 10)
                            except ValueError as exc:
                                raise Refusal("xenos-proc-socket-inode-invalid") from exc
                            if inode < 0 or inode > 0xFFFFFFFFFFFFFFFF:
                                raise Refusal("xenos-proc-socket-inode-invalid")
                            result.add(inode)
                finally:
                    os.close(fd_dir)
            finally:
                os.close(pid_fd)
        return result
    finally:
        os.close(proc_fd)


def _proc_net_namespace(pid: int) -> str:
    proc_fd = _open_absolute_directory(
        PROC_ROOT,
        "xenos-proc-root-missing",
        "xenos-proc-root-invalid",
        "xenos-proc-root-unavailable",
    )
    try:
        pid_fd = _open_child_directory(proc_fd, str(pid), "xenos-proc-pid-unavailable")
        try:
            namespace_fd = _open_child_directory(
                pid_fd, "ns", "xenos-proc-netns-unavailable"
            )
            try:
                try:
                    return os.readlink("net", dir_fd=namespace_fd)
                except OSError as exc:
                    raise Refusal("xenos-proc-netns-unreadable") from exc
            finally:
                os.close(namespace_fd)
        finally:
            os.close(pid_fd)
    finally:
        os.close(proc_fd)


def _proc_socket_rows(pid: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for name, ipv6 in (("tcp", False), ("tcp6", True)):
        text = _read_relative_file(
            PROC_ROOT, (str(pid), "net", name), f"xenos-proc-{name}-unreadable"
        )
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise Refusal("xenos-tcp-row-invalid")
            if fields[3] != "0A":
                continue
            try:
                address_hex, port_hex = fields[1].split(":", 1)
                if re.fullmatch(r"[0-9A-Fa-f]{1,4}", port_hex) is None:
                    raise ValueError
                port = int(port_hex, 16)
                if port > 65535:
                    raise ValueError
                if ipv6:
                    if re.fullmatch(r"[0-9A-Fa-f]{32}", address_hex) is None:
                        raise ValueError
                    packed = b"".join(
                        int(address_hex[index : index + 8], 16).to_bytes(4, byteorder=sys.byteorder)
                        for index in range(0, 32, 8)
                    )
                    address = ipaddress.IPv6Address(packed)
                else:
                    if re.fullmatch(r"[0-9A-Fa-f]{8}", address_hex) is None:
                        raise ValueError
                    packed = int(address_hex, 16).to_bytes(4, byteorder=sys.byteorder)
                    address = ipaddress.IPv4Address(packed)
                inode = int(fields[9], 10)
                if inode < 0 or inode > 0xFFFFFFFFFFFFFFFF:
                    raise ValueError
            except (ValueError, OverflowError) as exc:
                raise Refusal("xenos-tcp-listener-invalid") from exc
            endpoint_host = f"[{address}]" if address.version == 6 else str(address)
            rows.append(
                {
                    "endpoint": f"http://{endpoint_host}:{port}",
                    "inode": inode,
                    "loopback": address.is_loopback,
                    "port": port,
                }
            )

    text = _read_relative_file(
        PROC_ROOT, (str(pid), "net", "unix"), "xenos-proc-unix-unreadable"
    )
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 7:
            raise Refusal("xenos-unix-row-invalid")
        if fields[3] != "00010000" or len(fields) < 8:
            continue
        try:
            inode = int(fields[6], 10)
            if inode < 0 or inode > 0xFFFFFFFFFFFFFFFF:
                raise ValueError
        except ValueError as exc:
            raise Refusal("xenos-unix-listener-invalid") from exc
        rows.append(
            {
                "endpoint": f"unix:{fields[7]}",
                "inode": inode,
                "loopback": True,
                "port": None,
            }
        )
    return rows


def census_xenos(xenos_id: str) -> dict[str, object]:
    entry = _registered_entry(xenos_id)
    if entry.get("kind") != "cartridge-process":
        return {"ok": True, "id": xenos_id, "listeners": []}
    observed = _systemd_control_group(xenos_id)
    if observed is None:
        return {"ok": True, "id": xenos_id, "listeners": []}
    control_group, active_state = observed
    pids = _cgroup_pids(control_group, active_state)
    if not pids:
        return {"ok": True, "id": xenos_id, "listeners": []}
    inodes = _process_socket_inodes(pids)
    namespace_pids: dict[str, int] = {}
    for pid in sorted(pids):
        namespace = _proc_net_namespace(pid)
        namespace_pids.setdefault(namespace, pid)
    rows = [
        row
        for pid in namespace_pids.values()
        for row in _proc_socket_rows(pid)
    ]
    listeners = [
        row
        for row in rows
        if row["loopback"] and row["inode"] in inodes
    ]
    return {"ok": True, "id": xenos_id, "listeners": listeners}


def main(argv: Sequence[str] | None = None) -> int:
    if os.geteuid() != 0:
        _emit({"ok": False, "firstMissingSignal": "xenos-run-root-required"})
        return 1
    args = list(sys.argv[1:] if argv is None else argv)
    legacy_verb_form = len(args) >= 3 and args[1] in {"band", "exec"}
    if args and args[0] in {"seat", "census"} and not legacy_verb_form:
        verb = args[0]
        if len(args) != 2:
            _emit({"ok": False, "firstMissingSignal": f"xenos-{verb}-arguments-invalid"})
            return 1
        try:
            receipt = seat_xenos(args[1]) if verb == "seat" else census_xenos(args[1])
        except Refusal as refusal:
            _emit(refusal.receipt())
            return 1
        except (OSError, subprocess.SubprocessError):
            _emit({"ok": False, "firstMissingSignal": f"xenos-{verb}-observation-failed"})
            return 1
        _emit(receipt)
        return 0
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

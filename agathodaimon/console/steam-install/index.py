"""Install Steam only after the owner explicitly accepts Valve's licence."""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Callable, Sequence

from agathodaimon.console.restart.index import steam_executable

SCHEMA = "agathodaimon.console.steam-install.v1"
LOG = Path("/var/log/appliance/appliance.log")
SELECTIONS = b"steam steam/question select I AGREE\nsteam steam/license note\n"


class CommandFailure(Exception):
    def __init__(self, argv: Sequence[str], code: int | None, last_line: str):
        self.command = shlex.join(argv)
        self.code = code
        self.last_line = last_line[-512:]
        super().__init__(self.command)


def _environment() -> dict[str, str]:
    # Read the body's databases, never an inherited alternate debconf/dpkg seat.
    environment = {
        key: value for key, value in os.environ.items()
        if not key.startswith(("DEBCONF_", "DPKG_")) and key != "APT_CONFIG"
    }
    environment["LC_ALL"] = "C"
    return environment


def _run(
    argv: Sequence[str], *, consume: Callable[[str], None] | None = None,
    selection: bytes | None = None, environment: dict[str, str] | None = None,
) -> tuple[int, str]:
    """Drain output as a bounded stream; keep only its last nonempty line."""
    try:
        with subprocess.Popen(
            argv, stdin=subprocess.PIPE if selection is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=_environment() if environment is None else environment,
        ) as process:
            if selection is not None:
                assert process.stdin is not None
                try:
                    process.stdin.write(selection)
                except BrokenPipeError:
                    pass
                finally:
                    process.stdin.close()
            assert process.stdout is not None
            pending = b""
            last = ""
            while True:
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                lines = (pending + chunk.replace(b"\r", b"\n")).split(b"\n")
                pending = lines.pop()[-4096:]
                for raw in lines:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        last = line[-512:]
                        if consume is not None:
                            consume(line)
            if pending.strip():
                line = pending.decode("utf-8", errors="replace").strip()
                last = line[-512:]
                if consume is not None:
                    consume(line)
            return process.wait(), last
    except OSError as error:
        raise CommandFailure(argv, None, f"{type(error).__name__}: {error}") from error


def _require(argv: Sequence[str], **kwargs) -> None:
    code, last = _run(argv, **kwargs)
    if code:
        raise CommandFailure(argv, code, last)


def _apt_body(os_release: Path) -> bool:
    """A distro declaration and the actual executables must both agree."""
    values: dict[str, str] = {}
    for line in os_release.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator and key in {"ID", "ID_LIKE"}:
            values[key] = " ".join(shlex.split(value, comments=True))
    families = {values.get("ID", ""), *values.get("ID_LIKE", "").split()}
    apt = shutil.which("apt-get")
    dpkg = shutil.which("dpkg")
    pacman = shutil.which("pacman")
    if "arch" in families or (pacman and not (apt and dpkg)):
        return False
    return bool(families & {"debian", "ubuntu"} and apt and dpkg)


def _stanzas(text: str):
    fields: dict[str, str] = {}
    previous = ""
    for line in [*text.splitlines(), ""]:
        if not line.strip():
            if fields:
                yield fields
            fields = {}
            previous = ""
        elif not line.lstrip().startswith("#"):
            if line[0].isspace() and previous:
                fields[previous] += " " + line.strip()
            else:
                key, separator, value = line.partition(":")
                if separator:
                    previous = key.strip().lower()
                    fields[previous] = value.strip()


def _contrib_enabled() -> bool:
    root = Path("/etc/apt")
    paths = [root / "sources.list"] if (root / "sources.list").exists() else []
    paths += sorted((root / "sources.list.d").glob("*.list"))
    paths += sorted((root / "sources.list.d").glob("*.sources"))
    enabled = False
    for path in paths:
        text = path.read_text(encoding="utf-8")
        if path.suffix == ".sources":
            enabled |= any(
                row.get("enabled", "yes").lower() != "no"
                and "deb" in row.get("types", "").split()
                and "contrib" in row.get("components", "").split()
                for row in _stanzas(text)
            )
        else:
            for line in text.splitlines():
                active = line.partition("#")[0].strip()
                match = re.match(r"^deb\s+(?:\[[^\]]*\]\s+)?\S+\s+\S+\s+(.*)$", active)
                if match and "contrib" in match.group(1).split():
                    enabled = True
    return enabled


def _license_accepted() -> bool:
    # debconf-show is readonly, but its File driver creates absent databases.
    # Preflight the selected system configuration so even that path is inert.
    config = Path("/etc/debconf.conf")
    if not config.exists():
        config = Path("/usr/share/debconf/debconf.conf")
    rows = list(_stanzas(config.read_text(encoding="utf-8")))
    for row in rows:
        driver = row.get("driver", "").lower()
        if driver and row.get("readonly", "true").lower() not in {"true", "yes", "1"}:
            raise ValueError("debconf-readonly-configuration-required")
        if driver == "file":
            database = Path(row.get("filename", ""))
            if not database.is_absolute() or not database.is_file():
                raise ValueError("debconf-database-absent")
        elif driver and driver != "stack":
            raise ValueError("debconf-readonly-driver-unsupported")
    environment = _environment()
    environment["DEBCONF_SYSTEMRC"] = str(config)
    accepted = False

    def observe(line: str) -> None:
        nonlocal accepted
        key, separator, value = line.lstrip("* ").partition(":")
        if separator and key == "steam/question":
            accepted = value.strip() == "I AGREE"

    _require(["debconf-show", "steam"], consume=observe, environment=environment)
    return accepted


def _state() -> dict:
    package: dict[str, str] = {}
    absent = False

    def observe(line: str) -> None:
        nonlocal absent
        if "steam-installer" in line and "is not installed and no information is available" in line:
            absent = True
        key, separator, value = line.partition(":")
        if separator and key in {"Status", "Version"}:
            package[key] = value.strip()

    argv = ["dpkg", "-s", "steam-installer"]
    code, last = _run(argv, consume=observe)
    if code and not (code == 1 and absent):
        raise CommandFailure(argv, code, last)
    architectures: set[str] = set()
    _require(["dpkg", "--print-foreign-architectures"], consume=architectures.add)
    steam_path = Path(steam_executable())
    executable = str(steam_path) if steam_path.is_file() and os.access(steam_path, os.X_OK) else None
    return {
        "schema": SCHEMA,
        "installed": package.get("Status", "").split()[-2:] == ["ok", "installed"],
        "version": package.get("Version"),
        "executable": executable,
        "i386_enabled": "i386" in architectures,
        "contrib_enabled": _contrib_enabled(),
        "license_accepted": _license_accepted(),
    }


def _failure(error: CommandFailure) -> dict:
    return {"command": error.command, "exit_code": error.code, "last_line": error.last_line}


def _record_deed(started: float, state: dict, failure: CommandFailure | None) -> None:
    row = {
        "who": "console-steam-install", "actor": "owner", "verb": "install",
        "target": socket.gethostname()[:96], "outcome": "failed" if failure else "installed",
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "version": (state.get("version") or "")[:96] or None,
        "license_accepted_by": "owner",
    }
    if failure:
        row.update({
            "command": failure.command[:128], "exit_code": failure.code,
            "signal": failure.last_line.encode("ascii", errors="replace").decode()[-192:],
        })
    line = (json.dumps(row, separators=(",", ":")) + "\n").encode("ascii")
    if len(line) >= 1024:
        raise ValueError("deed-line-too-large")
    LOG.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o644)
    try:
        if os.write(descriptor, line) != len(line):
            raise OSError("deed-line-short-write")
    finally:
        os.close(descriptor)


def _emit(result: dict, code: int) -> int:
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon console steam-install")
    parser.add_argument("--check", action="store_true", help="Read installed state without changing anything")
    parser.add_argument("--accept-license", action="store_true", help="The owner explicitly accepts Valve's Steam licence")
    parser.add_argument("--json", action="store_true", help="Print JSON (also the default)")
    parser.add_argument("--os-release", type=Path, default=Path("/etc/os-release"), help="OS declaration (override for labelled proof)")
    args = parser.parse_args(argv)
    try:
        if not _apt_body(args.os_release):
            return _emit({"schema": SCHEMA, "error": "package-manager-unsupported"}, 6)
        state = _state()
    except (OSError, ValueError, CommandFailure) as error:
        detail = _failure(error) if isinstance(error, CommandFailure) else {"signal": str(error)}
        return _emit({"schema": SCHEMA, "error": "observation-failed", **detail}, 1)
    if args.check:
        return _emit(state, 0)
    if state["installed"]:
        return _emit(state, 7)
    if not args.accept_license:
        return _emit({**state, "error": "license-not-accepted"}, 8)
    if os.geteuid() != 0:
        return _emit({**state, "error": "root-required"}, 1)

    started = time.monotonic()
    failure = None
    try:
        if not state["i386_enabled"]:
            _require(["dpkg", "--add-architecture", "i386"])
        _require(["debconf-set-selections"], selection=SELECTIONS)
        environment = _environment()
        environment["DEBIAN_FRONTEND"] = "noninteractive"
        _require(["apt-get", "update"], environment=environment)
        _require(["apt-get", "install", "--yes", "steam-installer", "steam-devices"], environment=environment)
        state = _state()
        if not state["installed"]:
            raise CommandFailure(["dpkg", "-s", "steam-installer"], None, "steam-installer-readback-not-installed")
    except (OSError, ValueError, CommandFailure) as error:
        failure = error if isinstance(error, CommandFailure) else CommandFailure(["readback"], None, str(error))
        try:
            state = _state()
        except (OSError, ValueError, CommandFailure):
            state = {"schema": SCHEMA, "observation_error": "post-attempt-state-unavailable"}
    try:
        _record_deed(started, state, failure)
    except (OSError, ValueError) as error:
        result = {**state, "error": "deed-log-failed", "signal": str(error)}
        if failure:
            result.update(_failure(failure))
        return _emit(result, 9 if failure else 1)
    if failure:
        return _emit({**state, "error": "command-failed", **_failure(failure)}, 9)
    return _emit(state, 0)


if __name__ == "__main__":
    raise SystemExit(main())

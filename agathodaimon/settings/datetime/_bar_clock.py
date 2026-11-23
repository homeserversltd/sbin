"""Read and write Waybar's owner-controlled clock include."""
from __future__ import annotations

import json
import math
import os
import stat
import subprocess
import sys
from pathlib import Path

# The writer can be run as owner from a privileged settings stop.
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agathodaimon._nidus.write import WriteError, write

FORMATS = {
    "24h": ("{:%H:%M} \uf017 ", "{:%A, %B %d, %Y (%R)} "),
    "12h": ("{:%I:%M %p} \uf017 ", "{:%A, %B %d, %Y (%I:%M %p)} "),
}
ABSENT = "unsupported:bar-clock-override-absent"
_INVALID = "datetime-bar-clock-override-invalid"
_INCLUDE = ".config/waybar/clock-override.json"
_FILE_MAX = 1024 * 1024


class _MalformedDocument(ValueError):
    """The bounded regular file was read, but its contents could not be parsed."""


def _finite_number(token: str) -> float:
    # Reject bare NaN/Infinity and exponents that overflow a JSON round trip.
    value = float(token)
    if not math.isfinite(value):
        raise ValueError(_INVALID)
    return value


def _open_unlinked(path: Path) -> int:
    # O_NOFOLLOW on the file alone leaves .config and waybar able to
    # redirect a privileged read. Pin each parent before opening its child.
    path = path.absolute()
    if ".." in path.parts:
        raise ValueError("bar-clock-path-invalid")
    directory_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor, directory_flags)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=directory)
    finally:
        os.close(directory)


def _strip_jsonc(raw: bytes) -> bytearray:
    # A monotonically advancing scan: quoted bytes are never reconsidered
    # as syntax, and an unterminated comment or string fails at its first scan.
    data = bytearray(raw)
    end, pos = len(data), 0
    previous = comma = None
    while pos < end:
        token = data[pos]
        if token == ord('"'):
            pos += 1
            while pos < end:
                char = data[pos]
                pos += 1
                if char == ord('"'):
                    break
                if char == ord('\\'):
                    pos += 1
            else:
                raise ValueError("bar-clock-jsonc-unclosed-string")
            previous, comma = token, None
            continue
        if token == ord('/') and pos + 1 < end:
            start = pos
            if data[pos + 1] == ord('/'):
                pos += 2
                while pos < end and data[pos] not in b"\r\n":
                    pos += 1
            elif data[pos + 1] == ord('*'):
                stop = data.find(b"*/", pos + 2)
                if stop < 0:
                    raise ValueError("bar-clock-jsonc-unclosed-comment")
                pos = stop + 2
            if pos != start:
                data[start:pos] = b" " * (pos - start)
                continue
        if token not in b" \t\r\n":
            if token in b"}]" and comma is not None:
                data[comma] = ord(' ')
            comma = pos if token == ord(',') and previous is not None and previous not in b"[{:," else None
            previous = token
        pos += 1
    return data


def _read(path: Path, *, finite_numbers: bool = False):
    fd = _open_unlinked(path)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("bar-clock-not-a-regular-file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(_FILE_MAX + 1)
    finally:
        os.close(fd)
    if len(raw) > _FILE_MAX:
        raise ValueError("bar-clock-file-too-large")
    try:
        raw.decode("utf-8")  # Comments, too, must be UTF-8.
        text = _strip_jsonc(raw).decode("utf-8")
        if finite_numbers:
            return json.loads(text, parse_float=_finite_number, parse_constant=_finite_number)
        return json.loads(text)
    except (ValueError, RecursionError) as error:
        raise _MalformedDocument(_INVALID) from error


def includes_override(home: Path) -> bool:
    try:
        config = _read(home / ".config/waybar/waybar.conf")
    except (OSError, ValueError, RecursionError):
        return False
    # Direct includes only: do not expand shell words or walk other includes.
    paths = {str(home / _INCLUDE), "~/" + _INCLUDE, "$HOME/" + _INCLUDE, "${HOME}/" + _INCLUDE}
    for bar in config if isinstance(config, list) else [config]:
        if not isinstance(bar, dict):
            continue
        include = bar.get("include")
        if any(isinstance(item, str) and item in paths
               for item in (include if isinstance(include, list) else [include])):
            return True
    return False


def _match(document) -> str | None:
    clock = document.get("clock") if isinstance(document, dict) else None
    if not isinstance(clock, dict):
        return None
    pair = (clock.get("format"), clock.get("format-alt"))
    return next((name for name, patterns in FORMATS.items() if pair == patterns), None)


def read_format(home: Path, *, included: bool | None = None) -> str | None:
    if included is None:
        included = includes_override(home)
    if not included:
        return None
    try:
        return _match(_read(home / _INCLUDE, finite_numbers=True))
    except (OSError, ValueError, RecursionError):
        return None


def _write_format(home: Path, name: str) -> dict:
    if not includes_override(home):
        raise ValueError(ABSENT)
    path = home / _INCLUDE
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(_INVALID)
        value = _read(path, finite_numbers=True)
    except (FileNotFoundError, _MalformedDocument):
        value = None
    clock = value.get("clock") if isinstance(value, dict) else None
    if not isinstance(clock, dict) or not all(isinstance(clock.get(key), str) for key in ("format", "format-alt")):
        clock = {}
        value = {"clock": clock}
    result = {"time_format": name, "waybar_reload": "unchanged", "commands": []}
    if _match(value) == name:
        return dict(result, changed=False)
    primary, alt = FORMATS[name]
    clock.update({"format": primary, "format-alt": alt})
    # Escaped lone surrogates can survive json.loads. Escape those code
    # points again without escaping the clock glyph or other valid Unicode.
    document = json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False)
    payload = (document + "\n").encode("utf-8", errors="backslashreplace")

    def reload_bar():
        argv = ["/usr/bin/pkill", "-USR2", "-u", str(os.geteuid()), "-x", "waybar"]
        attempt = subprocess.run(argv, capture_output=True, timeout=3, check=False)
        result["commands"].append({"argv": argv, "returncode": attempt.returncode})
        if attempt.returncode not in (0, 1):
            raise ValueError("datetime-waybar-reload-failed")
        result["waybar_reload"] = "signalled" if attempt.returncode == 0 else "no-bar-signalled"

    def verify():
        if _match(_read(path, finite_numbers=True)) != name:
            raise ValueError("datetime-bar-clock-readback-failed")

    parts = write([{"path": path, "candidate": payload}], verify=verify, reload=reload_bar)
    return dict(result, changed=parts["changed"])


def set_format(home: Path, name: str) -> dict:
    if os.geteuid() != 0:
        return _write_format(home, name)
    # nidus must not traverse a writable home directory with root privileges.
    argv = ["/usr/sbin/runuser", "-u", "owner", "--", sys.executable, "-I", "-B",
            str(Path(__file__).resolve()), str(home), name]
    child = subprocess.run(argv, capture_output=True, text=True, timeout=8, check=False)
    try:
        result = json.loads(child.stdout)
    except ValueError as error:
        raise ValueError("datetime-bar-clock-write-failed") from error
    if not isinstance(result, dict):
        raise ValueError("datetime-bar-clock-write-failed")
    if child.returncode != 0 or result.get("ok") is not True:
        raise ValueError(result.get("firstMissingSignal", "datetime-bar-clock-write-failed"))
    return result


if __name__ == "__main__":
    try:
        if len(sys.argv) != 3 or sys.argv[2] not in FORMATS:
            raise ValueError("invalid:time_format")
        print(json.dumps(dict(_write_format(Path(sys.argv[1]), sys.argv[2]), ok=True)))
    except (OSError, ValueError, WriteError, RecursionError) as error:
        signal = str(error) if isinstance(error, ValueError) else "datetime-bar-clock-write-failed"
        print(json.dumps({"ok": False, "firstMissingSignal": signal}))
        sys.exit(1)

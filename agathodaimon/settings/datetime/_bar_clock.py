"""Read and write Waybar's owner-controlled clock include."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

# The writer can be run as owner from a privileged settings stop.
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agathodaimon._nidus.write import WriteError, write

FORMATS = {
    "24h": ("{:%H:%M}  ", "{:%A, %B %d, %Y (%R)} "),
    "12h": ("{:%I:%M %p}  ", "{:%A, %B %d, %Y (%I:%M %p)} "),
}
ABSENT = "unsupported:bar-clock-override-absent"
_INCLUDE = ".config/waybar/clock-override.json"
_JSON_STRING = r'"(?:\\.|[^"\\])*"'


def _read(path: Path):
    # Waybar reads JSONC, including comments and trailing commas. A quoted
    # comment marker (e.g. in a format string) is not a comment.
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK), encoding="utf-8") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("bar-clock-not-a-regular-file")
        text = stream.read(1024 * 1024 + 1)
    if len(text) > 1024 * 1024:
        raise ValueError("bar-clock-file-too-large")
    text = re.sub(_JSON_STRING + r"|//[^\r\n]*|/\*[\s\S]*?\*/",
                  lambda m: m[0] if m[0].startswith('"') else " ", text)
    text = re.sub(_JSON_STRING + r"|,(?=\s*[}\]])",
                  lambda m: m[0] if m[0].startswith('"') else "", text)
    return json.loads(text)


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


def read_format(home: Path) -> str | None:
    if not includes_override(home):
        return None
    try:
        return _match(_read(home / _INCLUDE))
    except (OSError, ValueError, RecursionError):
        return None


def _write_format(home: Path, name: str) -> dict:
    if not includes_override(home):
        raise ValueError(ABSENT)
    path = home / _INCLUDE
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("datetime-bar-clock-override-invalid")
        value = _read(path)
    except FileNotFoundError:
        value = {}
    if not isinstance(value, dict) or not isinstance(value.get("clock", {}), dict):
        raise ValueError("datetime-bar-clock-override-invalid")
    result = {"time_format": name, "waybar_reload": "unchanged", "commands": []}
    if _match(value) == name:
        return dict(result, changed=False)
    primary, alt = FORMATS[name]
    value.setdefault("clock", {}).update({"format": primary, "format-alt": alt})
    payload = (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()

    def reload_bar():
        argv = ["/usr/bin/pkill", "-USR2", "-u", str(os.geteuid()), "-x", "waybar"]
        attempt = subprocess.run(argv, capture_output=True, timeout=3, check=False)
        result["commands"].append({"argv": argv, "returncode": attempt.returncode})
        if attempt.returncode not in (0, 1):
            raise ValueError("datetime-waybar-reload-failed")
        result["waybar_reload"] = "signalled" if attempt.returncode == 0 else "no-bar-signalled"

    def verify():
        if _match(_read(path)) != name:
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

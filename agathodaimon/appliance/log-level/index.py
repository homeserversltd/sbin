"""Apply the body's hyalos level to the programs named in its dial seat."""
from __future__ import annotations

import json
import re
import stat
import subprocess
import time
from pathlib import Path

from agathodaimon import _deed, _envelope
from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon._nidus.refusal import BadRequest, Refusal, named_signal
from agathodaimon._nidus.unit import systemctl
from agathodaimon._nidus.write import WriteError, write
from agathodaimon.cli import _profile_for_crossing, _read_json_nofollow

_DIAL = "hyalos.dial.v1"
_DROPIN = "60-hyalos-level.conf"
_MODE = 0o644
_DIRECTIVES = {"Environment", "LogFilterPatterns", "ExecStart"}
# Leave room for the applied level in the deed's 48-character target.
_PROGRAM = re.compile(r"[A-Za-z0-9_.-]{1,40}")
_UNIT = re.compile(r"(?!-)(?:[A-Za-z0-9:_.@-]|\\x[0-9a-fA-F]{2})+")
_UNLOADED = {"not-found", "masked", "error", "bad-setting", "stub", "merged"}


def _level(value):
    if type(value) is int:
        return value, "envelope"
    try:
        config = _read_json_nofollow(appliance_runtime_path("config"))
    except (OSError, ValueError, RecursionError):
        config = None
    hyalos = config.get("hyalos") if isinstance(config, dict) else None
    value = hyalos.get("level") if isinstance(hyalos, dict) else None
    return (value, "config") if type(value) is int else (1, "default")


def _candidate(levels, level: int) -> bytes | None:
    if levels is None:
        return None
    if not isinstance(levels, dict):
        raise BadRequest("log-level-levels-invalid")
    selected = level
    while selected >= 1:
        row = levels.get(str(selected))
        if row is not None:
            if not isinstance(row, dict):
                raise BadRequest("log-level-setting-invalid")
            lines = row.get("dropin")
            if lines is not None:
                if not isinstance(lines, list):
                    raise BadRequest("log-level-setting-invalid")
                for line in lines:
                    name, sep, _ = line.partition("=") if isinstance(line, str) else ("", "", "")
                    if (name not in _DIRECTIVES or not sep or any(c in line for c in "\r\n\0")
                            or line.rstrip().endswith("\\")):
                        directive = name if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,63}", name) else None
                        raise BadRequest("log-level-directive-refused", directive)
                header = f"# hyalos level {level}: written by appliance/log-level; it leaves at level 1.\n[Service]\n"
                try:
                    return (header + "".join(line + "\n" for line in lines)).encode("utf-8")
                except UnicodeError:
                    raise BadRequest("log-level-setting-invalid") from None
            same_as = row.get("same_as")
            if same_as is not None:
                if type(same_as) is not int or not 1 <= same_as < selected:
                    raise BadRequest("log-level-same-as-invalid")
                selected = same_as
                continue
        selected -= 1
    return None


def _load_state(name: str) -> str | None:
    try:
        shown = systemctl("show", "-p", "LoadState", "--value", name)
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return None
    state = shown.stdout.strip()
    if state in _UNLOADED:
        return state
    if shown.returncode == 0:
        return "loaded" if state == "loaded" else "not-loaded"
    return None


def _directory_missing(path: Path) -> bool:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return True
    if not stat.S_ISDIR(mode):
        raise Refusal("log-level-dropin-directory-invalid")
    return False


def _readback(path: Path, candidate: bytes | None) -> None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        if candidate is None:
            return
    else:
        if (candidate is not None and stat.S_ISREG(mode) and stat.S_IMODE(mode) == _MODE
                and path.read_bytes() == candidate):
            return
    raise Refusal("log-level-readback-mismatch")


def _command_ok(*argv: str) -> bool:
    try:
        return systemctl(*argv).returncode == 0
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return False


def _apply_program(entry, level: int, units_dir: Path, answer: dict) -> None:
    started = time.monotonic()
    entry = entry if isinstance(entry, dict) else {}
    name = entry.get("program")
    name = name if isinstance(name, str) and _PROGRAM.fullmatch(name) else None
    row = {"program": name, "outcome": "refused", "units": [], "signal": "none"}
    answer["programs"].append(row)
    units = entry.get("units")
    units = [] if units is None else units
    if name is None or not isinstance(units, list) or any(
        not isinstance(unit, str) or len(unit) > 253 or unit in {".", ".."} or not _UNIT.fullmatch(unit)
        for unit in units
    ) or len(units) != len(set(units)):
        row["signal"] = "log-level-program-invalid"
        return

    takes = entry.get("takes")
    if takes is None:
        takes = "restart"
    try:
        if takes not in ("restart", "reload"):
            raise BadRequest("log-level-takes-invalid")
        candidate = _candidate(entry.get("levels"), level)
    except BadRequest as error:
        row["signal"] = error.args[0]
        if len(error.args) > 1:
            row["directive"] = error.args[1]
        row["units"] = [{"unit": unit, "outcome": "skipped", "why": row["signal"]} for unit in units]
        return

    loaded = {}
    for unit in units:
        state = _load_state(unit)
        unit_row = {"unit": unit, "outcome": "unchanged" if state == "loaded" else "skipped"}
        row["units"].append(unit_row)
        if state == "loaded":
            path = units_dir / (unit + ".d") / _DROPIN
            loaded[path] = unit_row
        else:
            unit_row["why"] = state or "log-level-load-state-failed"
            if state is None:
                row.update(outcome="failed", signal=unit_row["why"])
    answer["could_change_to"]["programs"].append({
        "program": name, "change": "remove" if candidate is None else "write",
        "takes": takes, "units": [unit_row["unit"] for unit_row in loaded.values()],
    })
    if row["outcome"] == "failed":
        return

    missing = []
    made = []
    commands = []

    def check():
        for directory in missing:
            directory.mkdir(mode=0o755)
            made.append(directory)
            directory.chmod(0o755)

    def reload():
        manager_ok = _command_ok("daemon-reload")
        commands.append({"action": "daemon-reload", "ok": manager_ok})
        if not manager_ok:
            raise Refusal("log-level-daemon-reload-failed")
        failed = False
        for unit_row in loaded.values():
            unit = unit_row["unit"]
            ok = _command_ok(takes, unit)
            commands.append({"action": takes, "unit": unit, "ok": ok})
            failed |= not ok
        if failed:
            raise Refusal(f"log-level-{takes}-failed")

    def readback():
        for path in loaded:
            _readback(path, candidate)

    try:
        if loaded and _directory_missing(units_dir):
            raise Refusal("log-level-unit-root-missing")
        for path in loaded:
            if _directory_missing(path.parent) and candidate is not None:
                missing.append(path.parent)
        parts = write([{"path": path, "candidate": candidate, "mode": _MODE} for path in loaded],
                      check=check, reload=reload, readback=readback)
    except WriteError as error:
        parts = error.parts
        phase = parts["final_receipt"]["firstMissingSignal"]
        row.update(outcome="failed", signal=named_signal(error.cause, "log-level-" + phase.removesuffix("-failed")))
    except (OSError, Refusal) as error:
        row.update(outcome="failed", signal=named_signal(error, "log-level-dropin-directory"))
        return
    else:
        row["outcome"] = "changed" if parts["changed"] else "unchanged"

    attempt = parts["attempt"]
    steps = attempt["steps"]
    replaced = {step["path"] for step in steps if step["step"] == "replace" and step["outcome"] == "ok"}
    restored = {step["path"] for step in steps if step["step"] == "restore" and step["outcome"] == "ok"}
    changed = replaced - restored
    for path, unit_row in loaded.items():
        if str(path) in changed:
            unit_row["outcome"] = "removed" if candidate is None else "written"
        elif str(path) in replaced:
            unit_row["why"] = "restored"
    answer["observed"]["files"].extend(parts["observed"])
    answer["attempt"]["attempted"] |= attempt["attempted"]
    answer["attempt"]["programs"].append({"program": name, "steps": steps, "commands": commands})
    answer["mutationPerformed"] |= bool(replaced or made)
    answer["changed"] |= bool(changed)
    if changed:
        _deed.send("sbin", "log-level", row["outcome"] == "changed",
                   target=f"{name}.level-{level}", duration_ms=int((time.monotonic() - started) * 1000),
                   signal=row["signal"], outcome=row["outcome"])


def _apply(request, answer: dict) -> str:
    level, source = _level(request.payload.get("level"))
    appliance, profile_ok = _profile_for_crossing()
    answer.update(level=level, appliance=appliance)
    answer["observed"] = {"level_source": source, "appliance": appliance, "files": []}
    answer["could_change_to"] = {"level": level, "programs": []}
    if not 1 <= level <= 5:
        return "log-level-out-of-range"
    if not profile_ok:
        return "log-level-profile-unavailable"
    try:
        path = appliance_runtime_path("seats") / (_DIAL + ".json")
        if not stat.S_ISREG(path.lstat().st_mode):
            return "log-level-seat-absent"
        seat = _read_json_nofollow(path)
    except (OSError, ValueError, RecursionError):
        return "log-level-seat-absent"
    if not isinstance(seat, dict) or seat.get("schema") != _DIAL:
        return "log-level-seat-foreign"

    answer["observed"]["dial"] = _DIAL
    appliances = seat.get("appliances")
    section = appliances.get(appliance) if isinstance(appliances, dict) else None
    programs = section.get("programs") if isinstance(section, dict) else None
    if programs is None or programs == []:
        answer["observed"]["signal"] = "log-level-no-programs"
        return "none"
    if not isinstance(programs, list):
        return "log-level-programs-invalid"
    units_dir = appliance_runtime_path("units")
    for entry in programs:
        _apply_program(entry, level, units_dir, answer)
    return next((row["signal"] for row in answer["programs"] if row["signal"] != "none"), "none")


def main(argv=None) -> int:
    answer = {"level": None, "appliance": None, "programs": [], "changed": False,
              "mutationPerformed": False, "observed": None, "could_change_to": None,
              "attempt": {"attempted": False, "programs": []}}
    request = None
    try:
        request = _envelope.read_fields("level")
    except (_envelope.EnvelopeError, RecursionError):
        signal = "log-level-request-invalid"
    else:
        signal = _apply(request, answer)
    final = {"ok": signal == "none", "firstMissingSignal": signal}
    answer.update(final, final_receipt=final)
    print(json.dumps(_envelope.attach(answer, request) if request else answer, separators=(",", ":")))
    return 0 if answer["ok"] else 1

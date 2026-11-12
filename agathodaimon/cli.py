#!/usr/bin/env python3
from __future__ import annotations
import ast
import copy
import difflib
import importlib.util
import getpass
import contextlib
from datetime import datetime, timezone
import time
import json
import os
import re
import signal as signal_module
import stat
import sys
import warnings
from pathlib import Path
from io import BytesIO, StringIO, TextIOWrapper

class _EnvelopeStdin(StringIO):
    @property
    def buffer(self):
        return BytesIO(self.getvalue().encode("utf-8"))


ROOT = Path(__file__).resolve().parent
if str(ROOT.parent) not in sys.path: sys.path.insert(0, str(ROOT.parent))
from agathodaimon import _envelope
sys.modules["_envelope"] = _envelope
from agathodaimon._envelope import appliance_runtime_path
from agathodaimon.carapace import normalize_profile
from agathodaimon import _load_trace
from agathodaimon._seat import ForeignSeat, read_seats
_stamp_target = None
_stamp_seat = None
_front_args = []
_front_dry_run = False

def _stamp_receipt(receipt, target):
    if (not target or not isinstance(receipt, dict)
            or not isinstance(receipt.get("ok"), bool)
            or receipt.get("schema") == "caduceus.chord.receipt.v1"):
        return receipt
    receipt["schema"] = "caduceus.staff.receipt.v1"
    parts = target.split("/")
    receipt.setdefault("stop", {"noun": "/".join(parts[:-1]) if len(parts) > 1 else parts[0],
                                "verb": parts[-1] if len(parts) > 1 else ""})
    receipt.setdefault("observed", None)
    receipt.setdefault("could_change_to", None)
    receipt.setdefault("attempt", None)
    receipt.setdefault("final_receipt", {"ok": receipt["ok"],
                                         "firstMissingSignal": receipt.get("firstMissingSignal")})
    if _stamp_seat is not None:
        receipt.setdefault("seat", _stamp_seat)
    return receipt

ALIASES = {"cert": ("network", "cert"), "vault": ("storage", "vault"), "upload": ("storage", "upload"), "nas": ("storage", "nas"), "backup": ("storage", "backup"), "forgejo": ("storage", "backup", "forgejo"), "time": ("settings", "datetime")}
SERVICE_ALIASES = {
    "service-control": ("portals", "service-control"),
    "staff-daemon": ("python", "staff-daemon"),
    "disk-doors": ("storage", "disk-doors"),
    "ssh-exposure": ("settings", "ssh"),
    "desktop-cache": ("settings", "default-apps", "desktop-cache"),
    "rebis-profile-retire": ("update", "profile-retire"),
}

def _index(path: Path) -> dict:
    index = path / "index.json"
    if not index.is_file(): return {}
    return json.loads(index.read_text(encoding="utf-8"))

def _mutation_allowed(path: Path) -> bool | None:
    try:
        declaration = _index(path)
    except (OSError, UnicodeError, ValueError, RecursionError):
        return None
    value = declaration.get("mutation_allowed") if isinstance(declaration, dict) else None
    return value if isinstance(value, bool) else None

def _children(path: Path) -> list[str]: return list(_index(path).get("children", []))

def _load(path: Path):
    rel = path.relative_to(ROOT); safe = "agathodaimon.face_" + "_".join(rel.parts[:-1])
    spec = importlib.util.spec_from_file_location(safe, path)
    if spec is None or spec.loader is None: raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec); module.__package__ = "agathodaimon"; sys.modules[safe] = module; spec.loader.exec_module(module); return module

def _help_result(path: Path) -> dict:
    declaration = _index(path)
    source = path / "index.py"
    kind = "chord" if "serve" in declaration and not source.is_file() else "stop"
    doc = ""
    fields = []
    if source.is_file():
        tree = ast.parse(source.read_text(encoding="utf-8"))
        doc = (ast.get_docstring(tree) or "").split("\n\n", 1)[0]
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            callee = node.func.id if isinstance(node.func, ast.Name) else (
                node.func.attr if isinstance(node.func, ast.Attribute) else None
            )
            if callee == "read_fields":
                for argument in node.args:
                    if isinstance(argument, ast.Constant) and isinstance(argument.value, str) and argument.value not in fields:
                        fields.append(argument.value)
            for keyword in node.keywords:
                if keyword.arg != "known_fields":
                    continue
                try:
                    names = ast.literal_eval(keyword.value)
                except (ValueError, TypeError, SyntaxError):
                    continue
                if isinstance(names, (tuple, list)):
                    for name in names:
                        if isinstance(name, str) and name not in fields:
                            fields.append(name)
        if any(isinstance(node, (ast.Assign, ast.AnnAssign)) and
               any(isinstance(target, ast.Name) and target.id == "ACTIONS" for target in
                   (node.targets if isinstance(node, ast.Assign) else [node.target]))
               for node in tree.body):
            kind = "fused"
    result = {"schema": "agathodaimon.cli.help.v1", "path": path.relative_to(ROOT).as_posix(),
              "kind": kind, "description": doc, "ok": True, "mutationPerformed": False,
              "payload_fields": [{"name": name,
                                  "meaning": doc if re.search(r"\b" + re.escape(name) + r"\b", doc, re.IGNORECASE) else None}
                                 for name in fields]}
    if kind == "chord":
        result["stages"] = [stage.get("stage_id") for stage in declaration.get("serve", []) + declaration.get("rescue", []) + declaration.get("finally", [])]
        if declaration.get("children"):
            result["children"] = declaration["children"]
    return result


def _help(path: Path) -> None:
    print(json.dumps(_help_result(path)))

def _slash_target(raw_path: str) -> Path | None:
    parts = tuple(part for part in raw_path.split("/") if part)
    if not parts or any(part in {".", ".."} for part in parts):
        return None
    path = ROOT
    for part in parts:
        if part not in _children(path):
            return None
        path /= part
    target = path / "index.py"
    if target.is_file():
        return target
    return path if "serve" in _index(path) else None


def _shelf_version() -> str:
    for candidate in (ROOT.parent / "VERSION", ROOT / "VERSION"):
        try:
            if candidate.is_file():
                return candidate.read_text(encoding="utf-8").strip()
        except (OSError, UnicodeError):
            continue
    # The content seat is read-only. The override permits isolated observations.
    git_dir = Path(os.environ.get("AGATHODAIMON_CONTENT_SEAT", "/opt/sbin/source")) / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref = head[5:]
            if not ref.startswith("refs/") or any(part in {"", ".", ".."} for part in ref.split("/")):
                return "unknown"
            try:
                head = (git_dir / ref).read_text(encoding="utf-8").strip()
            except FileNotFoundError:
                head = ""
                try:
                    with (git_dir / "packed-refs").open(encoding="utf-8") as packed:
                        for line in packed:
                            fields = line.split()
                            if len(fields) == 2 and fields[1] == ref:
                                head = fields[0]
                                break
                except (OSError, UnicodeError):
                    pass
        if re.fullmatch(r"[0-9a-fA-F]{40}", head):
            return "sha-" + head.lower()
    except (OSError, UnicodeError, ValueError):
        pass
    return "unknown"


def _fresh_envelope(band: str) -> dict:
    stamp = datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    version = _shelf_version()
    return {"schema": "caduceus.staff.v1", "intent_id": "agathodaimon-" + band.replace("/", "-") + "-" + stamp,
            "transition": band, "origin_of_intent": "near", "version": version, "timestamp": stamp, "payload": {}}


_HAND_SECRET_NAMES = {"pin", "oldPin", "newPin", "key", "password", "passphrase", "token", "secret", "oldPassword", "newPassword", "currentPassword", "vaultPassword", "devicePasswords"}


def _hand_options(words: list[str]) -> dict:
    result = {}
    repeated = set()
    i = 0
    while i < len(words):
        word = words[i]
        if not word.startswith("--") or len(word) == 2:
            raise ValueError("expected a long option")
        name, equal, value = word[2:].partition("=")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", name) or name in {"action", "op", "operation", "verb", "command", "mode", "args"} or name in _HAND_SECRET_NAMES:
            raise ValueError("invalid or forbidden long option")
        if not equal:
            if name == "dry-run" or i + 1 >= len(words) or words[i + 1].startswith("--"):
                value = "true"
            else:
                i += 1
                value = words[i]
        try:
            typed = json.loads(value, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid JSON constant")))
            if isinstance(typed, str):
                typed = value
        except (ValueError, json.JSONDecodeError):
            typed = value
        if name in result:
            if name not in repeated:
                result[name] = [result[name]]
                repeated.add(name)
            result[name].append(typed)
        else:
            result[name] = typed
        i += 1
    return result


def _contains_secret_name(value):
    if isinstance(value, dict):
        return any(key in _HAND_SECRET_NAMES or _contains_secret_name(child) for key, child in value.items())
    if isinstance(value, list):
        return any(_contains_secret_name(child) for child in value)
    return False


# The walker's part-name literals are serve, rescue, and finally.
_CHORD_PART_NAMES = frozenset({"serve", "rescue", "finally"})


class _ChordError(ValueError):
    pass


def _references(value):
    if isinstance(value, dict):
        if "$ref" in value:
            if len(value) != 1 or not isinstance(value["$ref"], str):
                raise _ChordError("chord-ref-unresolved")
            yield value["$ref"]
        else:
            for child in value.values():
                yield from _references(child)
    elif isinstance(value, list):
        for child in value:
            yield from _references(child)


def _validate_chord(declaration: dict):
    serve = declaration.get("serve")
    rescue = declaration.get("rescue", [])
    final = declaration.get("finally", [])
    if not all(isinstance(stages, list) for stages in (serve, rescue, final)):
        raise _ChordError("chord-stage-invalid")
    seen = set()
    serve_ids = set()
    settles_declared = False
    for phase, stages in (("serve", serve), ("rescue", rescue), ("finally", final)):
        for stage in stages:
            if not isinstance(stage, dict):
                raise _ChordError("chord-stage-invalid")
            if "rust" in stage or "native" in stage:
                raise _ChordError("chord-stage-not-snake")
            sid, snake = stage.get("stage_id"), stage.get("snake")
            target = _slash_target(snake) if isinstance(snake, str) and snake else None
            if not isinstance(sid, str) or not sid or sid in seen or target is None or not target.is_file():
                raise _ChordError("chord-stage-invalid")
            if not isinstance(stage.get("arguments", {}), dict) or not isinstance(stage.get("required", True), bool):
                raise _ChordError("chord-stage-invalid")
            if "settles_on" in stage:
                settles_on = stage["settles_on"]
                if (phase != "serve" or settles_declared or not isinstance(settles_on, str)
                        or re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*", settles_on) is None):
                    raise _ChordError("chord-stage-invalid")
                settles_declared = True
            deps = stage.get("depends_on", [])
            if not isinstance(deps, list) or any(not isinstance(dep, str) or dep not in (serve_ids if phase == "finally" else seen) for dep in deps):
                raise _ChordError("chord-stage-invalid")
            if phase == "rescue":
                targets = stage.get("on_refusal_of")
                if not isinstance(targets, list) or not targets or any(not isinstance(target, str) or target not in serve_ids for target in targets):
                    raise _ChordError("chord-stage-invalid")
            deadline = stage.get("deadline_seconds")
            if deadline is not None and (isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not 1 <= deadline <= 600):
                raise _ChordError("chord-stage-deadline-invalid")
            for ref in _references(stage.get("arguments", {})):
                parts = ref.split(".")
                if parts[-1] in _HAND_SECRET_NAMES:
                    raise _ChordError("chord-ref-secret")
                if len(parts) >= 3 and parts[:2] == ["request", "payload"] and all(parts[2:]):
                    continue
                if len(parts) >= 4 and parts[0] == "stages" and parts[2] == "receipt" and parts[1] in seen and all(parts[3:]):
                    continue
                raise _ChordError("chord-ref-unresolved")
            seen.add(sid)
            if phase == "serve":
                serve_ids.add(sid)
    return serve, rescue, final


def _resolve_arguments(value, request, completed, allow_unrun=False):
    if isinstance(value, dict):
        if "$ref" in value:
            parts = value["$ref"].split(".")
            if parts[0] == "request":
                current = {"request": request}
            else:
                if allow_unrun and (parts[1] not in completed or completed[parts[1]]["outcome"] == "stage-skipped"):
                    return None
                current = {"stages": completed}
            for part in parts:
                if not isinstance(current, dict) or part not in current:
                    raise _ChordError("chord-ref-unresolved")
                current = current[part]
            return copy.deepcopy(current)
        return {key: _resolve_arguments(child, request, completed, allow_unrun) for key, child in value.items()}
    if isinstance(value, list):
        return [_resolve_arguments(child, request, completed, allow_unrun) for child in value]
    return value


def _stage_changed(receipt):
    for key in ("changed", "mutationPerformed", "mutation_performed"):
        value = receipt.get(key)
        if isinstance(value, bool):
            return value
    return False


def _deed_target(routine_id):
    target = routine_id.replace("/", ".")
    return target if re.fullmatch(r"[A-Za-z0-9_.-]{1,48}", target) else "chord"


def _stage_word(row, mutating):
    if row["outcome"] == "stage-skipped":
        return "skipped"
    if row["outcome"] == "stage-refused":
        return "refused"
    if not mutating:
        return "completed"
    receipt = row.get("receipt")
    return "changed" if isinstance(receipt, dict) and _stage_changed(receipt) else "kept"


def _stage_deed(routine_id, row, word, signal, duration_ms):
    from agathodaimon._deed import send
    send("sbin", row["stage_id"], word != "refused", target=_deed_target(routine_id),
         duration_ms=duration_ms,
         signal=signal or "operation-failed", outcome=word)


def _chord_deed(routine_id, rows, mutating, ok, changed, signal, started):
    from agathodaimon._deed import send
    word = "refused" if not ok else "changed" if changed else "kept"
    stages = [[row["stage_id"], _stage_word(row, is_write)]
              for row, is_write in zip(rows, mutating)]
    return send("sbin", "chord", ok, target=_deed_target(routine_id),
                duration_ms=int((time.monotonic() - started) * 1000),
                signal=signal, outcome=word, stages=stages)


def _walk_chord(path: Path, envelope: dict) -> int:
    interrupted = [False]
    def mark_interrupted(signum, frame):
        interrupted[0] = True
    previous = {sig: signal_module.getsignal(sig) for sig in (signal_module.SIGTERM, signal_module.SIGINT)}
    try:
        for sig in previous:
            signal_module.signal(sig, mark_interrupted)
        return _walk_chord_inner(path, envelope, interrupted)
    finally:
        for sig, handler in previous.items():
            signal_module.signal(sig, handler)


def _walk_chord_inner(path: Path, envelope: dict, interrupted: list[bool]) -> int:
    started = time.monotonic()
    routine_id = path.relative_to(ROOT).as_posix()
    rows = []
    stage_mutating = []
    stage_durations = []
    stage_refusals = []
    completed = {}
    failed = None
    signal = "none"
    changed = False
    payload = envelope.get("payload")
    dry_run = isinstance(payload, dict) and payload.get("dry-run") is True
    mutating_chord = _mutation_allowed(path) is not False

    def preflight_refusal(reason):
        if mutating_chord and not dry_run:
            _chord_deed(routine_id, [], [], False, False, reason, started)

    from agathodaimon._envelope import _pin_bearing_exousia, _redact_declared, _redact_pin_carriers
    request = json.dumps(_redact_declared(_redact_pin_carriers(envelope), _HAND_SECRET_NAMES), separators=(",", ":"))
    if _pin_bearing_exousia(envelope):
        preflight_refusal("chord-secret-carrier-refused")
        print(json.dumps({"schema": "caduceus.chord.receipt.v1", "ok": False, "routine_id": routine_id,
                          "request": request, "stages": [], "failedStage": None, "firstMissingSignal": "chord-secret-carrier-refused"}))
        return 1
    try:
        serve, rescue, final = _validate_chord(_index(path))
    except (OSError, ValueError, _ChordError) as exc:
        reason = str(exc) if isinstance(exc, _ChordError) else "chord-stage-invalid"
        preflight_refusal(reason)
        print(json.dumps({"schema": "caduceus.chord.receipt.v1", "ok": False, "routine_id": routine_id,
                          "request": request, "stages": [], "failedStage": None, "firstMissingSignal": reason}))
        return 1
    if dry_run:
        for stage in serve + rescue + final:
            target = _slash_target(stage["snake"])
            if _index(target.parent).get("dry-run") is not True:
                print(json.dumps({"schema": "caduceus.chord.receipt.v1", "ok": False, "routine_id": routine_id,
                                  "request": request, "stages": [], "failedStage": None,
                                  "firstMissingSignal": "chord-dry-run-undeclared-stage",
                                  "firstMissingField": stage["stage_id"]}))
                return 1
    blocked = False
    settled_by = None
    last_executed = None

    def consume_between_stages():
        nonlocal blocked, failed, signal, settled_by
        if not interrupted[0] or last_executed is None:
            return
        interrupted[0] = False
        previous_row, previous_phase = last_executed
        previous_row["outcome"] = "stage-refused"
        previous_row["firstMissingSignal"] = "chord-interrupted"
        if settled_by == previous_row["stage_id"]:
            settled_by = None
        if failed is None:
            failed, signal = previous_row["stage_id"], "chord-interrupted"
        if previous_phase == "serve":
            blocked = True

    for phase, stages in (("serve", serve), ("rescue", rescue), ("finally", final)):
        for stage in stages:
            consume_between_stages()
            sid, band = stage["stage_id"], stage["snake"]
            stage_started = time.monotonic()
            declared_target = _slash_target(band)
            is_write = (declared_target is None or
                        _mutation_allowed(declared_target.parent if declared_target.is_file() else declared_target) is not False)
            stage_mutating.append(is_write)
            stage_durations.append(0)
            stage_refusals.append(None)
            row = {"stage_id": sid, "transition": band, "outcome": "stage-skipped", "arguments": {}, "receipt": None}
            rows.append(row)
            if phase == "serve" and settled_by is not None and not blocked:
                row["skipped_by"] = "settled"
                completed[sid] = row
                stage_durations[-1] = int((time.monotonic() - stage_started) * 1000)
                continue
            rescue_untriggered = phase == "rescue" and (settled_by is not None or not any(
                completed.get(dep, {}).get("outcome") == "stage-refused" for dep in stage["on_refusal_of"]
            ))
            dependency_blocked = any(
                completed.get(dep, {}).get("outcome") != "stage-completed"
                and not (phase == "finally" and completed.get(dep, {}).get("firstMissingSignal") == "chord-interrupted")
                for dep in stage.get("depends_on", [])
            )
            if (phase == "serve" and blocked) or rescue_untriggered or dependency_blocked:
                completed[sid] = row
                stage_durations[-1] = int((time.monotonic() - stage_started) * 1000)
                continue
            refusal = None
            stage_target = None
            answered_stop = None
            printed_stop = False
            try:
                arguments = _resolve_arguments(stage.get("arguments", {}), envelope, completed, phase != "serve")
                row["arguments"] = arguments
                stage_envelope = copy.deepcopy(envelope)
                payload = stage_envelope.get("payload")
                stage_envelope["payload"] = {**(payload if isinstance(payload, dict) else {}), **arguments}
                stage_envelope["routine"] = {"request": _redact_declared(envelope, _HAND_SECRET_NAMES), "routine_id": routine_id,
                                             "stage": {"stage_id": sid, "arguments": _redact_declared(arguments, _HAND_SECRET_NAMES)}}
                stdout = StringIO()
                before = time.monotonic()
                stage_target = _slash_target(band)
                if stage_target is None:
                    raise _ChordError("chord-stage-invocation-failed")
                if interrupted[0] and last_executed is not None:
                    consume_between_stages()
                    if phase == "serve" and blocked:
                        completed[sid] = row
                        stage_durations[-1] = int((time.monotonic() - stage_started) * 1000)
                        continue
                if interrupted[0]:
                    raise _ChordError("chord-interrupted")
                last_executed = (row, phase)
                with contextlib.redirect_stdout(stdout):
                    try:
                        code = _invoke_envelope(stage_target, stage_envelope)
                    except SystemExit as exc:
                        code = exc.code if isinstance(exc.code, int) else 1
                elapsed = time.monotonic() - before
                try:
                    receipt = json.loads(stdout.getvalue())
                    if not isinstance(receipt, dict):
                        raise ValueError("not an object")
                    answered_stop = receipt.get("stop")
                    printed_stop = "stop" in receipt
                    receipt = _stamp_receipt(receipt, band)
                    row["receipt"] = receipt
                except (ValueError, json.JSONDecodeError):
                    receipt = None
                    refusal = "chord-stage-receipt-invalid"
                if stage.get("deadline_seconds") is not None and elapsed > stage["deadline_seconds"]:
                    refusal = "chord-stage-deadline-exceeded"
                if refusal is None and isinstance(receipt, dict):
                    parts = band.split("/")
                    matches = (not printed_stop or
                               (isinstance(answered_stop, dict)
                                and answered_stop.get("noun") == ("/".join(parts[:-1]) if len(parts) > 1 else parts[0])
                                and answered_stop.get("verb") == (parts[-1] if len(parts) > 1 else "")))
                    if not matches:
                        refusal = "chord-stage-receipt-schema-mismatch"
                if refusal is None and (code != 0 or receipt.get("ok") is False):
                    refusal = receipt.get("firstMissingSignal") or "chord-stage-refused"
                if receipt is not None and _stage_changed(receipt) is True:
                    changed = True
            except _ChordError as exc:
                refusal = str(exc)
            except Exception:
                refusal = "chord-stage-invocation-failed"
            was_interrupted = interrupted[0]
            if was_interrupted:
                interrupted[0] = False
                refusal = "chord-interrupted"
                row["firstMissingSignal"] = refusal
            row["outcome"] = "stage-refused" if refusal else "stage-completed"
            if phase == "serve" and not refusal and "settles_on" in stage:
                value = row["receipt"]
                for part in stage["settles_on"].split("."):
                    value = value.get(part) if isinstance(value, dict) else None
                if value is True:
                    settled_by = sid
            stage_durations[-1] = int((time.monotonic() - stage_started) * 1000)
            stage_refusals[-1] = refusal
            if refusal and (was_interrupted or phase == "finally" or stage.get("required", True)) and failed is None:
                failed, signal = sid, refusal
            if refusal and phase == "serve" and (was_interrupted or stage.get("required", True)):
                blocked = True
            completed[sid] = row
            last_executed = (row, phase)
    consume_between_stages()
    if not dry_run:
        for row, is_write, duration_ms, refusal in zip(rows, stage_mutating, stage_durations, stage_refusals):
            if is_write:
                _stage_deed(routine_id, row, _stage_word(row, True),
                            row.get("firstMissingSignal") or refusal, duration_ms)
    ok = (failed is None and
          all(not stage.get("required", True) or row["outcome"] == "stage-completed"
              or (row["outcome"] == "stage-skipped" and row.get("skipped_by") == "settled")
              for stage, row in zip(serve, rows[:len(serve)])) and
          all(row["outcome"] == "stage-completed" for row in rows[len(serve) + len(rescue):]))
    if not dry_run and _mutation_allowed(path) is not False:
        try:
            logged = _chord_deed(routine_id, rows, stage_mutating, ok, changed, signal, started)
        except (OSError, ValueError):
            logged = False
        if not logged and changed:
            ok = False
            if failed is None:
                signal = "chord-deed-log-unavailable"
    for row in rows:
        row["arguments"] = _redact_declared(row["arguments"], _HAND_SECRET_NAMES)
        if isinstance(row["receipt"], dict):
            row["receipt"] = _redact_declared({key: value for key, value in row["receipt"].items()
                                               if key not in {"raw_envelope", "envelope"}}, _HAND_SECRET_NAMES)
    answer = {"schema": "caduceus.chord.receipt.v1", "ok": ok, "routine_id": routine_id,
              "request": request, "stages": rows, "failedStage": failed, "firstMissingSignal": signal, "changed": changed}
    if settled_by is not None:
        answer["settledBy"] = settled_by
    print(json.dumps(answer, separators=(",", ":")))
    return 0 if ok else 1


def _dry_run_admits(path: Path, envelope: dict | None, argv: list[str] | None = None) -> bool:
    global _front_dry_run
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    args = payload.get("args") if isinstance(payload, dict) else None
    candidates = (args if isinstance(args, list) else []) + (argv if isinstance(argv, list) else [])
    _front_dry_run = _front_dry_run or (isinstance(payload, dict) and payload.get("dry-run") is True) or any(
        arg in ("--dry-run", "--dry-run=true") for arg in candidates if isinstance(arg, str)
    )
    if not isinstance(payload, dict) or "dry-run" not in payload:
        args = payload.get("args") if isinstance(payload, dict) else None
        candidates = (args if isinstance(args, list) else []) + (argv if isinstance(argv, list) else [])
        if not any(
            isinstance(arg, str) and (arg == "--dry-run" or arg.startswith("--dry-run="))
            for arg in candidates
        ):
            return True
        declaration = _index(path if path.is_dir() else path.parent)
        if declaration.get("dry-run") is True and declaration.get("hand") != "envelope":
            return True
        signal = ("agathodaimon-dry-run-invalid" if declaration.get("dry-run") is True
                  else "agathodaimon-dry-run-undeclared")
        _front_answer(signal, "dry-run", path, error=signal)
        return False
    declaration = _index(path if path.is_dir() else path.parent)
    if path.is_dir() and "serve" in declaration and payload["dry-run"] is True:
        return True
    if declaration.get("dry-run") is not True:
        signal = "agathodaimon-dry-run-undeclared"
    elif not isinstance(payload["dry-run"], bool):
        signal = "agathodaimon-dry-run-invalid"
    else:
        return True
    _front_answer(signal, "dry-run", path, error=signal)
    return False


def _dry_run_argv(envelope: dict | None, argv: list[str] | None) -> list[str] | None:
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    if not isinstance(payload, dict) or "dry-run" not in payload:
        return argv
    if argv is None:
        args = payload.get("args")
        argv = list(args) if isinstance(args, list) and all(isinstance(arg, str) for arg in args) else []
    else:
        argv = list(argv)
    argv = [arg for arg in argv if arg not in ("--dry-run=true", "--dry-run=false")]
    if payload["dry-run"] and "--dry-run" not in argv:
        argv.append("--dry-run")
    return argv


def _invoke_envelope(path: Path, envelope: dict, raw_envelope: str | None = None, argv: list[str] | None = None) -> int:
    if not _dry_run_admits(path, envelope, argv):
        return 2
    if path.is_dir():
        return _walk_chord(path, envelope)
    if _index(path.parent).get("hand") == "envelope":
        original_stdin = sys.stdin
        output = StringIO()
        try:
            sys.stdin = _EnvelopeStdin(raw_envelope if raw_envelope is not None else json.dumps(envelope))
            with contextlib.redirect_stdout(output):
                with _load_trace.span("agathodaimon.staff.import", source_state="dynamic-module"):
                    mod = _load(path)
                fn = getattr(mod, "main", None)
                if fn is None:
                    raise ValueError("missing main")
                code = int(fn([]) or 0)
        except (Exception, SystemExit):
            print(json.dumps({"schema": "agathodaimon.cli.envelope.v1", "ok": False,
                              "error": "agathodaimon-envelope-invocation-failed",
                              "firstMissingSignal": "agathodaimon-envelope-invocation-failed"}, separators=(",", ":")))
            return 2
        finally:
            sys.stdin = original_stdin
        print(output.getvalue(), end="")
        return code
    argv = _dry_run_argv(envelope, argv)
    with _load_trace.span("agathodaimon.staff.import", source_state="dynamic-module"):
        mod = _load(path)
    fn = getattr(mod, "main", None)
    if fn is None:
        print(json.dumps({"schema":"agathodaimon.cli.read.v1","path":str(path.parent.relative_to(ROOT)),"ok":True,"envelope":envelope,"mutationPerformed":False}))
        return 0
    original_stdin = sys.stdin
    try:
        sys.stdin = _EnvelopeStdin(raw_envelope if raw_envelope is not None else json.dumps(envelope))
        if argv is not None:
            try:
                return int(fn(list(argv)) or 0)
            except TypeError as exc:
                if "positional argument" not in str(exc) and "positional arguments" not in str(exc):
                    raise
                return int(fn() or 0)
        payload = envelope.get("payload")
        args = payload.get("args") if isinstance(payload, dict) else None
        if isinstance(args, list) and all(isinstance(arg, str) for arg in args):
            return int(fn(list(args)) or 0)
        try:
            return int(fn([]) or 0)
        except SystemExit:
            transition = envelope.get("transition")
            if not isinstance(transition, str):
                raise
            command = transition.rstrip("/").rsplit("/", 1)[-1]
            return int(fn([command]) or 0)
        except Exception as exc:
            print(json.dumps({"schema": "agathodaimon.cli.envelope.v1", "ok": False, "error": str(exc), "mutationPerformed": False}))
            return 1
    finally:
        sys.stdin = original_stdin

_CROSSING_SCHEMA = "appliance.crossings.v1"
_CROSSING_PART = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_CROSSING_ROUTE_SEGMENT = r"(?:[a-z0-9][a-z0-9_.-]*|:[a-z][a-z0-9_]*)"
_CROSSING_API_ROUTE = re.compile(
    rf"^/api/v1/{_CROSSING_ROUTE_SEGMENT}(?:/{_CROSSING_ROUTE_SEGMENT})*$"
)
_CROSSING_ADMIN_ROUTE_SEGMENT = rf"(?:{_CROSSING_ROUTE_SEGMENT}|[{{][a-z][a-z0-9_]*[}}])"
_CROSSING_ADMIN_API_ROUTE = re.compile(
    rf"^(?:POST|PUT|PATCH|DELETE) /api/v1/{_CROSSING_ADMIN_ROUTE_SEGMENT}(?:/{_CROSSING_ADMIN_ROUTE_SEGMENT})*$"
)
_CROSSING_JSON_LIMIT = 1024 * 1024


def _read_json_nofollow(path: Path):
    """Read one bounded regular JSON file without following path symlinks."""
    parts = path.parts
    if not path.is_absolute() or len(parts) < 2 or any(part in {".", ".."} for part in parts):
        raise OSError("unsafe JSON path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open("/", directory_flags)
    file_fd = None
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    try:
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _CROSSING_JSON_LIMIT:
            raise OSError("JSON source is not a bounded regular file")
        raw = bytearray()
        while len(raw) <= _CROSSING_JSON_LIMIT:
            block = os.read(file_fd, min(65536, _CROSSING_JSON_LIMIT + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > _CROSSING_JSON_LIMIT:
            raise OSError("JSON source exceeds size limit")
        return json.loads(raw.decode("utf-8"))
    finally:
        os.close(file_fd)


def _profile_for_crossing() -> tuple[str, bool]:
    try:
        profile_path = appliance_runtime_path("profile")
    except ValueError:
        return "unknown", False
    try:
        value = _read_json_nofollow(profile_path)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return "specula", True
    if not isinstance(value, dict):
        return "specula", True
    kernel = value.get("kernel")
    if isinstance(kernel, dict) and kernel.get("engine_component") == "harmonia-monad":
        return "specula", True
    profile = normalize_profile(value.get("profile"))
    if profile in ("homeserver", "homesi", "homeconsole", "hometv"):
        return profile, True
    return "specula", True


def _crossing_publication(
    profile: str,
) -> tuple[set[str], set[tuple[str, str]], set[str], set[tuple[str, str]], set[str]] | None:
    seat_profile = profile
    try:
        value = _read_json_nofollow(ROOT / "crossings" / f"{profile}.json")
    except FileNotFoundError:
        if profile == "specula":
            return None
        try:
            value = _read_json_nofollow(ROOT / "crossings" / "specula.json")
            seat_profile = "specula"
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("schema") != _CROSSING_SCHEMA or value.get("profile") != seat_profile:
        return None
    bands = value.get("bands")
    verbs = value.get("verbs")
    if not isinstance(bands, list) or not isinstance(verbs, list):
        return None
    clean_bands: set[str] = set()
    for band in bands:
        if (
            not isinstance(band, str)
            or not band
            or band.startswith("/")
            or band.endswith("/")
            or any(not _CROSSING_PART.fullmatch(part) for part in band.split("/"))
        ):
            return None
        if band.split("/", 1)[0] == "lib":
            return None
        clean_bands.add(band)
    clean_verbs: set[tuple[str, str]] = set()
    for pair in verbs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(part, str) and _CROSSING_PART.fullmatch(part) for part in pair)
        ):
            return None
        if pair[0] == "lib":
            return None
        clean_verbs.add((pair[0], pair[1]))
    published_routes = value.get("routes")
    if not isinstance(published_routes, list):
        return None
    clean_routes: set[str] = set()
    for route in published_routes:
        if not isinstance(route, str) or _CROSSING_API_ROUTE.fullmatch(route) is None:
            return None
        clean_routes.add(route)

    administrative = value.get("administrative")
    if not isinstance(administrative, dict) or set(administrative) != {"bands", "verbs", "routes"}:
        return None
    admin_bands = administrative.get("bands")
    admin_verbs = administrative.get("verbs")
    admin_routes = administrative.get("routes")
    if not isinstance(admin_bands, list) or not isinstance(admin_verbs, list) or not isinstance(admin_routes, list):
        return None

    clean_admin_bands: set[str] = set()
    for band in admin_bands:
        if (
            not isinstance(band, str)
            or not band
            or band.startswith("/")
            or band.endswith("/")
            or any(not _CROSSING_PART.fullmatch(part) for part in band.split("/"))
            or band.split("/", 1)[0] == "lib"
            or band not in clean_bands
        ):
            return None
        clean_admin_bands.add(band)

    clean_admin_verbs: set[tuple[str, str]] = set()
    for pair in admin_verbs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(part, str) and _CROSSING_PART.fullmatch(part) for part in pair)
            or pair[0] == "lib"
        ):
            return None
        verb = (pair[0], pair[1])
        if verb not in clean_verbs:
            return None
        clean_admin_verbs.add(verb)

    clean_admin_routes: set[str] = set()
    for route in admin_routes:
        if not isinstance(route, str):
            return None
        if _CROSSING_API_ROUTE.fullmatch(route) is not None:
            if route not in clean_routes:
                return None
        elif _CROSSING_ADMIN_API_ROUTE.fullmatch(route) is None:
            return None
        clean_admin_routes.add(route)
    return clean_bands, clean_verbs, clean_admin_bands, clean_admin_verbs, clean_admin_routes


def _crossing_request(args: list[str]) -> tuple[str, str | tuple[str, str] | None, str, bool]:
    """Classify only the staff line's exact band or noun-verb forms."""
    if args and "/" in args[0]:
        raw = args[0]
        nonempty = [part for part in raw.split("/") if part]
        first_is_lib = bool(nonempty and nonempty[0] == "lib")
        canonical = (
            not raw.startswith("/")
            and not raw.endswith("/")
            and all(_CROSSING_PART.fullmatch(part) for part in raw.split("/"))
        )
        if not canonical:
            return "invalid", None, raw, first_is_lib
        if len(args) not in {1, 2} or (len(args) == 2 and not args[1].lstrip().startswith("{")):
            return "invalid", None, raw, first_is_lib
        return "band", raw, raw, first_is_lib
    if len(args) == 2 and all(_CROSSING_PART.fullmatch(part) for part in args):
        return "verb", (args[0], args[1]), f"{args[0]} {args[1]}", args[0] == "lib"
    if len(args) == 1 and _CROSSING_PART.fullmatch(args[0]):
        return "invalid", None, args[0], args[0] == "lib"
    return "invalid", None, "invalid-request", bool(args and args[0] == "lib")


def _crossing_resolved_target(args: list[str]) -> str | None:
    """Resolve a legacy noun-verb pair through the same declared aliases as main."""
    if len(args) != 2 or not all(_CROSSING_PART.fullmatch(part) for part in args):
        return None
    service_alias = args[0] == "service" and args[1] in SERVICE_ALIASES
    alias = SERVICE_ALIASES[args[1]] if service_alias else ALIASES.get(args[0], (args[0],))
    remainder = [] if service_alias else args[1:]
    path = ROOT
    try:
        for part in alias:
            if part not in _children(path):
                return None
            path /= part
        while remainder and remainder[0] in _children(path):
            path /= remainder.pop(0)
    except (ValueError, OSError, json.JSONDecodeError):
        return None
    if remainder:
        return None
    return path.relative_to(ROOT).as_posix()


def _refuse_crossing(profile: str, requested: str) -> int:
    resolved = False
    try:
        parts = requested.split()
        if len(parts) == 2:
            resolved = _crossing_resolved_target(parts) is not None
        elif len(parts) == 1:
            cursor = ROOT
            segments = parts[0].split("/")
            if all(segments):
                for segment in segments:
                    if segment not in _children(cursor):
                        break
                    cursor /= segment
                else:
                    resolved = True
    except (OSError, ValueError, TypeError, RecursionError):
        pass
    _front_answer("agathodaimon-band-not-published", "crossing",
                  profile=profile, requested=requested if resolved else "<not-a-path>")
    return 1


def _admit_caduceus_crossing(args: list[str]) -> bool:
    profile, profile_ok = _profile_for_crossing()
    form, request_key, requested, first_is_lib = _crossing_request(args)
    resolved_target = _crossing_resolved_target(args) if form == "verb" else None
    resolved_is_lib = bool(resolved_target and resolved_target.split("/", 1)[0] == "lib")
    publication = _crossing_publication(profile) if profile_ok else None
    if not profile_ok or publication is None or first_is_lib or resolved_is_lib:
        _refuse_crossing(profile, requested)
        return False
    bands, verbs, _admin_bands, _admin_verbs, _admin_routes = publication
    published_verb_targets = {
        target
        for pair in verbs
        if (target := _crossing_resolved_target(list(pair))) is not None
    }
    admitted = (
        isinstance(request_key, str) and form == "band" and request_key in bands
    ) or (
        form == "verb"
        and resolved_target is not None
        and resolved_target in published_verb_targets
    )
    if not admitted:
        _refuse_crossing(profile, requested)
        return False
    return True


def _pin_required() -> bool:
    try:
        value = _read_json_nofollow(appliance_runtime_path("config"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return False
    global_config = value.get("global") if isinstance(value, dict) else None
    admin = global_config.get("admin") if isinstance(global_config, dict) else None
    return isinstance(admin, dict) and admin.get("pin_required") is True


def _take_envelope_pin(value: object) -> tuple[bool, object]:
    """Remove the secret flag from every supported Alkahest carrier location."""
    if not isinstance(value, dict):
        return False, None
    found = False
    pin = None
    for container in (value.get("payload"), value):
        if not isinstance(container, dict):
            continue
        flags = container.get("flags")
        exousia = flags.get("exousia") if isinstance(flags, dict) else None
        if isinstance(exousia, dict) and "pin" in exousia:
            candidate = exousia.pop("pin")
            if not found and candidate != "[REDACTED]":
                found, pin = True, candidate
    return found, pin


def _argv_envelope_has_pin(args: list[str]) -> bool:
    for argument in args:
        if not isinstance(argument, str) or not argument.lstrip().startswith("{"):
            continue
        try:
            envelope = json.loads(argument)
        except (TypeError, ValueError, RecursionError):
            continue
        found, _pin = _take_envelope_pin(envelope)
        if found:
            return True
    return False


def _capture_piped_envelope() -> tuple[dict | None, bool, object]:
    """Buffer piped stdin once, scrub a PIN, then restore the consumer stream."""
    try:
        if sys.stdin.isatty():
            return None, False, None
        raw = sys.stdin.read()
    except (AttributeError, OSError, UnicodeError):
        return None, False, None
    envelope = None
    pin_present = False
    pin = None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        parsed = None
    except (ValueError, RecursionError):
        raise ValueError("invalid-envelope-json") from None
    if isinstance(parsed, dict):
        envelope, unwrapped = _unwrap_receipt(parsed)
        pin_present, pin = _take_envelope_pin(envelope)
        if pin_present or unwrapped:
            raw = json.dumps(envelope, separators=(",", ":"))
    sys.stdin = _EnvelopeStdin(raw)
    return envelope, pin_present, pin


def _cli_target(args: list[str]) -> tuple[str | None, list[str]]:
    """Resolve slash, noun/verb, and declared service aliases to one band path."""
    if not args:
        return None, []
    if "/" in args[0]:
        raw = args[0]
        if (
            raw.startswith("/")
            or raw.endswith("/")
            or not all(_CROSSING_PART.fullmatch(part) for part in raw.split("/"))
            or len(args) not in {1, 2}
            or (len(args) == 2 and not args[1].lstrip().startswith("{"))
        ):
            return None, []
        return raw, []
    service_alias = args[0] == "service" and len(args) > 1 and args[1] in SERVICE_ALIASES
    alias = SERVICE_ALIASES[args[1]] if service_alias else ALIASES.get(args[0], (args[0],))
    remainder = args[2:] if service_alias else args[1:]
    path = ROOT
    try:
        for part in alias:
            if part not in _children(path):
                return None, []
            path /= part
        while remainder and remainder[0] in _children(path):
            path /= remainder.pop(0)
    except (OSError, json.JSONDecodeError, ValueError):
        return None, []
    return path.relative_to(ROOT).as_posix(), remainder


def _transmission_keys_json_argv(args: list[str]) -> bool:
    try:
        target, _remainder = _cli_target(list(args))
    except Exception:
        return False
    return target == "transmission/keys" and any(
        isinstance(argument, str) and argument.lstrip().startswith("{")
        for argument in args[1:]
    )


def _administrative_target(target: str, publication) -> bool:
    if publication is None:
        return False
    _bands, _verbs, admin_bands, admin_verbs, _routes = publication
    targets = {
        resolved
        for pair in admin_verbs
        if (resolved := _crossing_resolved_target(list(pair))) is not None
    }
    return any(
        target == published or target.startswith(published + "/")
        for published in admin_bands | targets
    )


def _declares_administrative_band(target: str) -> bool:
    try:
        declaration = _index(ROOT / target)
    except (OSError, UnicodeError, ValueError, RecursionError):
        return False
    sclerite = declaration.get("sclerite") if isinstance(declaration, dict) else None
    features = sclerite.get("features") if isinstance(sclerite, dict) else None
    if not isinstance(features, dict):
        return False
    for feature in features.values():
        administrative = feature.get("administrative") if isinstance(feature, dict) else None
        if isinstance(administrative, dict) and administrative.get("band") is True:
            return True
    return False


def _administrative_candidate(target: str | None) -> bool:
    if target is None:
        return False
    candidates = {
            "local-ai/slot",
            "appliance/service",
            "appliance/sudo-passwordless",
            "portals/service-control",
            "storage/nas/attach",
            "storage/nas/detach",
            "storage/nas/setup",
            "storage/vault/open",
            "storage/vault/policy",
            "transmission/keys",
        }
    return (
        target in candidates
        or any(target.startswith(candidate + "/") for candidate in candidates)
        or target.startswith("settings/")
        or target in {"exousia/change", "exousia/reset-default"}
        or _declares_administrative_band(target)
    )


def _envelope_operation(envelope: dict | None, remainder: list[str]) -> str | None:
    if remainder:
        if remainder[0] == "whitelist" and len(remainder) > 1:
            return f"whitelist {remainder[1]}"
        if remainder[0] in {"resolver", "device-name", "alias"} and len(remainder) > 1:
            return remainder[1].lower()
        return remainder[0].lower()
    if not isinstance(envelope, dict):
        return None
    payload = envelope.get("payload")
    containers = [payload, envelope]
    for container in containers:
        if not isinstance(container, dict):
            continue
        metadata = container.get("metadata")
        if isinstance(metadata, dict):
            containers.append(metadata)
        for key in ("action", "op", "operation", "verb"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value.lower()
    transition = envelope.get("transition")
    if isinstance(transition, str) and transition:
        parts = [part for part in re.split(r"[./:]", transition) if part]
        if parts:
            return parts[-1].lower()
    return None


def _display_startup_reapplication_without_pin(
    target: str, remainder: list[str], envelope: dict | None,
) -> bool:
    flat_apply = target == "settings/display" and remainder == ["apply"]
    split_apply = target == "settings/display/apply" and not remainder
    if not (flat_apply or split_apply) or envelope is not None:
        return False
    try:
        module = _load(ROOT / "settings" / "display" / "_acts.py")
        allowed = getattr(module, "startup_apply_allowed", None)
        return bool(callable(allowed) and allowed())
    except Exception:
        return False


def _admin_mutation_request(target: str, remainder: list[str], envelope: dict | None) -> bool:
    if target == "local-ai/slot":
        # The systemd launcher reads config and must remain noninteractive.
        # All other actions (including malformed ones) retain the PIN gate.
        try:
            module = _load(ROOT / "local-ai" / "slot" / "index.py")
            return module.select_action(envelope=envelope, argv=remainder) != "run"
        except Exception:
            return True
    if target == "transmission/keys":
        try:
            module = _load(ROOT / "transmission" / "keys" / "index.py")
            action = module.select_action(envelope=envelope, argv=remainder)
        except Exception:
            return True
        return action in {"replace", "rotate"}
    operation = _envelope_operation(envelope, remainder)
    if _display_startup_reapplication_without_pin(target, remainder, envelope):
        return False
    read_only = {"get", "read", "status", "list", "show", "observed", "validate", "verify"}
    if target.startswith("settings/"):
        return True
    if target == "appliance/service":
        return operation not in {"read", "get", "show", "list", "observed", "status"}
    if target == "portals/service-control":
        return operation not in read_only and not (operation and operation.endswith("-status"))
    if target == "appliance/sudo-passwordless":
        return operation not in {"read", "status", "get"}
    return True


def _prompt_administrative_pin() -> tuple[bool, str | None]:
    try:
        tty_fd = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return False, None
    os.close(tty_fd)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return True, getpass.getpass("Appliance PIN: ")
    except (EOFError, OSError, getpass.GetPassWarning):
        return False, None


def _verify_administrative_pin(pin: object) -> bool:
    if not isinstance(pin, str):
        return False
    try:
        module = _load(ROOT / "lib" / "sacred_credential" / "index.py")
        verify = getattr(module, "verify_and_derive_caduceus", None)
        if not callable(verify):
            return False
        derived = verify(pin)
        close = getattr(derived, "close", None)
        if callable(close):
            close()
        return True
    except Exception:
        return False


def _refuse_administrative(signal: str) -> int:
    _front_answer(signal, "administrative-pin", sensitive=True)
    return 1


def _administrative_pin_admits(
    target: str | None,
    remainder: list[str],
    envelope: dict | None,
    pin_required: bool,
    caduceus_root: bool,
    pin_present: bool,
    pin: object,
    publication,
    startup_unenveloped: bool = False,
) -> bool:
    if not pin_required or caduceus_root or target is None:
        return True
    is_admin = (
        _administrative_candidate(target)
        if publication is None
        else _administrative_target(target, publication)
    )
    if not is_admin:
        return True
    startup_envelope = None if startup_unenveloped else envelope
    if _display_startup_reapplication_without_pin(target, remainder, startup_envelope):
        return True
    declared = _mutation_allowed(ROOT / target)
    if declared is False or (declared is None and not _admin_mutation_request(target, remainder, envelope)):
        return True
    if not pin_present:
        tty_available, pin = _prompt_administrative_pin()
        if not tty_available:
            _refuse_administrative("exousia-pin-required")
            return False
    if not _verify_administrative_pin(pin):
        pin = None
        _refuse_administrative("exousia-pin-wrong")
        return False
    pin = None
    return True


def _trace_operation(target: str | None, remainder: list[str]) -> str:
    """Name only declared static staff loci; never copy argv or payload values."""
    return "agathodaimon.staff.cli.operation"


def _unplaced(words: list[str], kind: str) -> str:
    def noun(segment: str) -> bool:
        return 1 <= len(segment) <= 128 and all(
            char.isalpha() or char.isdigit() or char in "-_" for char in segment
        )

    def echoable(word: str) -> bool:
        return all(noun(segment) for segment in word.split("/")) if kind != "noun" else noun(word)

    return " ".join(words) if all(echoable(word) for word in words) else f"<not-a-{kind}>"


def _front_answer(signal: str, step: str, path: Path | None = None,
                  word: str | None = None, observed_extra=None,
                  sensitive: bool = False, **extra) -> None:
    """Answer a front-door miss without copying payload or option values."""
    walked = []
    cursor = ROOT
    stopped = word
    try:
        if path is not None:
            cursor = path.parent if path.is_file() else path
            walked = list(cursor.relative_to(ROOT).parts)
        elif _front_args:
            first = _front_args[0]
            parts = (first.split("/") if "/" in first else
                     list(ALIASES.get(first, (first,))) + _front_args[1:])
            for part in parts:
                if part not in _children(cursor):
                    stopped = part
                    break
                cursor /= part
                walked.append(part)
        children = _children(cursor)
        resolved = (cursor / "index.py").is_file() or "serve" in _index(cursor)
        fields = _help_result(cursor)["payload_fields"] if resolved else None
    except (OSError, ValueError, TypeError, SyntaxError, RecursionError):
        children, fields, resolved = [], None, False
    words = []
    depth = 0
    aligned = True
    option_value = False
    for index, item in enumerate(_front_args):
        if not isinstance(item, str):
            words.append("<not-a-word>")
            aligned = False
            continue
        if item.startswith("--") or option_value:
            words.append("<not-a-option>" if item.startswith("--") else "<not-a-value>")
            option_value = item.startswith("--") and "=" not in item
            aligned = False
            continue
        kind = "path" if index == 0 and "/" in item else "noun"
        segments = item.split("/") if kind == "path" else [item]
        placed = (aligned and all(segments) and
                  walked[depth:depth + len(segments)] == segments)
        if placed:
            words.append(item)
            depth += len(segments)
        else:
            words.append(f"<not-a-{kind}>")
            aligned = False
        option_value = False
    nearest = None
    if isinstance(stopped, str):
        matches = difflib.get_close_matches(stopped, children, n=1)
        nearest = matches[0] if matches else None
    noun = "/".join(walked[:-1] if resolved and len(walked) > 1 else walked)
    verb = walked[-1] if resolved and len(walked) > 1 else ""
    observed = {"words": words, "walked": walked, "stopped_at": step}
    if observed_extra:
        observed.update(observed_extra)
    choices = {"children": children, "nearest": nearest}
    if fields is not None:
        choices["payload_fields"] = fields
    result = {"schema": "caduceus.staff.receipt.v1", "ok": False,
              "firstMissingSignal": signal, "mutationPerformed": False,
              "stop": {"noun": noun, "verb": verb}, "observed": observed,
              "could_change_to": choices, "attempt": {"attempted": False, "step": step},
              "final_receipt": {"ok": False, "firstMissingSignal": signal}}
    result.update(extra)
    if _stamp_seat is not None:
        result["seat"] = _stamp_seat
    print(json.dumps(result, separators=(",", ":")))


def _unwrap_receipt(value):
    if isinstance(value, dict) and value.get("schema") == "caduceus.staff.receipt.v1":
        carried = value.get("envelope")
        if not isinstance(carried, dict) or carried.get("schema") != "caduceus.staff.v1":
            raise ValueError("receipt-carries-no-request")
        return carried, True
    return value, False


class _StampBytes(BytesIO):
    def __init__(self):
        super().__init__()
        # The crossing daemon replaces StringIO with its bounded capture.
        guard = StringIO()
        self._guard = guard if hasattr(guard, "limit") else None

    def write(self, data):
        if self._guard is not None:
            remaining = max(0, getattr(self._guard, "limit") - getattr(self._guard, "size"))
            self._guard.write("x" * min(memoryview(data).nbytes, remaining + 1))
        return super().write(data)


class _StampOutput:
    def __init__(self, destination):
        self._destination = destination
        self.buffer = _StampBytes()
        self._text = TextIOWrapper(self.buffer, encoding=getattr(destination, "encoding", None) or "utf-8",
                                   errors=getattr(destination, "errors", None) or "strict", write_through=True)

    @property
    def encoding(self):
        return self._text.encoding

    @property
    def errors(self):
        return self._text.errors

    def write(self, text):
        return self._text.write(text)

    def flush(self):
        self._text.flush()

    def fileno(self):
        return self._destination.fileno()

    def isatty(self):
        return self._destination.isatty()

    def bytes(self):
        self.flush()
        return self.buffer.getvalue()


def _emit_stamp_bytes(destination, data):
    destination.flush()
    view = memoryview(data)
    while view:
        written = destination.buffer.write(view)
        if written is None or written <= 0:
            raise OSError("stdout-write-failed")
        view = view[written:]


def main(argv=None):
    from agathodaimon._envelope import echo_scope
    with echo_scope():
        return _scoped_main(argv)


def _scoped_main(argv=None):
    global _stamp_target, _stamp_seat, _front_args, _front_dry_run
    started = time.monotonic()
    _front_dry_run = False
    _front_args = list(sys.argv[1:] if argv is None else argv)
    _stamp_target = None
    _stamp_seat = None
    try:
        folder = appliance_runtime_path("seats")
        seats = read_seats(folder)
    except ForeignSeat as exc:
        _front_answer("agathodaimon-seat-foreign", "seat-read",
                      observed_extra={"id": exc.seat_id, "found": exc.found})
        return 2
    except (OSError, ValueError, UnicodeError, RecursionError):
        _front_answer("agathodaimon-seat-read-failed", "seat-read")
        return 2
    _stamp_target = None
    absent = [seat_id for seat_id, seat in seats.items() if seat["state"] == "absent"]
    _stamp_seat = {"folder": str(folder), "absent": absent} if absent else None
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        stream_target = _slash_target(args[0]) if len(args) == 1 and "/" in args[0] else None
        stream = (stream_target is not None and stream_target.is_file()
                  and _index(stream_target.parent).get("envelope", {}).get("stdin") == "stream")
        raw_target = _slash_target(args[0]) if 1 <= len(args) <= 2 and "/" in args[0] else None
        raw_stdout = (raw_target is not None and raw_target.is_file()
                      and _index(raw_target.parent).get("envelope", {}).get("stdout") == "raw")
    except (OSError, ValueError, TypeError):
        stream = False
        raw_stdout = False
    if stream or raw_stdout:
        return _main(argv, folder, seats)
    destination = sys.stdout
    output = _StampOutput(destination)
    try:
        with contextlib.redirect_stdout(output):
            result = _main(argv, folder, seats)
    except BaseException:
        _emit_stamp_bytes(destination, output.bytes())
        raise
    captured = output.bytes()
    try:
        raw = captured.decode("utf-8")
    except UnicodeDecodeError:
        raw = ""
    answer = None
    if _stamp_target:
        try:
            answer = json.loads(raw)
        except (ValueError, TypeError):
            pass
    if (isinstance(answer, dict) and isinstance(answer.get("ok"), bool)
            and answer.get("schema") != "caduceus.chord.receipt.v1"
            and not _front_dry_run and isinstance(_stamp_target, str)
            and any(_stamp_target.startswith(prefix) for prefix in
                    ("network/dhcp/", "network/dns/", "network/identity/"))):
        try:
            target = _slash_target(_stamp_target)
            if target is not None and target.is_file() and _mutation_allowed(target.parent) is not False:
                from agathodaimon._deed import send
                word = "refused" if not answer["ok"] else "changed" if _stage_changed(answer) else "kept"
                send("sbin", _stamp_target.rsplit("/", 1)[-1], answer["ok"],
                     target=_stamp_target.replace("/", "."), outcome=word,
                     signal=answer.get("firstMissingSignal") or "operation-failed",
                     duration_ms=int((time.monotonic() - started) * 1000))
        except Exception:
            print("caduceus-deed-post-failed", file=sys.stderr)
    if isinstance(answer, dict) and isinstance(answer.get("ok"), bool) and answer.get("schema") != "caduceus.chord.receipt.v1":
        sys.stdout.write(json.dumps(_stamp_receipt(answer, _stamp_target)) + "\n")
    elif (isinstance(answer, dict) and answer.get("schema") == "caduceus.chord.receipt.v1"
          and _stamp_seat is not None and "seat" not in answer):
        compact = raw == json.dumps(answer, separators=(",", ":")) + "\n"
        answer.setdefault("seat", _stamp_seat)
        sys.stdout.write(json.dumps(answer, separators=(",", ":") if compact else None) + "\n")
    else:
        _emit_stamp_bytes(destination, captured)
    return result


def _chord_part_names_drift(seat):
    if not isinstance(seat, dict):
        return None
    names = set()
    for key in ("required", "optional"):
        values = seat.get(key)
        if isinstance(values, list):
            names.update(value for value in values if isinstance(value, str))
    if names == _CHORD_PART_NAMES:
        return None
    return {"seat_only": sorted(names - _CHORD_PART_NAMES),
            "walker_only": sorted(_CHORD_PART_NAMES - names)}


def _main(argv, folder, seats):
    global _stamp_target
    args=list(sys.argv[1:] if argv is None else argv)
    wrapped_argv_pin = False
    if len(args) == 2 and "/" in args[0]:
        try:
            argv_envelope = json.loads(args[1])
        except RecursionError:
            _front_answer("invalid-envelope-json", "parse-envelope")
            return 2
        except (TypeError, ValueError):
            argv_envelope = None
        if isinstance(argv_envelope, dict):
            try:
                argv_envelope, unwrapped = _unwrap_receipt(argv_envelope)
            except ValueError:
                _front_answer("receipt-carries-no-request", "unwrap-receipt")
                return 2
            if unwrapped:
                wrapped_argv_pin, _pin = _take_envelope_pin(argv_envelope)
                _pin = None
                args[1] = json.dumps(argv_envelope, separators=(",", ":"))
        if isinstance(argv_envelope, dict) and _contains_secret_name(argv_envelope.get("payload")):
            _front_answer("invalid-or-forbidden-long-option", "options")
            return 2
    if _transmission_keys_json_argv(args):
        return _refuse_administrative("transmission-keys-stdin-required")
    caduceus_root = os.environ.get("SUDO_USER") == "caduceus" and os.geteuid() == 0
    if caduceus_root:
        if not _admit_caduceus_crossing(args):
            return 1
        for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
            os.environ.pop(name, None)
    # A JSON-argv request may carry a forbidden PIN and a dry-run field. Give
    # the target's dry-run refusal precedence without exposing either value.
    if len(args) == 2 and "/" in args[0] and args[1].lstrip().startswith("{"):
        preflight_envelope = None
        try:
            preflight_envelope = json.loads(args[1])
            preflight_target = _slash_target(args[0])
        except (ValueError, OSError):
            preflight_target = None
        if preflight_target is not None and not _dry_run_admits(preflight_target, preflight_envelope):
            return 2
    if wrapped_argv_pin or _argv_envelope_has_pin(args):
        return _refuse_administrative("exousia-pin-required")
    if not args or args == ["--help"]:
        census = {"folder": str(folder),
                  "loaded": [{"id": seat_id, "schema_version": seat["schema_version"]}
                             for seat_id, seat in seats.items() if seat["state"] == "loaded"],
                  "absent": [seat_id for seat_id, seat in seats.items() if seat["state"] == "absent"]}
        drift = _chord_part_names_drift(seats.get("caduceus.chord.v1", {}).get("seat"))
        if drift is not None:
            for entry in census["loaded"]:
                if entry["id"] == "caduceus.chord.v1":
                    entry["drift"] = drift
        print(json.dumps({"schema":"agathodaimon.cli.spine.v1","nouns":_children(ROOT),"seats":census},indent=2)); return 0
    if args == ["--version"]:
        print(_shelf_version()); return 0
    original=args[:]
    pin_required = _pin_required()
    publication = None
    if pin_required:
        profile, profile_ok = _profile_for_crossing()
        publication = _crossing_publication(profile) if profile_ok else None
    if len(args) == 1 and "/" in args[0]:
        stream_target = _slash_target(args[0])
        if (stream_target is not None and stream_target.is_file()
                and _index(stream_target.parent).get("envelope", {}).get("stdin") == "stream"):
            cli_target, remainder = _cli_target(args)
            if cli_target is None:
                _front_answer("invalid-stream-path", "stream-path")
                return 2
            # A stream is not inspected here, so it cannot prove the absence
            # of input required for the display startup exception.
            gate_envelope = {} if cli_target == "settings/display/apply" else None
            if not _administrative_pin_admits(
                cli_target, remainder, gate_envelope, pin_required, caduceus_root,
                False, None, publication,
            ):
                return 1
            return int(_load(stream_target).main() or 0)
        raw_envelope = sys.stdin.read()
        try:
            envelope = json.loads(raw_envelope)
        except (TypeError, ValueError, RecursionError):
            _front_answer("invalid-envelope-json", "parse-envelope")
            return 2
        if not isinstance(envelope, dict):
            _front_answer("envelope-must-be-a-json-object", "parse-envelope")
            return 2
        try:
            envelope, unwrapped = _unwrap_receipt(envelope)
        except ValueError:
            _front_answer("receipt-carries-no-request", "unwrap-receipt")
            return 2
        pin_present, pin = _take_envelope_pin(envelope)
        from agathodaimon._envelope import mark_gate_pin_present
        mark_gate_pin_present(pin_present)
        if pin_present or unwrapped:
            raw_envelope = json.dumps(envelope, separators=(",", ":"))
        target = _slash_target(args[0])
        if target is None:
            _front_answer("unknown-path", "walk-path")
            return 2
        cli_target, remainder = _cli_target(args)
        if not _dry_run_admits(target, envelope):
            return 2
        admitted = _administrative_pin_admits(
            cli_target, remainder, envelope, pin_required, caduceus_root,
            pin_present, pin, publication,
        )
        pin = None
        if not admitted:
            return 1
        _stamp_target = cli_target
        return _load_trace.run_cli(
            envelope, _trace_operation(cli_target, remainder),
            lambda: _invoke_envelope(target, envelope, raw_envelope),
        )
    if len(args) == 2 and "/" in args[0]:
        try:
            envelope = json.loads(args[1])
        except (TypeError, ValueError, RecursionError):
            _front_answer("invalid-envelope-json", "parse-envelope")
            return 2
        if not isinstance(envelope, dict):
            _front_answer("envelope-must-be-a-json-object", "parse-envelope")
            return 2
        raw_envelope = args[1]
        target = _slash_target(args[0])
        if target is None:
            _front_answer("unknown-path", "walk-path")
            return 2
        cli_target, remainder = _cli_target(args)
        if not _dry_run_admits(target, envelope):
            return 2
        if not _administrative_pin_admits(
            cli_target, remainder, envelope, pin_required, caduceus_root,
            False, None, publication,
        ):
            return 1
        _stamp_target = cli_target
        return _load_trace.run_cli(
            envelope, _trace_operation(cli_target, remainder),
            lambda: _invoke_envelope(target, envelope, raw_envelope),
        )
    service_alias=args[0]=="service" and len(args)>1 and args[1] in SERVICE_ALIASES
    alias=SERVICE_ALIASES[args[1]] if service_alias else ALIASES.get(args[0],(args[0],))
    remainder=args[2:] if service_alias else args[1:]
    path=ROOT
    try:
        for part in alias:
            if part not in _children(path): raise ValueError(part)
            path/=part
        while remainder and remainder[0] in _children(path): path/=remainder.pop(0)
    except (ValueError,OSError,json.JSONDecodeError):
        display = args[0] if args[0] == "__caduceus_crossing_probe_nonexistent__" else "<not-a-noun>"
        print(f"unknown noun: {display}",file=sys.stderr)
        _front_answer("unknown-noun", "walk-noun")
        return 2
    children=_children(path); has_index=(path/"index.py").is_file()
    chord = not has_index and "serve" in _index(path)
    if not has_index and not chord:
        if children and remainder == ["--help"]:
            print(json.dumps({"noun":original[0],"verbs":children},indent=2)); return 0
        if remainder or (not sys.stdin.isatty() and sys.stdin.read()):
            _front_answer("agathodaimon-noun-has-no-act", "walk-noun", path, remainder[0] if remainder else None); return 2
        print(json.dumps({"noun":original[0],"verbs":children},indent=2)); return 0
    if children and not has_index and not chord and remainder and remainder[0] != "--help":
        _front_answer("unknown-verb", "walk-verb", path, remainder[0]); return 2
    if not chord and ((remainder==["--help"] and (children or not has_index)) or (not remainder and children and not has_index)):
        print(json.dumps({"noun":original[0],"verbs":children},indent=2))
        if has_index:
            _help(path)
        return 0
    if not has_index and not chord:
        if not remainder:
            print(json.dumps({"noun":original[0],"verbs":children},indent=2)); return 0
        _front_answer("unknown-verb", "walk-verb", path, remainder[0]); return 2
    if remainder == ["--help"]: _help(path); return 0
    try:
        envelope, pin_present, pin = _capture_piped_envelope()
        from agathodaimon._envelope import mark_gate_pin_present
        mark_gate_pin_present(pin_present)
    except ValueError as exc:
        if str(exc) == "invalid-envelope-json":
            _front_answer("invalid-envelope-json", "parse-envelope", path)
        else:
            _front_answer("receipt-carries-no-request", "unwrap-receipt", path)
        return 2
    if children and has_index and not remainder and (not isinstance(sys.stdin, _EnvelopeStdin) or not sys.stdin.getvalue()):
        print(json.dumps({"noun":original[0],"verbs":children},indent=2)); return 0
    cli_target = path.relative_to(ROOT).as_posix()
    # Bare legacy objects belong to the module; schema-bearing envelopes,
    # long options, empty stdin, and chords retain the hand form.
    hand_form = (chord or (bool(remainder) and remainder[0].startswith("--"))
                 or (not remainder and (envelope is None or "schema" in envelope)))
    if hand_form:
        startup_unenveloped = envelope is None and not remainder
        if envelope is None:
            raw = sys.stdin.getvalue() if isinstance(sys.stdin, _EnvelopeStdin) else ""
            if raw.strip():
                try:
                    json.loads(raw)
                except (ValueError, TypeError, RecursionError):
                    _front_answer("invalid-envelope-json", "parse-envelope", path)
                else:
                    _front_answer("envelope-must-be-a-json-object", "parse-envelope", path)
                return 2
            envelope = _fresh_envelope(cli_target)
        elif "schema" not in envelope:
            stub = envelope
            envelope = _fresh_envelope(cli_target)
            for field in ("payload", "flags"):
                if isinstance(stub.get(field), dict):
                    envelope[field] = stub[field]
        try:
            options = _hand_options(remainder)
        except ValueError as exc:
            _front_answer(str(exc).replace(" ", "-"), "options", path); return 2
        from agathodaimon._envelope import _pin_bearing_exousia
        if _pin_bearing_exousia({"payload": options}):
            return _refuse_administrative("exousia-pin-stdin-required")
        payload = envelope.get("payload")
        if payload is not None and not isinstance(payload, dict):
            _front_answer("envelope-payload-must-be-an-object", "payload", path); return 2
        envelope["payload"] = {**(payload or {}), **options}
        target = path if chord else path / "index.py"
        if not _dry_run_admits(target, envelope, remainder or None):
            return 2
        if chord and pin_required and not caduceus_root and publication is None:
            return _refuse_administrative("agathodaimon-crossings-unavailable")
        admitted = _administrative_pin_admits(cli_target, [], envelope, pin_required, caduceus_root, pin_present, pin, publication, startup_unenveloped)
        pin = None
        if not admitted:
            return 1
        _stamp_target = cli_target
        return _load_trace.run_cli(envelope, _trace_operation(cli_target, remainder), lambda: _invoke_envelope(target, envelope, argv=remainder or None))
    if not _dry_run_admits(path / "index.py", envelope, remainder):
        return 2
    if _index(path).get("hand") == "envelope":
        if remainder:
            _front_answer("unexpected-word", "walk-remainder", path, remainder[0])
            return 2
        if envelope is None:
            envelope = _fresh_envelope(cli_target)
        if not _administrative_pin_admits(cli_target, [], envelope, pin_required, caduceus_root, pin_present, pin, publication):
            return 1
        _stamp_target = cli_target
        return _load_trace.run_cli(envelope, _trace_operation(cli_target, remainder), lambda: _invoke_envelope(path / "index.py", envelope))
    remainder = _dry_run_argv(envelope, remainder) or []
    trace_present, _ = _load_trace.extract_load_context(envelope)
    mod = None
    fn = None
    if not trace_present:
        # Preserve the ordinary primitive path's eager import/refusal ordering.
        mod = _load(path / "index.py")
        fn = getattr(mod, "main", None)
        if fn is None:
            print(json.dumps({"schema":"agathodaimon.read.v1","path":str(path.relative_to(ROOT)),"ok":True,"mutationPerformed":False}))
            return 0
    admitted = _administrative_pin_admits(
        cli_target, remainder, envelope, pin_required, caduceus_root,
        pin_present, pin, publication,
    )
    pin = None
    if not admitted:
        return 1

    def invoke_module() -> int:
        nonlocal mod, fn
        if mod is None:
            with _load_trace.span("agathodaimon.staff.import", source_state="dynamic-module"):
                mod = _load(path / "index.py")
            fn = getattr(mod, "main", None)
        if fn is None:
            print(json.dumps({"schema":"agathodaimon.read.v1","path":str(path.relative_to(ROOT)),"ok":True,"mutationPerformed":False}))
            return 0
        try:
            return int(fn(remainder) or 0)
        except TypeError as exc:
            if "positional argument" not in str(exc) and "positional arguments" not in str(exc):
                raise
            return int(fn() or 0)

    _stamp_target = cli_target
    return _load_trace.run_cli(envelope, _trace_operation(cli_target, remainder), invoke_module)

if __name__ == "__main__": raise SystemExit(main())

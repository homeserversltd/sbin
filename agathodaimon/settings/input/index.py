"""Caduceus settings/input actuator for the Hyprland input policy."""
from __future__ import annotations
import argparse, json, os, re, shutil, subprocess, sys, tempfile, uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from typing import Any
from agathodaimon._envelope import EnvelopeError, attach, read
SCHEMA = "caduceus.staff.settings.input.v1"
FIELDS = ("pointer_sensitivity", "scroll_factor", "natural_scroll", "tap_to_click", "middle_button_emulation")
KEYS = {"pointer_sensitivity": "sensitivity", "scroll_factor": "scroll_factor", "natural_scroll": "natural_scroll", "tap_to_click": "tap-to-click", "middle_button_emulation": "middle_button_emulation"}
BOUNDS = {"pointer_sensitivity": (-1.0, 1.0), "scroll_factor": (0.1, 10.0)}

def settings_root() -> Path:
    return Path(os.environ.get("CADUCEUS_SETTINGS_HOME", os.path.expanduser("~")))

def config_paths() -> tuple[Path, Path]:
    directory = settings_root() / ".config" / "hypr"
    return directory / "input.conf", directory / "input-overrides.conf"

def matching_block(lines: list[str], name: str, start: int = 0) -> tuple[int, int] | None:
    opening, depth = None, 0
    for index in range(start, len(lines)):
        code = lines[index].split("#", 1)[0]
        if opening is None and re.match(rf"^\s*{re.escape(name)}\s*\{{", code):
            opening, depth = index, code.count("{") - code.count("}")
        elif opening is not None:
            depth += code.count("{") - code.count("}")
            if depth <= 0:
                return opening, index
    return None

def assignments(lines: list[str], begin: int, end: int) -> dict[str, str]:
    result = {}
    for line in lines[begin + 1:end]:
        match = re.match(r"^\s*([-\w]+)\s*=\s*(.*?)\s*(?:#.*)?$", line)
        if match:
            result[match.group(1)] = match.group(2).strip()
    return result

def read_scoped_values(path: Path) -> dict[str, dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return {"global": {}, "touchpad": {}}
    outer = matching_block(lines, "input")
    if outer is None:
        return {"global": {}, "touchpad": {}}
    touchpad = matching_block(lines, "touchpad", outer[0] + 1)
    if touchpad is None or touchpad[1] > outer[1]:
        touchpad = None
    global_values = assignments(lines, outer[0], touchpad[0]) if touchpad else assignments(lines, outer[0], outer[1])
    if touchpad:
        global_values.update(assignments(lines, touchpad[1], outer[1]))
    return {"global": global_values, "touchpad": assignments(lines, *touchpad) if touchpad else {}}

def read_values() -> dict[str, Any]:
    base, override = config_paths()
    base_scopes, override_scopes = read_scoped_values(base), read_scoped_values(override)
    values, sources = {}, {}
    for field in FIELDS:
        scope = "touchpad" if field in {"tap_to_click", "middle_button_emulation"} else "global"
        raw = override_scopes[scope].get(KEYS[field])
        source = override if raw is not None else base
        if raw is None:
            raw = base_scopes[scope].get(KEYS[field])
        if raw is None:
            values[field], sources[field] = None, "none"
        elif field in BOUNDS:
            try:
                number = float(raw); values[field] = int(number) if number.is_integer() else number
            except ValueError:
                values[field] = raw
            sources[field] = str(source)
        else:
            values[field], sources[field] = raw.lower() == "true", str(source)
    return {"values": values, "sources": sources, "base": str(base), "override": str(override)}

def validate(field: str, value: Any) -> str:
    if field not in FIELDS:
        raise ValueError(f"unknown:{field}")
    if field in BOUNDS:
        if isinstance(value, bool) or not isinstance(value, (int, float, str)):
            raise ValueError(f"invalid:{field}:number-required")
        try: number = float(str(value).strip())
        except ValueError as error: raise ValueError(f"invalid:{field}:number-required") from error
        low, high = BOUNDS[field]
        if not low <= number <= high: raise ValueError(f"invalid:{field}:range")
        return f"{number:g}"
    if not isinstance(value, bool): raise ValueError(f"invalid:{field}:strict-bool-required")
    return "true" if value else "false"

def render(values: dict[str, str]) -> bytes:
    global_fields = ("pointer_sensitivity", "scroll_factor", "natural_scroll")
    touchpad_fields = ("tap_to_click", "middle_button_emulation")
    lines = ["# Managed by caduceus settings/input; do not edit input.conf.", "input {"]
    lines.extend(f"    {KEYS[field]} = {values[KEYS[field]]}" for field in global_fields if KEYS[field] in values)
    lines.append("    touchpad {")
    lines.extend(f"        {KEYS[field]} = {values[KEYS[field]]}" for field in touchpad_fields if KEYS[field] in values)
    lines.extend(("    }", "}", ""))
    return "\n".join(lines).encode()

def atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
        temporary = Path(handle.name); handle.write(payload); handle.flush(); os.fsync(handle.fileno())
    try:
        os.replace(temporary, path); directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally: temporary.unlink(missing_ok=True)

def persist_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    root = Path(os.environ.get("CADUCEUS_RECEIPT_ROOT", "/var/lib/caduceus/receipts"))
    path = root / str(uuid.uuid4()) / "run.json"
    atomic_write(path, (json.dumps(receipt, sort_keys=True) + "\n").encode())
    receipt["receiptPath"] = str(path)
    return receipt

def reload_hypr() -> dict[str, Any]:
    command = os.environ.get("CADUCEUS_HYPRCTL") or shutil.which("hyprctl") or "hyprctl"
    try:
        result = subprocess.run([command, "reload"], check=False, capture_output=True, text=True, timeout=8)
        return {"ok": result.returncode == 0, "returncode": result.returncode, "stdout": result.stdout[:4096].strip(), "stderr": result.stderr[:4096].strip()}
    except (OSError, subprocess.SubprocessError) as error:
        return {"ok": False, "returncode": 127, "error": str(error)}

def apply_changes(changes: dict[str, Any]) -> dict[str, Any]:
    if not changes: raise ValueError("no-fields-supplied")
    normalized = {field: validate(field, value) for field, value in changes.items()}
    _, override = config_paths(); current = read_scoped_values(override)
    effective = dict(current["global"]); effective.update(current["touchpad"])
    effective.update({KEYS[field]: value for field, value in normalized.items()})
    payload = render(effective); previous = override.read_bytes() if override.exists() else None
    if previous == payload: return persist_receipt({"schema": SCHEMA, "ok": True, "changed": False, "mutationPerformed": False, "readback": read_values()})
    atomic_write(override, payload)
    receipt = {"schema": SCHEMA, "ok": True, "changed": True, "fields": list(changes), "mutationPerformed": True, "reload": reload_hypr()}
    if not receipt["reload"]["ok"]:
        if previous is None: override.unlink(missing_ok=True)
        else: atomic_write(override, previous)
        receipt.update(ok=False, changed=False, rollback=True, firstMissingSignal="reload-failed")
    else: receipt["readback"] = read_values()
    return persist_receipt(receipt)

def transition_operation(envelope: dict[str, Any]) -> str:
    for key in ("operation", "action", "transition"):
        value = envelope.get(key)
        if isinstance(value, str) and value: return re.split(r"[./:]", value.rstrip("/"))[-1]
    return "read"

def emit(receipt: dict[str, Any], status: int = 0) -> int:
    print(json.dumps(receipt, sort_keys=True)); return status

def crossing_changes(args: list[Any]) -> dict[str, Any]:
    if not args or args[0] != "set":
        raise ValueError("cli-parse-failure")
    changes: dict[str, Any] = {}
    index = 1
    while index < len(args):
        if index + 3 >= len(args) or args[index] != "--field" or args[index + 2] != "--value-json":
            raise ValueError("cli-parse-failure")
        field, raw = args[index + 1], args[index + 3]
        if not isinstance(field, str) or not isinstance(raw, str):
            raise ValueError("cli-parse-failure")
        try:
            changes[field] = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(f"invalid:{field}:json") from error
        index += 4
    return changes

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("read"); set_parser = subparsers.add_parser("set")
    for field in FIELDS: set_parser.add_argument(f"--{field.replace('_', '-')}")
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        try:
            args = parser.parse_args(argv)
        except SystemExit:
            return emit({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": "cli-parse-failure"}, 2)
        if args.operation == "read":
            return emit({"schema": SCHEMA, "ok": True, "mutationPerformed": False, **read_values()})
        try:
            raw_stdin = sys.stdin.read()
        except OSError as error:
            return emit({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": f"stdin-read-failure:{error}"}, 1)
        if raw_stdin.strip():
            try:
                candidate = json.loads(raw_stdin)
            except json.JSONDecodeError:
                return emit({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": "invalid-json"}, 1)
            if not isinstance(candidate, dict):
                return emit({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": "json-object-required"}, 1)
        else:
            candidate = {}
        changes = dict(candidate)
        for field in FIELDS:
            value = getattr(args, field)
            if value is not None:
                if field not in BOUNDS and value in {"true", "false"}:
                    value = value == "true"
                changes[field] = value
        if args.operation == "set":
            try:
                receipt = apply_changes(changes)
                return emit(receipt, 0 if receipt.get("ok") else 1)
            except ValueError as error:
                return emit({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": str(error)}, 1)
    else:
        try:
            request = read(known_fields=tuple(FIELDS) + ("args",))
        except EnvelopeError as error:
            return emit({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": str(error)}, 1)
        candidate = request.payload
        crossing_argv = candidate.get("args") if not request.envelope and isinstance(candidate, dict) else None
        if isinstance(crossing_argv, list):
            if crossing_argv == ["get", "--json"]:
                return emit(attach({"schema": SCHEMA, "ok": True, "mutationPerformed": False, **read_values()}, request), 0)
            try:
                receipt = apply_changes(crossing_changes(crossing_argv))
                return emit(attach(receipt, request), 0 if receipt.get("ok") else 1)
            except ValueError as error:
                return emit(attach({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": str(error)}, request), 1)
        if request.envelope:
            operation = transition_operation(request.value)
            if operation == "read": return emit(attach({"schema": SCHEMA, "ok": True, "mutationPerformed": False, **read_values()}, request), 0)
            if operation not in {"set", "mutate", "change", "apply"}: return emit(attach({"schema": SCHEMA, "ok": False, "mutationPerformed": False, "firstMissingSignal": f"unsupported-operation:{operation}"}, request), 1)
            try:
                changes = {field: value for field, value in candidate.items() if field in FIELDS}
                if not changes: raise ValueError("no-fields-supplied")
                receipt = apply_changes(changes)
                return emit(attach(receipt, request), 0 if receipt.get("ok") else 1)
            except ValueError as error:
                return emit(attach({"schema": SCHEMA, "ok": False, "changed": False, "mutationPerformed": False, "firstMissingSignal": str(error)}, request), 1)
        return emit({"schema": SCHEMA, "ok": False, "mutationPerformed": False, "firstMissingSignal": "cli-parse-failure"}, 2)

if __name__ == "__main__": raise SystemExit(main())

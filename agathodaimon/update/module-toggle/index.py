"""Atomic Caduceus ownership of the Harmonia module disable list.

This actuator is deliberately the narrow live writer for
``/etc/appliance/config.json``.  It parses the document for validity, changes
only ``harmonia.disabled_modules``, and splices that member into the original
JSON bytes so every unrelated field remains byte-for-byte intact.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Sequence

CONFIG_PATH = "/etc/appliance/config.json"
BACKUP_ROOT = "/var/lib/caduceus/backups/harmonia-module-toggle"
MODULE_ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


class ToggleError(ValueError):
    """A named refusal that leaves the household document untouched."""


def _root() -> Path:
    return Path(os.environ.get("CADUCEUS_ROOT", "/"))


def _path(device_path: str) -> Path:
    return _root() / device_path.lstrip("/")


def config_path() -> Path:
    return _path(CONFIG_PATH)


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-duplicate-key")
        value[key] = child
    return value


def _load(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (json.JSONDecodeError, ToggleError) as exc:
        raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid") from exc
    if not isinstance(value, dict):
        raise ToggleError("agathodaimon-harmonia-module-toggle-config-not-object")
    return value


def _skip_ws(raw: str, index: int) -> int:
    while index < len(raw) and raw[index].isspace():
        index += 1
    return index


def _object_members(raw: str, start: int = 0) -> tuple[int, int, dict[str, tuple[int, int]]]:
    """Return an object's bounds and each direct member value span."""
    decoder = json.JSONDecoder()
    start = _skip_ws(raw, start)
    if start >= len(raw) or raw[start] != "{":
        raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid")
    index = start + 1
    members: dict[str, tuple[int, int]] = {}
    while True:
        index = _skip_ws(raw, index)
        if index >= len(raw):
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid")
        if raw[index] == "}":
            return start, index, members
        try:
            key, key_end = decoder.raw_decode(raw, index)
        except json.JSONDecodeError as exc:
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid") from exc
        if not isinstance(key, str) or key in members:
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid")
        index = _skip_ws(raw, key_end)
        if index >= len(raw) or raw[index] != ":":
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid")
        value_start = _skip_ws(raw, index + 1)
        try:
            _, value_end = decoder.raw_decode(raw, value_start)
        except json.JSONDecodeError as exc:
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid") from exc
        members[key] = (value_start, value_end)
        index = _skip_ws(raw, value_end)
        if index >= len(raw):
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid")
        if raw[index] == "}":
            return start, index, members
        if raw[index] != ",":
            raise ToggleError("agathodaimon-harmonia-module-toggle-config-invalid")
        index += 1


def _dedupe(modules: list[str]) -> list[str]:
    seen: set[str] = set()
    return [item for item in modules if not (item in seen or seen.add(item))]


def _render_disabled(modules: list[str]) -> str:
    return json.dumps(modules, indent=2, ensure_ascii=False)


def _insert_member(raw: str, start: int, end: int, key: str, rendered: str) -> str:
    """Insert one direct JSON member without changing existing member bytes."""
    interior = raw[start + 1 : end]
    if not interior.strip():
        insertion = f'\n  {json.dumps(key)}: {rendered}\n'
    elif "\n" in interior:
        insertion = f',\n  {json.dumps(key)}: {rendered}'
    else:
        insertion = f', {json.dumps(key)}: {rendered}'
    return raw[:end] + insertion + raw[end:]


def _updated_bytes(raw: str, module: str, state: str) -> tuple[str, list[str]]:
    document = _load(raw)
    harmonia = document.get("harmonia")
    if harmonia is not None and not isinstance(harmonia, dict):
        raise ToggleError("agathodaimon-harmonia-module-toggle-harmonia-not-object")
    previous = [] if harmonia is None else harmonia.get("disabled_modules", [])
    if not isinstance(previous, list) or any(not isinstance(item, str) for item in previous):
        raise ToggleError("agathodaimon-harmonia-module-toggle-disabled-modules-invalid")
    disabled = _dedupe(previous)
    if state == "off":
        disabled = _dedupe(disabled + [module])
    else:
        disabled = [item for item in disabled if item != module]

    root_start, root_end, root_members = _object_members(raw)
    rendered_disabled = _render_disabled(disabled)
    if "harmonia" not in root_members:
        rendered_harmonia = json.dumps({"disabled_modules": disabled}, indent=2, ensure_ascii=False)
        return _insert_member(raw, root_start, root_end, "harmonia", rendered_harmonia), disabled

    harmonia_start, harmonia_end = root_members["harmonia"]
    nested_start, nested_end, nested_members = _object_members(raw, harmonia_start)
    if harmonia_end != nested_end + 1:
        raise ToggleError("agathodaimon-harmonia-module-toggle-harmonia-not-object")
    if "disabled_modules" in nested_members:
        value_start, value_end = nested_members["disabled_modules"]
        return raw[:value_start] + rendered_disabled + raw[value_end:], disabled
    return _insert_member(raw, nested_start, nested_end, "disabled_modules", rendered_disabled), disabled


def _atomic_write(path: Path, payload: bytes, mode: int, uid: int, gid: int, prefix: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fchmod(handle.fileno(), mode)
            if os.geteuid() == 0:
                os.fchown(handle.fileno(), uid, gid)
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _backup(path: Path, raw: bytes) -> Path:
    directory = _path(BACKUP_ROOT)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    target = directory / f"config-{stamp}.json"
    _atomic_write(target, raw, 0o600, os.geteuid(), os.getegid(), ".config-backup.")
    return target


def _device_path(path: Path) -> str:
    try:
        return "/" + str(path.relative_to(_root()))
    except ValueError:
        return str(path)


def _receipt(module: str | None, state: str, disabled: list[str], backup: Path | None, *, ok: bool = True, signal: str = "none") -> dict[str, Any]:
    return {
        "module": module,
        "state": state,
        "disabled_modules": disabled,
        "backup_path": None if backup is None else _device_path(backup),
        "ok": ok,
        "firstMissingSignal": signal,
    }


def list_disabled() -> dict[str, Any]:
    path = config_path()
    if not path.is_file():
        return _receipt(None, "list", [], None, ok=False, signal="agathodaimon-harmonia-module-toggle-config-missing")
    try:
        document = _load(path.read_text(encoding="utf-8"))
        harmonia = document.get("harmonia", {})
        if not isinstance(harmonia, dict):
            raise ToggleError("agathodaimon-harmonia-module-toggle-harmonia-not-object")
        disabled = harmonia.get("disabled_modules", [])
        if not isinstance(disabled, list) or any(not isinstance(item, str) for item in disabled):
            raise ToggleError("agathodaimon-harmonia-module-toggle-disabled-modules-invalid")
        return _receipt(None, "list", _dedupe(disabled), None)
    except (OSError, ToggleError) as exc:
        return _receipt(None, "list", [], None, ok=False, signal=str(exc))


def toggle(module: str, state: str) -> dict[str, Any]:
    if not MODULE_ID.fullmatch(module):
        return _receipt(module, state, [], None, ok=False, signal="agathodaimon-harmonia-module-toggle-module-invalid")
    path = config_path()
    if not path.is_file():
        return _receipt(module, state, [], None, ok=False, signal="agathodaimon-harmonia-module-toggle-config-missing")
    try:
        original = path.read_bytes()
        raw = original.decode("utf-8")
        updated, disabled = _updated_bytes(raw, module, state)
        if updated == raw:
            return _receipt(module, state, disabled, None)
        metadata = path.stat()
        backup = _backup(path, original)
        _atomic_write(path, updated.encode("utf-8"), stat.S_IMODE(metadata.st_mode), metadata.st_uid, metadata.st_gid, ".config.")
        return _receipt(module, state, disabled, backup)
    except (OSError, UnicodeDecodeError, ToggleError) as exc:
        return _receipt(module, state, [], None, ok=False, signal=str(exc))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-harmonia-module-toggle")
    parser.add_argument("module_or_command", help="a module id, or 'list'")
    parser.add_argument("state", nargs="?", choices=("on", "off"))
    args = parser.parse_args(argv)
    if args.module_or_command == "list":
        if args.state is not None:
            parser.error("list takes no state")
        value = list_disabled()
    elif args.state is None:
        parser.error("module toggles require on or off")
    else:
        value = toggle(args.module_or_command, args.state)
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

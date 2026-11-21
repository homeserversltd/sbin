"""Read owner input settings and apply input changes on Sway only."""
from __future__ import annotations

import math
import os
import re
from pathlib import Path
from typing import Any

from agathodaimon._nidus.refusal import named_signal
from agathodaimon._nidus.write import WriteError
from agathodaimon.settings import _parity, _shared, _sway_overrides


_SWAY_FIELDS = {"accel_profile", "left_handed", "disable_while_typing", "pointer_speed",
                "natural_scroll", "tap_to_click", "scroll_factor"}
_HYPR_FIELDS = {
    "keyboard_layout": (("input", "kb_layout"),),
    "keyboard_variant": (("input", "kb_variant"),),
    "repeat_delay_ms": (("input", "repeat_delay"),),
    "pointer_speed": (("input", "sensitivity"),),
    "scroll_factor": (("input", "scroll_factor"),),
    "natural_scroll": (("input", "natural_scroll"), ("touchpad", "natural_scroll")),
    "tap_to_click": (("touchpad", "tap_to_click"), ("touchpad", "tap-to-click")),
    "accel_profile": (("input", "accel_profile"),),
    "left_handed": (("input", "left_handed"),),
    "disable_while_typing": (("touchpad", "disable_while_typing"),),
}


def _hypr_declarations(path: Path, *, lua: bool = False) -> dict[tuple[str, str], str]:
    """Read literal declarations in the owner's input and touchpad blocks, never execute Lua."""
    scopes: list[str] = []
    result: dict[tuple[str, str], str] = {}
    lines = _shared.hypr_lua_lines(path) if lua else _shared.ini_read(path)
    start = ["config"] if lua else []
    block = r"(\w+)\s*=\s*\{" if lua else r"(\w+)\s*\{"
    for line in lines:
        code = (line if lua else line.split("#", 1)[0]).strip()
        if lua and not scopes:
            if re.fullmatch(r"hl\.config\s*\(\s*\{", code):
                scopes.append("config")
            continue
        opening = re.fullmatch(block, code)
        if opening:
            scopes.append(opening[1])
        elif scopes and re.fullmatch(r"\}\s*[,;)]?", code):
            scopes.pop()
        elif scopes in (start + ["input"], start + ["input", "touchpad"]):
            assignment = re.fullmatch(r"([-\w]+)\s*=\s*(.*)", code)
            if assignment:
                raw = assignment[2].rstrip(",;").strip() if lua else assignment[2].strip()
                result[(scopes[-1], assignment[1])] = raw
    return result


def _hypr_value(field: str, raw: str, *, lua: bool) -> Any:
    if field in {"pointer_speed", "scroll_factor"}:
        try:
            value = float(raw)
        except ValueError:
            return None
        return value if math.isfinite(value) else None
    if field == "repeat_delay_ms":
        return int(raw) if re.fullmatch(r"[0-9]{1,9}", raw) else None
    if field in {"natural_scroll", "tap_to_click", "left_handed", "disable_while_typing"}:
        return {"true": True, "false": False}.get(raw.lower())
    if lua:
        string = re.fullmatch(r'''(["'])([\w,.-]*)\1''', raw)
        return string[2] if string else None
    return raw


def read_values() -> dict[str, Any]:
    selected = _parity.backends.select_backend()
    if selected:
        values, sources = _parity.sway_input_values(selected)
        return {"values": values, "sources": sources,
                "base": str(_shared.home() / ".config/sway/conf.d/input.conf"),
                "override": str(_sway_overrides.path())}

    directory = _shared.home() / ".config/hypr"
    base, override = directory / "input.conf", directory / "input-overrides.conf"
    lua_path = directory / "hyprland.lua"
    values = dict.fromkeys(_shared.FIELDS["input"])
    sources = dict.fromkeys(values, "none")
    lua = lua_path.is_file()
    if lua:
        # The old hyprlang override is not sourced by the Lua configuration.
        base = lua_path
        declarations = [(base, _hypr_declarations(base, lua=True))]
    else:
        declarations = [(override, _hypr_declarations(override)), (base, _hypr_declarations(base))]
    for field, keys in _HYPR_FIELDS.items():
        for source, settings in declarations:
            raw = next((settings[key] for key in keys if key in settings), None)
            if raw is not None:
                value = _hypr_value(field, raw, lua=lua)
                if value is not None:
                    values[field], sources[field] = value, str(source)
                break
    return {"values": values, "sources": sources, "base": str(base), "override": str(override),
            "readonly": dict.fromkeys(values, _shared.SWAY_SESSION_UNAVAILABLE)}


def apply_changes(changes: dict[str, Any]) -> dict[str, Any]:
    selected = _parity.backends.select_backend()
    if not selected:
        raise ValueError("unsupported:" + _shared.SWAY_SESSION_UNAVAILABLE)
    if not changes:
        raise ValueError("no-fields-supplied")
    if changes.keys() - _SWAY_FIELDS:
        raise ValueError("unsupported:sway-input-field")

    # Validate all fields before opening the one file transaction.
    blocks = {field: _parity.input_block(field, value) for field, value in changes.items()}
    receipt = _shared.Receipt("input", list(changes))
    dry_run = os.environ.get("CADUCEUS_SETTINGS_DRY_RUN") == "1"
    scroll = blocks.get("scroll_factor")
    scroll_command = scroll[2][0].strip() if scroll is not None else None

    def reload():
        if dry_run:
            receipt.commands.append({"argv": ["swaymsg", "reload"], "dryRun": True})
        else:
            _parity._sway_reload(receipt)

    def apply_scroll():
        if scroll_command is None:
            return
        if dry_run:
            receipt.commands.append({"argv": ["swaymsg", *scroll_command.split()], "dryRun": True})
        else:
            _parity.sway_command(selected, scroll_command, receipt, "sway-scroll-factor-failed")

    try:
        _sway_overrides.replace_blocks(
            blocks.values(), receipt, "input-override-invalid",
            reload=reload if changes.keys() - {"scroll_factor"} else None,
            apply_live=apply_scroll if scroll is not None else None,
        )
    except WriteError as error:
        signal = named_signal(error.cause, "settings-input")
        if error.restore_errors:
            signal = "rollback-failed:" + signal
        # A scroll-only IPC failure cannot prove the live state after dispatch.
        uncertain = bool(error.restore_errors or (not dry_run and scroll is not None
                                                   and len(changes) == 1 and receipt.commands))
        failure = receipt.finish(False, error=signal)
        raise _shared.ReceiptFailure(signal, failure["receipt"], uncertain) from error
    answer = receipt.finish(True, receipt.changed)
    if dry_run:
        answer.update(dryRun=True, commands=receipt.commands)
    return answer

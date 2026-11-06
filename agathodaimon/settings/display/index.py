"""Display policy facade: current owner backend, query and apply receipts."""
from __future__ import annotations

import json
import math
import os
import pwd
import shlex
import sys
import time
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).parents[3]))

from agathodaimon.settings import _shared
from agathodaimon.settings.display import backends, policy
from agathodaimon._envelope import EnvelopeError, Request, attach, read

DISPLAY_FIELDS = ("output", "resolution", "refresh_rate", "scale", "orientation", "brightness", "night_light", "hdr", "adaptive_sync", "overscan")
MODE_FIELDS = {"resolution", "refresh_rate"}
OVERRIDE_BEGIN = "# settings-display-output-begin"
OVERRIDE_END = "# settings-display-output-end"
ORIENTATIONS = {"normal", "90", "180", "270"}


def startup_apply_allowed() -> bool:
    """Only an owner Sway session may use the unattended reapplication PIN seam."""
    selected = backends.select_backend()
    return isinstance(selected, dict) and selected.get("kind") == "sway"


def _values(settings: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "resolution": settings.get("resolution", "auto"),
        "refresh_rate": settings.get("refresh_rate", policy.DEFAULT_REFRESH_RATE),
        "scale": None,
        "orientation": None,
        "brightness": None,
        "night_light": None,
        "hdr": None,
        "adaptive_sync": None,
        "overscan": None,
    }


def _kms_observation() -> dict[str, Any]:
    return policy.connected_connectors()


def _resolution_observation(connectors: Sequence[Mapping[str, Any]], settings: Mapping[str, Any]) -> dict[str, Any]:
    return policy.resolve_mode(connectors, settings)


def _options(output: Mapping[str, Any] | None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "scale": [{"value": value, "label": f"{value}×"} for value in (1, 2)],
        "orientation": [{"value": value, "label": label} for value, label in (
            ("normal", "Normal"), ("90", "Rotated 90°"),
            ("180", "Rotated 180°"), ("270", "Rotated 270°"))],
    }
    if not output:
        return result
    modes = output.get("modes")
    if not isinstance(modes, list) or not modes:
        return result
    dimensions = set()
    rates = set()
    current = output.get("current_mode")
    for mode in modes[:policy.MAX_MODES]:
        if not isinstance(mode, dict):
            continue
        width, height, refresh = mode.get("width"), mode.get("height"), mode.get("refresh")
        if (type(width) is not int or type(height) is not int or width <= 0 or height <= 0):
            continue
        dimensions.add((width, height))
        if (isinstance(current, dict) and width == current.get("width") and height == current.get("height")
                and type(refresh) is int and refresh > 0):
            rates.add(Fraction(refresh, 1000))
    if dimensions:
        result["resolution"] = [{"value": "auto", "label": "Automatic"}] + [
            {"value": f"{w}x{h}", "label": f"{w} × {h}"} for w, h in sorted(dimensions)]
    if rates:
        result["refresh_rate"] = [{"value": int(rate) if rate.denominator == 1 else float(rate),
                                   "label": f"{backends._refresh_hz_text(rate)} Hz"}
                                  for rate in sorted(rates)]
    return result


def _failure(signal: str, *, settings: Mapping[str, Any] | None = None,
             requested: Mapping[str, Any] | None = None, backend: Mapping[str, Any] | None = None,
             resolved: Mapping[str, Any] | None = None, current: Any = None,
             mutation_performed: bool = False, **extra: Any) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "ok": False,
        "changed": False,
        "mutationPerformed": mutation_performed,
        "firstMissingSignal": signal,
    }
    if settings is not None:
        receipt["values"] = _values(settings)
        receipt["settingsSource"] = settings.get("source")
    if requested is not None:
        receipt["requested"] = dict(requested)
    if backend is not None:
        receipt["backend"] = dict(backend)
    if resolved is not None:
        receipt["resolved"] = dict(resolved)
    if current is not None:
        receipt["current"] = current
    receipt.update(extra)
    return receipt


def _unsupported_field(requested: Mapping[str, Any]) -> str | None:
    return next((field for field in requested if field not in MODE_FIELDS), None)


def _current_summary(connector: Mapping[str, Any] | None) -> Any:
    if not isinstance(connector, Mapping):
        return None
    return connector.get("current_mode") or connector.get("kms_current_mode")


def _mode_matches_current(mode: Mapping[str, Any], current: Any) -> bool:
    if not isinstance(current, Mapping):
        return False
    if mode.get("width") != current.get("width") or mode.get("height") != current.get("height"):
        return False
    selected_rate = policy._rate_fraction(mode)
    current_rate = policy._rate_fraction(current)
    if current_rate is None and isinstance(current.get("refresh"), int) and not isinstance(current.get("refresh"), bool):
        current_rate = Fraction(int(current["refresh"]), 1000)
    return selected_rate is not None and current_rate is not None and abs(selected_rate - current_rate) <= Fraction(1, 1000)


# The Sway backend owns a sparse per-screen table; absence means Automatic.
SELECTED_PREFIX = "# settings-display-selected-output "


def _display_settings(selected: Mapping[str, Any]) -> dict[str, Any]:
    if selected.get("kind") == "sway":
        return {"resolution": "auto", "refresh_rate": policy.DEFAULT_REFRESH_RATE,
                "source": "output-overrides", "fallback": None, "defaulted": []}
    return policy.load_settings()


def _outputs(selected: Mapping[str, Any]) -> list[dict[str, Any]]:
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, ["-t", "get_outputs"])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    raw, error = backends._parse_json_list(result)
    if error:
        raise ValueError(error)
    return [x for x in raw if isinstance(x, dict) and x.get("active") is True
            and isinstance(x.get("name"), str)]


def _identifier(output: Mapping[str, Any]) -> str | None:
    parts = [output.get(k) for k in ("make", "model", "serial")]
    if any(not isinstance(x, str) or not x.strip() or x.strip().lower() == "unknown" for x in parts):
        return None
    return " ".join(parts)


def _keys(outputs: Sequence[Mapping[str, Any]]) -> dict[str, str]:
    identifiers = [_identifier(x) for x in outputs]
    return {str(x["name"]): ident if ident and identifiers.count(ident) == 1 else str(x["name"])
            for x, ident in zip(outputs, identifiers)}


def _listed(outputs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    physical = [x for x in outputs if not str(x["name"]).startswith("HEADLESS-")]
    return sorted(physical or list(outputs), key=policy._connector_rank)


def _table_path() -> Path:
    return _shared.home() / ".config/sway/output-overrides.conf"


def _table_parse(original: str) -> tuple[list[str], int, int, list[str], dict[tuple[str, str], str], str | None]:
    lines = original.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == OVERRIDE_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.rstrip("\r\n") == OVERRIDE_END]
    if len(begins) != len(ends) or len(begins) > 1 or (begins and ends[0] <= begins[0]):
        raise ValueError("display-override-invalid")
    start, end = (begins[0], ends[0]) if begins else (len(lines), len(lines) - 1)
    body = lines[start + 1:end] if begins else []
    rows: dict[tuple[str, str], str] = {}
    selection = None
    for line in body:
        if line.startswith(SELECTED_PREFIX):
            if selection is not None:
                raise ValueError("display-selection-duplicate")
            selection = line[len(SELECTED_PREFIX):].rstrip("\r\n")
            continue
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if len(words) != 4 or words[0] != "output" or words[2] not in {"mode", "scale", "transform"}:
            raise ValueError("display-override-invalid")
        rows[(words[1], words[2])] = words[3]
    return lines, start, end, body, rows, selection


def _table_update(original: str, *, key: str, field: str, value: str | None,
                  aliases: Sequence[str] = ()) -> str:
    lines, start, end, body, _rows, _selection = _table_parse(original)
    kept = []
    for line in body:
        if field == "selection" and line.startswith(SELECTED_PREFIX):
            continue
        words = shlex.split(line, comments=True)
        if field != "selection" and len(words) == 4 and words[0] == "output" and words[1] in {key, *aliases} and words[2] == field:
            continue
        kept.append(line if line.endswith("\n") else line + "\n")
    if value is not None:
        if field == "selection":
            if "\n" in value or "\r" in value:
                raise ValueError("invalid:output")
            kept.append(SELECTED_PREFIX + value + "\n")
        else:
            kept.append(f"output {backends._escape_sway_name(key)} {field} {value}\n")
    block = [OVERRIDE_BEGIN + "\n", *kept, OVERRIDE_END + "\n"]
    if end >= start:
        lines[start:end + 1] = block
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.extend(block)
    return "".join(lines)


def _read_table() -> str:
    path = _table_path()
    return path.read_text(encoding="utf-8") if path.exists() else ""


def _row(rows: Mapping[tuple[str, str], str], output: Mapping[str, Any], keys: Mapping[str, str], field: str) -> str | None:
    name = str(output["name"])
    return rows.get((keys[name], field), rows.get((name, field)))


def _picked(outputs: Sequence[Mapping[str, Any]], selection: str | None) -> Mapping[str, Any] | None:
    keys = _keys(outputs)
    choices = _listed(outputs)
    return next((x for x in choices if keys[str(x["name"])] == selection), choices[0] if choices else None)


def _sway_command(selected: Mapping[str, Any], command: str, receipt: Any = None) -> None:
    socket = str(selected["socket"])
    argv, runtime, _ = backends._sway_argv(socket, [command])
    result = backends._bounded_command(argv, runtime=runtime, socket_path=socket)
    if receipt is not None:
        receipt.commands.append({"argv": argv, "returncode": result.get("returncode")})
    responses, error = backends._parse_json_list(result)
    if error or not responses or not all(isinstance(x, dict) and x.get("success") is True for x in responses):
        raise ValueError(error or "sway-display-apply-failed")


def _position_command(outputs: Sequence[Mapping[str, Any]]) -> str:
    physical = sorted([x for x in outputs if not str(x["name"]).startswith("HEADLESS-")], key=policy._connector_rank)
    headless = [x for x in outputs if str(x["name"]).startswith("HEADLESS-")]
    commands = []
    x = 0
    for output in physical:
        rect = output.get("rect")
        if not isinstance(rect, dict) or not isinstance(rect.get("width"), int) or rect["width"] <= 0:
            raise ValueError("sway-output-logical-width-unavailable")
        commands.append(f"output {backends._escape_sway_name(str(output['name']))} pos {x} 0")
        x += rect["width"]
    commands.extend(f"output {backends._escape_sway_name(str(output['name']))} pos 0 0" for output in headless)
    return "; ".join(commands)


def _arrange(selected: Mapping[str, Any], receipt: Any = None) -> None:
    outputs = _outputs(selected)
    command = _position_command(outputs)
    if command:
        _sway_command(selected, command, receipt)
        after = {x["name"]: x for x in _outputs(selected)}
        x = 0
        for output in sorted([o for o in outputs if not str(o["name"]).startswith("HEADLESS-")], key=policy._connector_rank):
            rect = after.get(output["name"], {}).get("rect", {})
            if rect.get("x") != x or rect.get("y") != 0:
                raise ValueError("sway-position-readback-mismatch")
            x += output["rect"]["width"]
        for output in outputs:
            if str(output["name"]).startswith("HEADLESS-"):
                rect = after.get(output["name"], {}).get("rect", {})
                if rect.get("x") != 0 or rect.get("y") != 0:
                    raise ValueError("sway-position-readback-mismatch")


def _positions(outputs: Sequence[Mapping[str, Any]]) -> dict[str, tuple[int, int]]:
    positions = {}
    for output in outputs:
        rect = output.get("rect")
        if (not isinstance(rect, dict) or type(rect.get("x")) is not int
                or type(rect.get("y")) is not int):
            raise ValueError("sway-output-prior-position-unavailable")
        positions[str(output["name"])] = (rect["x"], rect["y"])
    return positions


def _restore_positions(selected: Mapping[str, Any], positions: Mapping[str, tuple[int, int]], receipt: Any = None) -> None:
    commands = [f"output {backends._escape_sway_name(name)} pos {x} {y}"
                for name, (x, y) in positions.items()]
    if not commands:
        return
    _sway_command(selected, "; ".join(commands), receipt)
    after = {str(item["name"]): item for item in _outputs(selected)}
    for name, (x, y) in positions.items():
        rect = after.get(name, {}).get("rect", {})
        if rect.get("x") != x or rect.get("y") != y:
            raise ValueError("sway-position-rollback-mismatch")


def _mode_for(output: Mapping[str, Any], resolution: str, refresh: int | float) -> dict[str, Any]:
    connectors = backends._merge_kms_modes(policy.normalize_sway_outputs([output]), _kms_observation())
    resolved = policy.resolve_mode(connectors, {"resolution": resolution, "refresh_rate": refresh})
    if not resolved.get("ok"):
        raise ValueError("display-no-eligible-advertised-mode")
    mode = resolved["mode"]
    if resolution != "auto" and resolution != f"{mode['width']}x{mode['height']}":
        raise ValueError("display-no-eligible-advertised-mode")
    return mode


def _mode_text(mode: Mapping[str, Any]) -> str:
    rate = policy._rate_fraction(mode)
    if rate is None:
        raise ValueError("display-mode-rate-unavailable")
    return f"{mode['width']}x{mode['height']}@{backends._refresh_hz_text(rate)}Hz"


def _mode_current_text(output: Mapping[str, Any]) -> str:
    mode = output.get("current_mode")
    if not isinstance(mode, dict) or not isinstance(mode.get("refresh"), int):
        raise ValueError("sway-output-prior-mode-unavailable")
    return f"{mode['width']}x{mode['height']}@{backends._refresh_hz_text(Fraction(mode['refresh'], 1000))}Hz"


def _live_matches(output: Mapping[str, Any] | None, field: str, value: str) -> bool:
    if not output:
        return False
    if field == "scale":
        return output.get("scale") == float(value)
    if field == "transform":
        return output.get("transform") == value
    if field == "mode":
        return _mode_current_text(output) == value
    if field == "hdr":
        return output.get("hdr") is (value == "on")
    if field == "adaptive_sync":
        return output.get("adaptive_sync_status") == ("enabled" if value == "on" else "disabled")
    return False


def _set_live(selected: Mapping[str, Any], name: str, field: str, value: str, receipt: Any = None) -> None:
    _sway_command(selected, f"output {backends._escape_sway_name(name)} {field} {value}", receipt)
    after = next((x for x in _outputs(selected) if x.get("name") == name), None)
    if not _live_matches(after, field, value):
        raise ValueError("sway-" + field + "-readback-mismatch")


def _write_table(path: Path, payload: str) -> None:
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    temp = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temp = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        if os.geteuid() == 0 and _shared.home() == _shared.OWNER_HOME:
            owner = pwd.getpwnam(_shared.OWNER_USER)
            os.chown(temp, owner.pw_uid, owner.pw_gid)
        os.replace(temp, path)
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


def _get_reply(settings: Mapping[str, Any], selected: Mapping[str, Any]) -> dict[str, Any]:
    try:
        outputs = _outputs(selected)
        _lines, _start, _end, _body, rows, selection = _table_parse(_read_table())
        keys = _keys(outputs)
        output = _picked(outputs, selection)
        kms = _kms_observation()
        connectors = backends._merge_kms_modes(policy.normalize_sway_outputs(outputs), kms)
        connector = next((x for x in connectors if output and x.get("name") == output.get("name")), None)
        resolved = policy.resolve_mode([connector] if connector else [], {"resolution": "auto", "refresh_rate": policy.DEFAULT_REFRESH_RATE})
        values = _values(settings)
        values["output"] = keys[str(output["name"])] if output else None
        values["resolution"] = "auto"
        values["scale"] = "auto"
        values["orientation"] = "auto"
        options = _options(output)
        automatic = {"value": "auto", "label": "Automatic"}
        options.setdefault("resolution", [automatic])
        options["scale"].insert(0, automatic)
        options["orientation"].insert(0, automatic)
        options.setdefault("refresh_rate", [])
        options["output"] = [{"value": keys[str(x["name"])], "label":
                              f"{x['make']} {x['model']} ({x['name']})" if _identifier(x) else str(x["name"])}
                             for x in _listed(outputs)]
        if output:
            mode = _row(rows, output, keys, "mode")
            if mode:
                values["resolution"] = mode.split("@", 1)[0]
            current = output.get("current_mode")
            if isinstance(current, dict) and isinstance(current.get("refresh"), int):
                values["refresh_rate"] = current["refresh"] / 1000
            scale = _row(rows, output, keys, "scale")
            if scale is not None:
                number = float(scale)
                if not math.isfinite(number) or number <= 0:
                    raise ValueError("display-override-invalid-scale")
                values["scale"] = int(number) if number.is_integer() else number
            values["orientation"] = _row(rows, output, keys, "transform") or "auto"
            features = output.get("features")
            if isinstance(features, dict):
                if features.get("hdr") is True and isinstance(output.get("hdr"), bool):
                    values["hdr"] = output["hdr"]
                if features.get("adaptive_sync") is True and output.get("adaptive_sync_status") in {"enabled", "disabled"}:
                    values["adaptive_sync"] = output["adaptive_sync_status"] == "enabled"
        return {"ok": True, "values": values, "options": options, "mutationPerformed": False,
                "observations": {"backend": dict(selected), "settings": {"source": settings.get("source"), "fallback": None, "defaulted": []},
                                 "live": {"ok": True, "source": "sway-ipc", "preferred_exposed_by_sway": False, "kms_status": kms.get("status"), "kms_errors": kms.get("errors", []), "connectors": connectors, "signal": None}, "resolved": resolved}}
    except (OSError, ValueError, TypeError, KeyError) as error:
        return _failure(str(error), settings=settings, backend=selected)


def _apply(selected: Mapping[str, Any], operation: str, supplied: Mapping[str, Any], settings: Mapping[str, Any]) -> dict[str, Any]:
    if selected.get("kind") != "sway":
        return _failure("display-backend-unavailable", settings=settings, backend=selected)
    path = _table_path()
    original = None
    existed = path.exists()
    live_attempted = False
    changes: list[tuple[str, str, str]] = []
    positions: dict[str, tuple[int, int]] | None = None
    receipt = None
    try:
        receipt = _shared.Receipt("display", ["apply" if operation == "apply" else next(iter(supplied), "apply")])
        original = _read_table()
        _lines, _start, _end, _body, rows, selection = _table_parse(original)
        outputs = _outputs(selected)
        keys = _keys(outputs)
        if operation == "apply":
            positions = _positions(outputs)
            for output in _listed(outputs):
                if str(output["name"]).startswith("HEADLESS-") or _row(rows, output, keys, "mode"):
                    continue
                mode = _mode_text(_mode_for(output, "auto", policy.DEFAULT_REFRESH_RATE))
                name = str(output["name"])
                changes.append((name, "mode", _mode_current_text(output)))
                live_attempted = True
                _set_live(selected, name, "mode", mode, receipt)
            live_attempted = True
            _arrange(selected, receipt)
            answer = receipt.finish(True, True)
            answer["mutationPerformed"] = True
            return answer
        if len(supplied) != 1:
            raise ValueError("mixed-display-fields")
        requested_field, value = next(iter(supplied.items()))
        if requested_field == "output":
            if not isinstance(value, str) or value not in [keys[str(x['name'])] for x in _listed(outputs)]:
                raise ValueError("invalid:output")
            updated = _table_update(original, key=value, field="selection", value=value)
            if updated != original:
                _write_table(path, updated)
            answer = receipt.finish(True, updated != original)
            answer["mutationPerformed"] = updated != original
            return answer
        output = _picked(outputs, selection)
        if not output:
            raise ValueError("sway-output-unavailable")
        name = str(output["name"])
        key = keys[name]
        aliases = [name]
        identifier = _identifier(output)
        if identifier and sum(_identifier(item) == identifier for item in outputs) == 1:
            aliases.append(identifier)
        if requested_field == "scale":
            if value != "auto" and (isinstance(value, bool) or not isinstance(value, (int, float)) or value not in (1, 2)):
                raise ValueError("display-fractional-scale-unsafe")
            field, desired = "scale", "1" if value == "auto" else str(int(value))
            prior_value = output.get("scale")
            if isinstance(prior_value, bool) or not isinstance(prior_value, (int, float)) or not math.isfinite(prior_value) or prior_value <= 0:
                raise ValueError("sway-output-prior-scale-unavailable")
            prior = str(prior_value)
        elif requested_field == "orientation":
            if value != "auto" and value not in ORIENTATIONS:
                raise ValueError("invalid:orientation")
            field, desired = "transform", "normal" if value == "auto" else value
            prior = output.get("transform")
            if prior not in {"normal", "90", "180", "270", "flipped", "flipped-90", "flipped-180", "flipped-270"}:
                raise ValueError("sway-output-prior-transform-unavailable")
        elif requested_field in MODE_FIELDS:
            current = output.get("current_mode")
            if not isinstance(current, dict):
                raise ValueError("sway-output-prior-mode-unavailable")
            prior = _mode_current_text(output)
            resolution = value if requested_field == "resolution" else f"{current['width']}x{current['height']}"
            refresh = value if requested_field == "refresh_rate" else current.get("refresh", 60000) / 1000
            policy.validate_settings({"resolution": resolution, "refresh_rate": refresh})
            desired = _mode_text(_mode_for(output, resolution, refresh))
            field = "mode"
        elif requested_field in {"hdr", "adaptive_sync"}:
            features = output.get("features")
            observed = output.get("hdr") if requested_field == "hdr" else output.get("adaptive_sync_status")
            if not isinstance(value, bool) or not isinstance(features, dict) or features.get(requested_field) is not True or (not isinstance(observed, bool) if requested_field == "hdr" else observed not in {"enabled", "disabled"}):
                raise ValueError("unsupported:" + requested_field)
            field, desired = requested_field, "on" if value else "off"
            prior = "on" if (observed is True or observed == "enabled") else "off"
        else:
            raise ValueError("unsupported:" + requested_field)
        positions = _positions(outputs)
        updated = original
        if field in {"scale", "transform", "mode"}:
            updated = _table_update(original, key=key, field=field, value=None if value == "auto" else desired, aliases=aliases)
            if updated != original:
                _write_table(path, updated)
        live_attempted = True
        changes.append((name, field, str(prior)))
        _set_live(selected, name, field, desired, receipt)
        _arrange(selected, receipt)
        answer = receipt.finish(True, updated != original or str(prior) != str(desired))
        answer["mutationPerformed"] = True
        return answer
    except (OSError, ValueError, TypeError, KeyError) as error:
        signal = str(error)
        if original is not None:
            try:
                if path.exists() and path.read_text(encoding="utf-8") != original:
                    if existed:
                        _write_table(path, original)
                    else:
                        path.unlink()
            except OSError as rollback:
                signal = "rollback-failed:" + str(rollback) + ":" + signal
        for name, field, prior in reversed(changes):
            try:
                _set_live(selected, name, field, prior, receipt)
            except (OSError, ValueError, TypeError, KeyError) as rollback:
                signal = "live-rollback-failed:" + str(rollback) + ":" + signal
        if live_attempted and positions is not None:
            try:
                _restore_positions(selected, positions, receipt)
            except (OSError, ValueError, TypeError, KeyError) as rollback:
                signal = "position-rollback-failed:" + str(rollback) + ":" + signal
        failure_receipt = receipt.finish(False, error=signal) if receipt is not None else None
        return _failure(signal, settings=settings, backend=selected, mutation_performed=live_attempted,
                        receipt=failure_receipt.get("receipt") if failure_receipt else None)


def _envelope_operation(request: Request) -> str:
    operation = request.verb.lower() if isinstance(request.verb, str) else "unknown"
    if operation in {"display", "settings", "exousia", "unknown"}:
        operation = "set" if request.payload else "read"
    return operation


def _request_has_payload(request: Request) -> bool:
    payload = request.value.get("payload")
    if isinstance(payload, Mapping) and payload:
        return True
    if request.payload:
        return True
    return any(field in request.value for field in DISPLAY_FIELDS)


def _log_mutation(operation: str, receipt: Mapping[str, Any], started: float) -> None:
    resolved = receipt.get("resolved")
    connector = resolved.get("connector") if isinstance(resolved, Mapping) else None
    line: dict[str, Any] = {
        "who": "agathodaimon", "verb": operation, "target": "settings/display",
        "outcome": "ok" if receipt.get("ok") is True else "failed",
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "signal": str(receipt.get("firstMissingSignal", "none"))[:128],
    }
    if isinstance(connector, Mapping) and isinstance(connector.get("connector_id"), int):
        line["connector_id"] = connector["connector_id"]
    encoded = json.dumps(line, sort_keys=True, separators=(",", ":"))
    if len(encoded) > 900:
        line.pop("connector_id", None)
        line["signal"] = "signal-truncated"
        encoded = json.dumps(line, sort_keys=True, separators=(",", ":"))
    print(encoded, file=sys.stderr)


def _dispatch_envelope(selected: Mapping[str, Any], request: Request) -> int:
    operation = _envelope_operation(request)
    started = time.monotonic()
    if operation in {"read", "get", "state"}:
        settings = _display_settings(selected)
        receipt = _get_reply(settings, selected)
    elif operation in {"set", "change", "mutate", "apply"}:
        supplied = {field: request.payload[field] for field in DISPLAY_FIELDS if field in request.payload}
        if operation == "apply" and _request_has_payload(request):
            receipt = _failure("apply-does-not-accept-payload", requested=supplied, backend=selected)
        elif operation != "apply" and not supplied:
            receipt = _failure("no-fields-supplied", backend=selected)
        else:
            settings = _display_settings(selected)
            receipt = _apply(selected, operation, supplied, settings)
    else:
        receipt = _failure(f"unsupported-operation:{operation}", backend=selected)
    if operation in {"set", "change", "mutate", "apply"}:
        _log_mutation(operation, receipt, started)
    print(json.dumps(attach(receipt, request), sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


def _parse_set_arguments(arguments: Sequence[str]) -> tuple[dict[str, Any] | None, str | None]:
    fields: list[str] = []
    values: list[Any] = []
    index = 0
    while index < len(arguments):
        if arguments[index] not in {"--field", "--value-json"} or index + 1 >= len(arguments):
            return None, "invalid-set-arguments"
        flag, value = arguments[index], arguments[index + 1]
        if flag == "--field":
            fields.append(value)
        else:
            try:
                values.append(json.loads(value))
            except (TypeError, json.JSONDecodeError):
                return None, "invalid-value-json"
        index += 2
    if not fields or len(fields) != len(values) or len(set(fields)) != len(fields):
        return None, "field-value-count-mismatch"
    return dict(zip(fields, values)), None


def _dispatch_argv(selected: Mapping[str, Any], original: Sequence[str]) -> int | None:
    arguments = list(original)
    if arguments and arguments[0] == "display":
        arguments = arguments[1:]
    if not arguments:
        return None
    operation = arguments[0].lower()
    started = time.monotonic()
    if operation in {"get", "read", "state"}:
        if arguments[1:] not in ([], ["--json"]):
            return None
        settings = _display_settings(selected)
        receipt = _get_reply(settings, selected)
    elif operation == "apply":
        if arguments[1:]:
            return None
        settings = _display_settings(selected)
        receipt = _apply(selected, operation, {}, settings)
    elif operation in {"set", "change", "mutate"}:
        supplied, error = _parse_set_arguments(arguments[1:])
        if error or supplied is None:
            receipt = _failure(error or "invalid-set-arguments", backend=selected)
        else:
            settings = _display_settings(selected)
            receipt = _apply(selected, operation, supplied, settings)
    else:
        return None
    if operation in {"set", "change", "mutate", "apply"}:
        _log_mutation(operation, receipt, started)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("ok") is True else 1


def main(argv: Sequence[str] | None = None) -> int:
    original = list(sys.argv[1:] if argv is None else argv)
    selected = backends.select_backend()
    if selected is None:
        return int(_shared.family_main("display", original) or 0)
    if original:
        result = _dispatch_argv(selected, original)
        if result is not None:
            return result
        return int(_shared.main(original) or 0)
    if sys.stdin.isatty():
        return int(_shared.main(original) or 0)
    try:
        request = read(known_fields=DISPLAY_FIELDS + ("args",))
    except (EnvelopeError, ValueError) as exc:
        print(json.dumps({"ok": False, "firstMissingSignal": str(exc),
                          "mutationPerformed": False}, sort_keys=True, separators=(",", ":")))
        return 1
    args = request.payload.get("args")
    if isinstance(args, list):
        result = _dispatch_argv(selected, args)
        if result is not None: return result
        print(json.dumps({"ok": False, "firstMissingSignal": "cli-parse-failure", "mutationPerformed": False}))
        return 1
    return _dispatch_envelope(selected, request)


if __name__ == "__main__":
    raise SystemExit(main())

"""Display policy facade: current owner backend, query and apply receipts."""
from __future__ import annotations

import json
import sys
import time
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence

sys.path.insert(0, str(Path(__file__).parents[3]))

from agathodaimon.settings import _shared
from agathodaimon.settings.display import backends, policy
from agathodaimon._envelope import EnvelopeError, Request, attach, read

DISPLAY_FIELDS = ("resolution", "refresh_rate", "scale", "orientation", "brightness", "night_light")
MODE_FIELDS = {"resolution", "refresh_rate"}


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
    }


def _kms_observation() -> dict[str, Any]:
    return policy.connected_connectors()


def _resolution_observation(connectors: Sequence[Mapping[str, Any]], settings: Mapping[str, Any]) -> dict[str, Any]:
    return policy.resolve_mode(connectors, settings)


def _get_reply(settings: Mapping[str, Any], selected: Mapping[str, Any]) -> dict[str, Any]:
    kind = selected.get("kind")
    kms = _kms_observation()
    if kind == "sway":
        sway = backends.observe_sway(str(selected["socket"]), kms)
        connectors = sway.get("connectors", []) if sway.get("ok") is True else []
        resolution = (_resolution_observation(connectors, settings) if sway.get("ok") is True
                      else {"ok": False, "connector": None, "mode": None,
                            "reason": str(sway.get("signal") or "sway-observation-unavailable"),
                            "fallback": False})
        live = {"ok": sway.get("ok") is True, "source": "sway-ipc",
                "preferred_exposed_by_sway": False,
                "kms_status": kms.get("status"), "kms_errors": kms.get("errors", []),
                "connectors": connectors, "signal": sway.get("signal")}
    else:
        return {"ok": False, "values": _values(settings), "mutationPerformed": False,
                "firstMissingSignal": "display-backend-unavailable"}
    reply: dict[str, Any] = {
        "ok": live.get("ok") is True,
        "values": _values(settings),
        "mutationPerformed": False,
        "observations": {
            "backend": dict(selected),
            "settings": {"source": settings.get("source"), "fallback": settings.get("fallback"),
                         "defaulted": settings.get("defaulted", [])},
            "live": live,
            "resolved": resolution,
        },
    }
    if live.get("ok") is not True:
        signal = live.get("signal")
        if not isinstance(signal, str) or not signal:
            errors = live.get("errors")
            if isinstance(errors, list) and errors and isinstance(errors[0], str) and errors[0]:
                signal = errors[0]
            else:
                signal = f"{str(live.get('source') or 'display')}-observation-unavailable"
        reply["firstMissingSignal"] = signal
    return reply


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


def _apply(selected: Mapping[str, Any], operation: str, supplied: Mapping[str, Any],
           settings: Mapping[str, Any]) -> dict[str, Any]:
    unsupported = _unsupported_field(supplied)
    if unsupported is not None:
        return _failure(f"unsupported:{unsupported}", settings=settings, backend=selected)
    try:
        effective = policy.validate_settings({
            "resolution": supplied.get("resolution", settings.get("resolution", "auto")),
            "refresh_rate": supplied.get("refresh_rate", settings.get("refresh_rate", policy.DEFAULT_REFRESH_RATE)),
        })
    except ValueError as exc:
        return _failure(f"invalid-display-setting:{exc}", settings=settings, backend=selected)
    kind = selected.get("kind")
    if kind == "sway":
        kms = _kms_observation()
        observed = backends.observe_sway(str(selected["socket"]), kms)
        if observed.get("ok") is not True:
            return _failure(str(observed.get("signal") or "sway-observation-unavailable"),
                            settings=settings, requested=effective, backend=selected)
        connectors = observed.get("connectors", [])
        resolved = _resolution_observation(connectors, effective)
        if resolved.get("ok") is not True:
            signal = ("display-no-connected-screen" if resolved.get("reason") == "no-connected-screen"
                      else "display-no-eligible-advertised-mode")
            return _failure(signal, settings=settings, requested=effective, backend=selected,
                            resolved=resolved)
        connector = resolved["connector"]
        mode = resolved["mode"]
        before = _current_summary(connector)
        result = backends.apply_sway_mode(str(selected["socket"]), connector, mode, kms)
        changed = not _mode_matches_current(mode, before)
        return {
            "ok": result.get("ok") is True,
            "changed": bool(result.get("ok") is True and changed),
            "mutationPerformed": result.get("mutation_performed") is True,
            "firstMissingSignal": result.get("signal") or "none",
            "values": _values(settings),
            "settingsSource": settings.get("source"),
            "backend": dict(selected),
            "requested": effective,
            "resolved": resolved,
            "current": {"before": before, "after": result.get("current_mode")},
            "physicalModeVerified": result.get("physical_mode_verified") is True,
            "swayCommand": result.get("command"),
        }
    return _failure("display-backend-unavailable", settings=settings, backend=selected)


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
        settings = policy.load_settings()
        receipt = _get_reply(settings, selected)
    elif operation in {"set", "change", "mutate", "apply"}:
        supplied = {field: request.payload[field] for field in DISPLAY_FIELDS if field in request.payload}
        if operation == "apply" and _request_has_payload(request):
            receipt = _failure("apply-does-not-accept-payload", requested=supplied, backend=selected)
        elif operation != "apply" and not supplied:
            receipt = _failure("no-fields-supplied", backend=selected)
        else:
            settings = policy.load_settings()
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
        settings = policy.load_settings()
        receipt = _get_reply(settings, selected)
    elif operation == "apply":
        if arguments[1:]:
            return None
        settings = policy.load_settings()
        receipt = _apply(selected, operation, {}, settings)
    elif operation in {"set", "change", "mutate"}:
        supplied, error = _parse_set_arguments(arguments[1:])
        if error or supplied is None:
            receipt = _failure(error or "invalid-set-arguments", backend=selected)
        else:
            settings = policy.load_settings()
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
        return int(_shared.main(original) or 0)
    if original:
        result = _dispatch_argv(selected, original)
        if result is not None:
            return result
        return int(_shared.main(original) or 0)
    if sys.stdin.isatty():
        return int(_shared.main(original) or 0)
    try:
        request = read(known_fields=DISPLAY_FIELDS)
    except (EnvelopeError, ValueError) as exc:
        print(json.dumps({"ok": False, "firstMissingSignal": str(exc),
                          "mutationPerformed": False}, sort_keys=True, separators=(",", ":")))
        return 1
    return _dispatch_envelope(selected, request)


if __name__ == "__main__":
    raise SystemExit(main())

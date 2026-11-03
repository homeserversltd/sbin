"""Dependency-free Caduceus wake-on-LAN staff door."""
from __future__ import annotations

import json
import sys
from importlib import import_module
from typing import Any, Sequence

try:
    _wol = import_module("agathodaimon.network.wake-on-lan._wol")
except ModuleNotFoundError as exc:
    if exc.name != "agathodaimon":
        raise
    import _wol

_json, send, probe = _wol._json, _wol.send, _wol.probe


def _usage_error(message: str) -> int:
    return _json({"ok": False, "error": message})


def _dispatch(command: Any, values: dict[str, Any]) -> dict[str, Any]:
    if command == "send":
        if "mac" not in values or set(values) - {"mac", "broadcast"}:
            raise ValueError("send requires mac and accepts only broadcast")
        return send(values["mac"], values.get("broadcast", "255.255.255.255"))
    if command == "probe":
        if set(values) != {"ip"}:
            raise ValueError("probe requires ip")
        return probe(values["ip"])
    raise ValueError("expected send or probe")


def _envelope() -> tuple[Any, dict[str, Any]]:
    try:
        envelope = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"invalid JSON envelope: {exc}") from exc
    if not isinstance(envelope, dict) or envelope.get("actuator") != "wake-on-lan":
        raise ValueError("envelope actuator must be \"wake-on-lan\"")
    metadata = envelope.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("envelope metadata must be an object")
    return metadata.get("action"), {key: value for key, value in metadata.items() if key != "action"}


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        try:
            command, values = _envelope()
            return _json(_dispatch(command, values))
        except ValueError as exc:
            return _usage_error(str(exc))
    if args[0] not in {"send", "probe"}:
        return _usage_error("expected send or probe")
    command = args.pop(0)
    values: dict[str, str] = {}
    while args:
        flag = args.pop(0)
        if flag not in {"--mac", "--broadcast", "--ip"} or not args or args[0].startswith("--"):
            return _usage_error("invalid arguments")
        values[flag[2:]] = args.pop(0)
    try:
        return _json(_dispatch(command, values))
    except ValueError as exc:
        return _usage_error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
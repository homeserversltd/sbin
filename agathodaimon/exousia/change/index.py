#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.exousia._common import ExousiaUnprovisioned, MalformedInput, invoke_library


def _refuse(signal):
    print(json.dumps({"ok": False, "firstMissingSignal": signal}, separators=(",", ":")))


def _pin(value, field, name):
    if field not in value or value[field] == "":
        raise MalformedInput("exousia-pin-" + name + "-missing")
    pin = value[field]
    if not isinstance(pin, str) or len(pin) > 512:
        raise MalformedInput("exousia-pin-invalid")
    return pin


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        _refuse("exousia-change-argument-extra")
        return 2
    try:
        try:
            request = read(known_fields=("oldPin", "newPin"), declared_flags=("oldPin", "newPin"))
        except (EnvelopeError, RecursionError) as exc:
            message = str(exc)
            if message == "foreign envelope schema":
                signal = "exousia-change-envelope-foreign"
            elif message.startswith("missing envelope kernel keys:"):
                signal = "exousia-change-envelope-kernel-missing"
            else:
                signal = "exousia-change-envelope-invalid"
            raise MalformedInput(signal) from exc
        value = request.payload
        old_pin, new_pin = _pin(value, "oldPin", "old"), _pin(value, "newPin", "new")
        result = invoke_library("atomic-change-pin", {"oldPin": old_pin, "newPin": new_pin})
        signal = result.get("firstMissingSignal")
        if result.get("ok") is False and isinstance(signal, str) and signal:
            raise ExousiaUnprovisioned(signal)
        if result.get("ok") is True:
            public_key, epoch = result.get("publicKey"), result.get("epoch")
            if not isinstance(public_key, str) or not isinstance(epoch, str):
                raise RuntimeError("invalid caduceus change response")
            result = {"ok": True, "publicKey": public_key, "epoch": epoch}
        elif result != {"ok": False}:
            raise RuntimeError("invalid caduceus change response")
    except MalformedInput as exc:
        _refuse(str(exc))
        return 2
    except ExousiaUnprovisioned as exc:
        print(json.dumps(attach({"ok": False, "firstMissingSignal": str(exc)}, request), separators=(",", ":")))
        return 0
    except Exception:  # noqa: BLE001
        print("exousia internal failure", file=sys.stderr)
        _refuse("exousia-change-internal-failure")
        return 1
    print(json.dumps(attach(result, request), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

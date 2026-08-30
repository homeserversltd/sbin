#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.exousia._common import ExousiaUnprovisioned, MalformedInput, invoke_launcher, text


def _is_pin_refusal(signal):
    normalized = signal.lower()
    return "pin-refused" in normalized or normalized == "caduceus-staff-derived-key-mismatch"


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        return 2
    try:
        try:
            request = read(known_fields=("oldPin", "newPin"), declared_flags=("oldPin", "newPin"))
        except EnvelopeError as exc:
            raise MalformedInput(str(exc)) from exc
        value = request.payload
        old_pin, new_pin = text(value, "oldPin"), text(value, "newPin")
        result = invoke_launcher("/usr/local/sbin/caduceus-atomic-change-pin", {"oldPin": old_pin, "newPin": new_pin})
        signal = result.get("firstMissingSignal")
        if result.get("ok") is False and isinstance(signal, str) and signal:
            if _is_pin_refusal(signal):
                result = {"ok": False}
            else:
                raise ExousiaUnprovisioned(signal)
        if result.get("ok") is True:
            public_key, epoch = result.get("publicKey"), result.get("epoch")
            if not isinstance(public_key, str) or not isinstance(epoch, str):
                raise RuntimeError("invalid caduceus change response")
            result = {"ok": True, "publicKey": public_key, "epoch": epoch}
        elif result != {"ok": False}:
            raise RuntimeError("invalid caduceus change response")
    except MalformedInput as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except ExousiaUnprovisioned as exc:
        print(json.dumps(attach({"ok": False, "firstMissingSignal": str(exc)}, request), separators=(",", ":")))
        return 0
    except Exception:  # noqa: BLE001
        print("exousia internal failure", file=sys.stderr)
        return 1
    print(json.dumps(attach(result, request), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

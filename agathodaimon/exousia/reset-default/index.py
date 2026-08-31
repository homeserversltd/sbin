#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon.exousia._common import (
    ExousiaUnprovisioned,
    MalformedInput,
    close,
    keyman,
    paths,
    public,
    text,
)


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        return 2
    try:
        try:
            value = json.load(sys.stdin)
        except json.JSONDecodeError as exc:
            raise MalformedInput("invalid JSON") from exc
        if not isinstance(value, dict) or set(value) != {"newPin"}:
            raise MalformedInput("unexpected exousia fields")
        new_pin = text(value, "newPin")
        key_dir, vault_dir = paths()
        manager = keyman(allow_missing_caduceus=True)
        reset = getattr(manager, "reset_caduceus_pin", None)
        if not callable(reset):
            print(json.dumps({"ok": False, "firstMissingSignal": "keyman-reset-primitive-absent"}, separators=(",", ":")))
            return 0
        try:
            reset(new_pin, key_dir=key_dir, vault_dir=vault_dir)
        except Exception:  # noqa: BLE001
            print(json.dumps({"ok": False, "firstMissingSignal": "keyman-reset-refused"}, separators=(",", ":")))
            return 0
        signer = manager.bind_derived_caduceus(key_dir=key_dir, vault_dir=vault_dir)
        try:
            signer_public, signer_epoch = public(signer)
            result = {"ok": True, "publicKey": signer_public, "epoch": signer_epoch}
        finally:
            close(signer)
    except MalformedInput as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except ExousiaUnprovisioned:
        print(json.dumps({"ok": False, "firstMissingSignal": "exousia-unprovisioned"}, separators=(",", ":")))
        return 0
    except Exception:  # noqa: BLE001
        print(json.dumps({"ok": False, "firstMissingSignal": "keyman-reset-refused"}, separators=(",", ":")))
        return 0
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

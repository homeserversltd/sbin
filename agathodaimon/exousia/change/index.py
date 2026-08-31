#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.exousia._common import (
    ExousiaUnprovisioned,
    MalformedInput,
    close,
    keyman,
    paths,
    public,
    text,
)


def _refused(exc):
    message = str(exc).lower()
    return "agathodaimon-pin-refused" in message or "caduceus-pin-refused" in message


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
        key_dir, vault_dir = paths()
        manager = keyman()
        try:
            manager.change_caduceus_pin(old_pin, new_pin, key_dir=key_dir, vault_dir=vault_dir)
        except Exception as exc:
            if not _refused(exc):
                raise
            print(json.dumps(attach({"ok": False}, request), separators=(",", ":")))
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
        print("exousia internal failure", file=sys.stderr)
        return 1
    print(json.dumps(attach(result, request), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

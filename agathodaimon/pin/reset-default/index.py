#!/usr/bin/env python3
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon.attendance._common import (  # noqa: E402
    AttendanceUnprovisioned,
    MalformedInput,
    close,
    keyman,
    paths,
    public,
)


def _refused(exc):
    message = str(exc).lower()
    return "agathodaimon-pin-refused" in message or "caduceus-pin-refused" in message


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one pin verb is required", file=sys.stderr)
        return 2
    try:
        value = json.load(sys.stdin)
        if not isinstance(value, dict) or set(value) != set():
            raise MalformedInput("unexpected pin fields")
        key_dir, vault_dir = paths()
        manager = keyman(allow_missing_caduceus=True)
        try:
            if (vault_dir / "caduceus.key").is_file():
                manager.change_caduceus_pin("1", "1", key_dir=key_dir, vault_dir=vault_dir)
            else:
                manager.provision_caduceus("1", key_dir=key_dir, vault_dir=vault_dir)
        except Exception as exc:
            if not _refused(exc):
                raise
            print(json.dumps({"ok": False}, separators=(",", ":")))
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
    except AttendanceUnprovisioned:
        print(json.dumps({"ok": False, "firstMissingSignal": "attendance-unprovisioned"}, separators=(",", ":")))
        return 0
    except Exception:
        print("pin internal failure", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

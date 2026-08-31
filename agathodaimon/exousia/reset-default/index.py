#!/usr/bin/env python3
import contextlib
import importlib.util
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon._envelope import EnvelopeError, attach, read


KEYMAN_PATH = Path(os.environ.get("AGATHODAIMON_KEYMAN_MODULE", "/opt/keyman/runtime/lib/keyman_caduceus_access.py"))
KEYMAN_KEY_DIR_DEFAULT = "/root/key"
KEYMAN_VAULT_DIR_DEFAULT = "/vault/.keys"


def _load_keyman():
    try:
        spec = importlib.util.spec_from_file_location("exousia_keyman", KEYMAN_PATH)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except Exception:  # noqa: BLE001
            sys.modules.pop(spec.name, None)
            return None
        return module
    except Exception:  # noqa: BLE001
        return None


def _valid_hex(value):
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdefABCDEF" for char in value
    )


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        return 2
    try:
        request = read(known_fields=("newPin",), declared_flags=("newPin",))
    except EnvelopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        value = request.payload
        if set(value) != {"newPin"}:
            raise ValueError
        new_pin = value["newPin"]
        if not isinstance(new_pin, str) or not new_pin or len(new_pin) > 512:
            raise ValueError
    except (TypeError, ValueError):
        print("newPin missing or invalid", file=sys.stderr)
        return 2

    key_dir = Path(os.environ.get("CADUCEUS_KEYMAN_KEY_DIR", KEYMAN_KEY_DIR_DEFAULT))
    vault_dir = Path(os.environ.get("CADUCEUS_KEYMAN_VAULT_DIR", KEYMAN_VAULT_DIR_DEFAULT))
    if not (key_dir / "skeleton.key").is_file() or not (vault_dir / "service_suite.key").is_file() or not KEYMAN_PATH.is_file():
        result = {"ok": False, "firstMissingSignal": "exousia-unprovisioned"}
        print(json.dumps(attach(result, request), separators=(",", ":")))
        return 0

    manager = _load_keyman()
    reset = getattr(manager, "reset_caduceus_pin", None) if manager is not None else None
    if not callable(reset):
        result = {"ok": False, "firstMissingSignal": "keyman-reset-primitive-absent"}
        print(json.dumps(attach(result, request), separators=(",", ":")))
        return 0

    try:
        reset(new_pin, key_dir=key_dir, vault_dir=vault_dir)
        signer = manager.bind_derived_caduceus(key_dir=key_dir, vault_dir=vault_dir)
        try:
            public_key = getattr(signer, "public_key_hex", None)
            if callable(public_key):
                public_key = public_key()
            epoch = getattr(signer, "signer_epoch", getattr(signer, "epoch", None))
            if callable(epoch):
                epoch = epoch()
            if not _valid_hex(public_key) or not _valid_hex(epoch):
                raise ValueError
            result = {"ok": True, "publicKey": public_key, "epoch": epoch}
        finally:
            with contextlib.suppress(Exception):
                close = getattr(signer, "close", None)
                if callable(close):
                    close()
    except Exception:  # noqa: BLE001
        result = {"ok": False, "firstMissingSignal": "keyman-reset-refused"}

    print(json.dumps(attach(result, request), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

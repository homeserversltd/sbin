"""Open a vault using device, mapper and mountpoint; passphrase is stdin-only, or seated_record selects the seated credential."""
from __future__ import annotations

import json
import sys
from io import StringIO
from typing import Sequence

from agathodaimon import _envelope
from agathodaimon.storage.vault.open import _core

MAX_INPUT_BYTES = 131072


def main(argv: Sequence[str] | None = None) -> int:
    request = None
    secret = None
    raw = bytearray()
    try:
        if argv:
            raise ValueError("arguments refused")
        raw.extend(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("request too large")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("invalid request")
        payload = value.get("payload") if "schema" in value else value
        if not isinstance(payload, dict):
            raise ValueError("invalid payload")
        passphrase = payload.pop("passphrase", None)
        passphrase_valid = passphrase is None or isinstance(passphrase, str)
        if isinstance(passphrase, str):
            try:
                secret = bytearray(passphrase.encode("utf-8"))
            except UnicodeError:
                passphrase_valid = False
        del passphrase
        stream = sys.stdin
        try:
            sys.stdin = StringIO(json.dumps(value, ensure_ascii=True, separators=(",", ":")))
            request = _envelope.read_fields("device", "mapper", "mountpoint", "passphrase", "seated_record")
        finally:
            sys.stdin = stream
        nouns = request.payload
        seated = nouns.get("seated_record", False)
        if not isinstance(seated, bool):
            receipt = _core._unlock_receipt(False, secret is not None, "agathodaimon-vault-open-request-invalid")
        elif seated:
            if "mountpoint" in nouns or secret is not None or not passphrase_valid:
                receipt = _core._receipt(False, True, "agathodaimon-vault-open-request-invalid")
            else:
                receipt = _core.open_from_seated_record({key: nouns[key] for key in ("device", "mapper") if key in nouns})
        else:
            direct = {key: nouns[key] for key in ("device", "mapper", "mountpoint") if key in nouns}
            receipt = _core._unlock(direct, secret, passphrase_valid)
    except (ValueError, TypeError, UnicodeError, OSError, _envelope.EnvelopeError):
        receipt = _core._receipt(False, True, "agathodaimon-vault-open-request-invalid")
    finally:
        _core._wipe(raw)
        if secret is not None:
            _core._wipe(secret)
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

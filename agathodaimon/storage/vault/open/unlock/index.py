"""Open a vault using device, mapper and mountpoint; passphrase is stdin-only, or seated_record selects the seated credential."""
from __future__ import annotations

import json
from dataclasses import replace
from typing import Sequence

from agathodaimon import _envelope
from agathodaimon.storage.vault.open import _core

def main(argv: Sequence[str] | None = None) -> int:
    request = None
    secret = None
    try:
        if argv:
            raise ValueError("arguments refused")
        request = _envelope.read_fields(
            "device", "mapper", "mountpoint", "passphrase", "seated_record",
            secret_bytes=("passphrase",), max_input_bytes=_core.MAX_INPUT_BYTES,
        )
        secret = request.secret_bytes.get("passphrase")
        if request.envelope and not isinstance(request.value.get("payload"), dict):
            request = None
            raise ValueError("invalid payload")
        nouns = request.payload
        seated = nouns.get("seated_record", False)
        if not isinstance(seated, bool):
            receipt = _core._unlock_receipt(False, secret is not None, "agathodaimon-vault-open-request-invalid")
        elif seated:
            if "mountpoint" in nouns or secret is not None:
                receipt = _core._request_refusal()
            else:
                receipt = _core.open_from_seated_record({key: nouns[key] for key in ("device", "mapper") if key in nouns})
        else:
            direct = {key: nouns[key] for key in ("device", "mapper", "mountpoint") if key in nouns}
            receipt = _core._unlock(direct, secret, True)
    except (ValueError, TypeError, OSError) as exc:
        receipt = _core._request_refusal(exc)
    finally:
        if secret is not None:
            _envelope.wipe_bytes(secret)
    if request is not None:
        # Intake removed the field and refused every other placement. Keep
        # attaching the sanitized remainder as before; PIN protection still applies.
        receipt = _envelope.attach(receipt, replace(request, secret_fields=(), secret_bytes={}))
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

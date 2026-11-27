"""Observe whether the bound VPN provider has a safely seated key."""
from __future__ import annotations

import json
from typing import Any

from agathodaimon.cli import _stamp_receipt
from agathodaimon.transmission import runtime as rt
from agathodaimon.transmission.keys import index as keys


def main(argv: Any = None) -> int:
    del argv
    request = None
    result = rt.receipt()
    result.update(configured=None, keys=None, mutationPerformed=False)
    try:
        request = rt.read_request()
        options, _providers = rt.resolve_bound_vpn(request)
        provider = options["provider"]
        result["provider"] = provider
        if not keys._vault_mount_proven():
            raise rt.TransmissionError("transmission-vault-locked", "key-presence")
        presence = keys._observe_key_map(result, [provider])
        result.update(ok=True, configured=presence[provider] == "present",
                      firstMissingSignal="none")
    except Exception as failure:
        failed = rt.failure_receipt(failure, result.get("provider"))
        result.update(failed)
    result = rt.finish(result, request, successful_read=result.get("ok") is True)
    result = _stamp_receipt(result, "transmission/vpn/configured")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    if result.get("ok") is not True:
        return 255
    return 0 if result.get("configured") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

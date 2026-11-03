"""Receipt handling for the fixed-act Tailscale stops."""
import copy
import json
from dataclasses import replace

from agathodaimon import _envelope
from agathodaimon.network.tailscale import _core


def _safe_request(action, request):
    safe = _core._safe_request(request)
    if action != "authkey":
        return safe
    value = copy.deepcopy(safe.value)
    payload = copy.deepcopy(safe.payload)

    def redact_key(item):
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "key":
                    item[key] = "[REDACTED]"
                else:
                    redact_key(child)
        elif isinstance(item, list):
            for child in item:
                redact_key(child)

    redact_key(value)
    redact_key(payload)
    return replace(safe, value=value, payload=payload,
                   raw_envelope=json.dumps(value, separators=(",", ":"), ensure_ascii=False))


def finish(action, operation, request, *args):
    if request is None:
        receipt = _core._receipt(action, False, "tailscale-envelope-invalid", attempt="read-envelope")
    else:
        try:
            receipt = operation(*args)
        except Exception:
            signals = {"status": "tailscale-status-failed", "up": "tailscale-up-failed",
                       "down": "tailscale-down-failed", "authkey": "tailscale-authkey-failed",
                       "tailnet": "tailscale-tailnet-failed"}
            receipt = _core._receipt(action, False, signals[action], attempt="bounded-operation")
        receipt = _envelope.attach(receipt, _safe_request(action, request))
    receipt["schema"] = f"caduceus.network.tailscale.{action}.v1"
    receipt = _core._scrub(receipt)
    print(json.dumps(receipt, sort_keys=True, ensure_ascii=False))
    return 0 if receipt.get("ok") is True else 1

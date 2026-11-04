"""Envelope-facing fixed-operation policy stops over the legacy writer."""
import json

from agathodaimon import _envelope
from agathodaimon.storage.vault.policy import _policy


def run(request, op):
    payload = dict(request.payload)
    payload["op"] = op
    try:
        receipt = _policy._dispatch(payload)
    except Exception:
        receipt = _policy._receipt(False, op, None, None, f"vault-policy-{op}-failed")
    receipt["schema"] = f"caduceus.storage.vault.policy.{op}.v1"
    receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


def invalid_envelope(op):
    receipt = _policy._receipt(False, op, None, None, "vault-policy-mapper-invalid")
    receipt["schema"] = f"caduceus.storage.vault.policy.{op}.v1"
    print(json.dumps(receipt, sort_keys=True))
    return 1

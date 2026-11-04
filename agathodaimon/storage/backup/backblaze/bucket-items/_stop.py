"""Envelope adapters for the two fixed bucket-item acts."""
import json

from agathodaimon import _envelope
from agathodaimon.storage.backup.backblaze import shared


def run(act, request):
    prefix = "backblaze-bucket-items-" + act
    if request.payload.get("dry-run"):
        result = {"ok": False, "firstMissingSignal": prefix + "-dry-run-unsupported"}
    else:
        metadata = {key: request.payload[key] for key in ("bucket", "path", "expected") if key in request.payload}
        metadata["op"] = act
        result = shared.main_for("bucket-items", {"actuator": "backblaze-bucket-items", "metadata": metadata}, True, deed_verb=prefix)
        if result.get("ok"):
            result["firstMissingSignal"] = "none"
        else:
            signals = {
                "bucket-invalid": "bucket-invalid",
                "bucket-not-configured": "bucket-not-configured",
                "item-path-invalid": "path-invalid",
                "config-update-active": "config-update-active",
                "bucket-run-active": "bucket-run-active",
                "bucket changed; refresh before saving": "expected-mismatch",
            }
            result["firstMissingSignal"] = prefix + "-" + signals.get(result.get("reason"), "unavailable")
    return _envelope.attach(result, request)


def finish(act, receipt):
    receipt["schema"] = "caduceus.storage.backup.backblaze.bucket-items." + act + ".v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1

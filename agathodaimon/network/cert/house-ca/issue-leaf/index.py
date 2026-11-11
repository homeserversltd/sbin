"""House CA issue-leaf stop."""
import importlib.util
import json
from pathlib import Path
from agathodaimon import _envelope

_spec = importlib.util.spec_from_file_location("_house_ca", Path(__file__).parents[1] / "_ca.py")
if _spec is None or _spec.loader is None:
    raise ImportError("cannot load house-ca primitives")
ca = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ca)

def names(value):
    return value.split(",") if isinstance(value, str) and value else value or ()

def boolean(payload, name):
    value = payload.get(name, False)
    if type(value) is not bool:
        raise ValueError("agathodaimon-house-ca-boolean-invalid")
    return value

def main(argv=None):
    request = None
    try:
        request = _envelope.read_fields('identity', 'sans', 'ips', 'dry-run')
        p = request.payload
        if not isinstance(p.get("identity"), str) or not p["identity"].strip():
            raise ValueError("agathodaimon-house-ca-identity-required")
        with ca.house_ca_lock():
            receipt = ca.issue_leaf(p["identity"], names(p.get("sans")), names(p.get("ips")), dry_run=boolean(p, "dry-run"))
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError, ca.subprocess.TimeoutExpired) as error:
        signal = str(error) if str(error) in ("agathodaimon-house-ca-busy", "agathodaimon-house-ca-identity-required") else ("agathodaimon-house-ca-timeout" if isinstance(error, ca.subprocess.TimeoutExpired) else "agathodaimon-house-ca-refused")
        receipt = ca._refusal("error", signal)
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.cert.house-ca.issue-leaf.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1

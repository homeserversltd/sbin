"""House CA apply-nginx stop."""
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
        request = _envelope.read_fields('portal', 'upstream', 'certificate', 'key-path', 'aliases', 'dry-run')
        p = request.payload
        with ca.house_ca_lock():
            receipt = ca.apply_nginx(p.get("portal"), p.get("upstream"), p.get("certificate"), p.get("key-path"), names(p.get("aliases")), dry_run=boolean(p, "dry-run"))
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError, ca.subprocess.TimeoutExpired) as error:
        signal = "agathodaimon-house-ca-busy" if str(error) == "agathodaimon-house-ca-busy" else ("agathodaimon-house-ca-timeout" if isinstance(error, ca.subprocess.TimeoutExpired) else "agathodaimon-house-ca-refused")
        receipt = ca._refusal("error", signal)
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.cert.house-ca.apply-nginx.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1

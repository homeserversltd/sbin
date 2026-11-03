"""House CA sign-csr stop."""
import copy
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
from agathodaimon import _envelope

_spec = importlib.util.spec_from_file_location("_house_ca", Path(__file__).parents[1] / "_ca.py")
if _spec is None or _spec.loader is None:
    raise ImportError("cannot load house-ca primitives")
ca = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ca)

def main(argv=None):
    request = None
    try:
        request = _envelope.read_fields('csrPem')
        p = request.payload
        receipt = ca.sign_csr(p.get("csrPem"))
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError):
        receipt = ca._refusal("error", "agathodaimon-house-ca-refused")
    if request is not None:
        carried = copy.deepcopy(request.value)
        container = carried.get("payload") if request.envelope else carried
        if isinstance(container, dict) and "csrPem" in container:
            container["csrPem"] = "[REDACTED]"
        request = replace(request, value=carried, raw_envelope=json.dumps(carried))
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.cert.house-ca.sign-csr.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1

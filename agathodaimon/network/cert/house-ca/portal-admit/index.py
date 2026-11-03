"""Admit a HomeServer portal using the house CA composite."""
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
        request = _envelope.read_fields('portal', 'lan-ip', 'upstream', 'aliases', 'dry-run')
        p = request.payload
        aliases = p.get("aliases")
        aliases = aliases.split(",") if isinstance(aliases, str) and aliases else aliases or ()
        dry_run = p.get("dry-run", False)
        if type(dry_run) is not bool:
            raise ValueError("agathodaimon-house-ca-boolean-invalid")
        receipt = ca.portal_admit(p.get("portal"), p.get("lan-ip"), p.get("upstream"), aliases, dry_run=dry_run)
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError):
        receipt = ca._refusal("error", "agathodaimon-house-ca-refused")
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.cert.house-ca.portal-admit.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1

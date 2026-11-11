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
        request = _envelope.read_fields('portal', 'upstream', 'certificate', 'key-path', 'aliases', 'tailnet-port', 'locations', 'max-body-size', 'read-timeout', 'dry-run')
        p = request.payload
        with ca.house_ca_lock():
            portal = p.get("portal")
            state = json.loads(ca.state_path().read_text()).get(ca.SCHEMA, {}) if ca.state_path().is_file() else {}
            prior = next((row for row in state.get("portals", []) if row.get("fqdn") == portal), {})
            upstream = p.get("upstream") if p.get("upstream") is not None else prior.get("upstream")
            aliases = p.get("aliases") if p.get("aliases") is not None else prior.get("aliases", [])
            locations = p.get("locations") if p.get("locations") is not None else prior.get("locations")
            if isinstance(locations, str):
                locations = json.loads(locations)
            port = p.get("tailnet-port") if p.get("tailnet-port") is not None else prior.get("tailnet_port")
            size = p.get("max-body-size") if p.get("max-body-size") is not None else prior.get("max_body_size", "1m")
            timeout = p.get("read-timeout") if p.get("read-timeout") is not None else prior.get("read_timeout", 60)
            certificate = p.get("certificate") or str(ca.cert_dir() / f"{portal}.pem")
            key_path = p.get("key-path") or str(ca.cert_dir() / f"{portal}.key.pem")
            receipt = ca.apply_nginx(portal, upstream, certificate, key_path, names(aliases), tailnet_port=port, locations=locations, max_body_size=size, read_timeout=timeout, dry_run=boolean(p, "dry-run"))
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError, ca.subprocess.TimeoutExpired) as error:
        signal = "agathodaimon-house-ca-busy" if str(error) == "agathodaimon-house-ca-busy" else ("agathodaimon-house-ca-timeout" if isinstance(error, ca.subprocess.TimeoutExpired) else "agathodaimon-house-ca-refused")
        receipt = ca._refusal("error", signal)
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    receipt["schema"] = "caduceus.network.cert.house-ca.apply-nginx.v1"
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt.get("ok") else 1

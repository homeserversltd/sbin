"""House CA apply-nginx stop."""
import importlib.util
import json
from pathlib import Path
from agathodaimon import _envelope

_spec = importlib.util.spec_from_file_location('_house_ca', Path(__file__).parents[1] / '_ca.py')
if _spec is None or _spec.loader is None:
    raise ImportError('cannot load house-ca primitives')
ca = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ca)


def names(value):
    return value.split(',') if isinstance(value, str) and value else value or ()


def boolean(payload, name):
    value = payload.get(name, False)
    if type(value) is not bool:
        raise ValueError('agathodaimon-house-ca-boolean-invalid')
    return value


def main(argv=None):
    request = None
    fields = ('portal', 'upstream', 'certificate', 'key-path', 'aliases', 'tailnet-port', 'locations', 'max-body-size', 'read-timeout', 'dry-run')
    served = list(fields) + ['template']
    try:
        request = _envelope.read_fields(*fields)
        raw = request.value.get('payload', {}) if request.envelope else request.value
        seat = ca._hestia_seat()
        if seat:
            served.extend(seat.get('notes', {}))
        extras = [key for key in raw if key not in served]
        if extras:
            raise ValueError(('unknown-field:' + extras[0]) if seat else 'agathodaimon-hestia-seat-absent')
        notes = {key: raw[key] for key in served if key not in fields and key in raw}
        p = request.payload
        locations = p.get('locations')
        if isinstance(locations, str):
            locations = json.loads(locations)
        aliases = names(p.get('aliases')) if p.get('aliases') is not None else None
        portal = p.get('portal')
        dry_run = boolean(p, 'dry-run')
        def preflight():
            return ca._portal_route_preflight(portal, p.get('upstream'), p.get('tailnet-port'), locations, p.get('max-body-size'), p.get('read-timeout'), notes, aliases, require_tailnet_name=False)[0]
        preflight()
        with ca.house_ca_lock():
            row = preflight()
            certificate = p.get('certificate') or str(ca.cert_dir() / f'{portal}.pem')
            key_path = p.get('key-path') or str(ca.cert_dir() / f'{portal}.key.pem')
            receipt = ca.apply_nginx(portal, row.get('upstream'), certificate, key_path, row.get('aliases', []), tailnet_port=row.get('tailnet_port'), locations=row.get('locations'), max_body_size=row['max_body_size'], read_timeout=row['read_timeout'], row=row, dry_run=dry_run)
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError, ca.subprocess.TimeoutExpired) as error:
        text = str(error)
        signal = text if text.startswith(('agathodaimon-hestia-', 'unknown-field:')) or text in ('agathodaimon-house-ca-busy', 'agathodaimon-nginx-input-invalid', 'agathodaimon-portal-tailnet-name-unavailable') else ('agathodaimon-house-ca-timeout' if isinstance(error, ca.subprocess.TimeoutExpired) else 'agathodaimon-house-ca-refused')
        receipt = ca._refusal('error', signal)
        receipt['served_fields'] = served
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    receipt['schema'] = 'caduceus.network.cert.house-ca.apply-nginx.v1'
    print(json.dumps(receipt, separators=(',', ':')))
    return 0 if receipt.get('ok') else 1

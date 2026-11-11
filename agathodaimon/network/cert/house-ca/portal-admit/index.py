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
    fields = ('portal', 'lan-ip', 'upstream', 'aliases', 'owner-mac', 'origin', 'claim-tiles', 'tailnet-port', 'locations', 'max-body-size', 'read-timeout', 'dry-run')
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
        aliases = p.get('aliases')
        aliases = aliases.split(',') if isinstance(aliases, str) else aliases
        claim_tiles = p.get('claim-tiles')
        claim_tiles = claim_tiles.split(',') if isinstance(claim_tiles, str) and claim_tiles else claim_tiles or ()
        locations = p.get('locations')
        if isinstance(locations, str):
            try:
                locations = json.loads(locations)
            except json.JSONDecodeError:
                raise ValueError('agathodaimon-nginx-input-invalid') from None
        dry_run = p.get('dry-run', False)
        if type(dry_run) is not bool:
            raise ValueError('agathodaimon-house-ca-boolean-invalid')
        if dry_run and not ca.state_path().parent.is_dir():
            raise ValueError('agathodaimon-house-ca-state-directory-absent')
        policy = {'max_body_size': p.get('max-body-size'), 'read_timeout': p.get('read-timeout')}
        ca._portal_route_preflight(p.get('portal'), p.get('upstream'), p.get('tailnet-port'), locations, notes=notes, aliases=aliases, **policy)
        with ca.house_ca_lock():
            receipt = ca.portal_admit(p.get('portal'), p.get('lan-ip'), p.get('upstream'), aliases, owner_mac=p.get('owner-mac'), origin=p.get('origin'), claim_tiles=claim_tiles, tailnet_port=p.get('tailnet-port'), locations=locations, dry_run=dry_run, notes=notes, **policy)
    except (_envelope.EnvelopeError, OSError, ValueError, TypeError, AttributeError, RuntimeError, ca.subprocess.CalledProcessError, ca.subprocess.TimeoutExpired) as error:
        text = str(error)
        signal = text if text.startswith(('agathodaimon-hestia-', 'unknown-field:')) or text in ('agathodaimon-house-ca-busy', 'agathodaimon-nginx-input-invalid', 'agathodaimon-portal-tailnet-name-unavailable') else ('agathodaimon-house-ca-timeout' if isinstance(error, ca.subprocess.TimeoutExpired) else 'agathodaimon-house-ca-refused')
        receipt = ca._refusal('error', signal)
        receipt['served_fields'] = served
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    receipt['schema'] = 'caduceus.network.cert.house-ca.portal-admit.v1'
    print(json.dumps(receipt, separators=(',', ':')))
    return 0 if receipt.get('ok') else 1

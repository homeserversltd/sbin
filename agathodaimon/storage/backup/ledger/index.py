"""Read a bounded, newest-first page of backup deeds from the appliance log."""
from __future__ import annotations

import json
import re
import sys

from agathodaimon.storage.backup.backblaze import shared

SCHEMA = 'caduceus.backup.ledger.v1'
CHUNK = 65536
BUDGET = 8 * 1024 * 1024


def project(value):
    if not isinstance(value, dict):
        return None
    verb = value.get('verb')
    target = value.get('target')
    if not isinstance(verb, str) or not re.fullmatch(r'[a-z0-9-]{1,128}', verb):
        return None
    if verb == 'pid2-fire-interrupted-by-boot':
        job, target = 'drives', 'nas-sync'
    elif verb.startswith('backblaze-'):
        job = 'offsite'
        target = value.get('bucket') if verb == 'backblaze-forgejo-b2-push' else target
        if not shared.valid_bucket(target):
            target = None
    elif target == 'nas-sync':
        job = 'drives'
    else:
        return None
    at = value.get('at')
    if not isinstance(at, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', at):
        at = None
    outcome = value.get('outcome')
    if outcome not in ('ok', 'failed', 'refused', 'interrupted'):
        outcome = None
    duration = value.get('duration_ms')
    if type(duration) is not int or duration < 0:
        duration = None
    signal = value.get('signal')
    if not isinstance(signal, str) or not re.fullmatch(r'[A-Za-z0-9._+-]{1,128}', signal):
        signal = None
    row = {'at': at,
           'job': job, 'verb': verb, 'target': target,
           'outcome': outcome, 'duration_ms': duration, 'signal': signal}
    for key in ('added_bytes', 'total_bytes'):
        if type(value.get(key)) is int and value[key] >= 0:
            row[key] = value[key]
    return row


def page(before, limit):
    rows = []
    try:
        with shared.log_path().open('rb') as stream:
            stream.seek(0, 2)
            size = stream.tell()
            end = size if before is None else min(before, size)
            position = end
            pending = b''
            read = 0
            while position > 0 and read < BUDGET:
                amount = min(CHUNK, position, BUDGET - read)
                position -= amount
                stream.seek(position)
                pending = stream.read(amount) + pending
                read += amount
                while b'\n' in pending:
                    cut = pending.rfind(b'\n')
                    line = pending[cut + 1:]
                    pending = pending[:cut]
                    if not line:
                        continue
                    try:
                        row = project(json.loads(line))
                    except (ValueError, UnicodeError):
                        continue
                    if row is not None:
                        rows.append(row)
                        if len(rows) == limit:
                            cursor = position + cut + 1
                            return rows, cursor or None
            if position == 0:
                if pending:
                    try:
                        row = project(json.loads(pending))
                    except (ValueError, UnicodeError):
                        row = None
                    if row is not None:
                        rows.append(row)
                return rows, None
            # Revisit the partial oldest line; an over-budget line is skipped
            # so a malicious or damaged log cannot trap the cursor forever.
            cursor = position + len(pending)
            return rows, (position if cursor >= end else cursor) or None
    except FileNotFoundError:
        return [], None


def main(argv=None):
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError('request-invalid')
        payload = request.get('payload')
        metadata = request.get('metadata')
        if isinstance(payload, dict):
            metadata = payload.get('metadata', payload) if payload else metadata
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError('metadata-invalid')
        before = metadata.get('before')
        limit = metadata.get('limit', 50)
        if before is not None and (type(before) is not int or before < 0):
            raise ValueError('before-invalid')
        if type(limit) is not int or not 1 <= limit <= 200:
            raise ValueError('limit-invalid')
        rows, cursor = page(before, limit)
        result = {'schema': SCHEMA, 'ok': True, 'rows': rows, 'next': cursor,
                  'firstMissingSignal': 'none'}
    except (OSError, ValueError, UnicodeError, shared.Refusal) as error:
        signal = str(error) if isinstance(error, ValueError) else 'backup-ledger-unavailable'
        result = {'schema': SCHEMA, 'ok': False, 'rows': [], 'next': None,
                  'firstMissingSignal': signal}
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

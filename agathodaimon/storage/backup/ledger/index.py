"""Project backup deeds and report when the ledger source is unavailable."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from agathodaimon import _envelope
from agathodaimon.storage.backup.backblaze import shared


def project(value):
    if not isinstance(value, dict):
        return None
    attrs = value.get('attributes_redacted')
    if (value.get('organ') == 'pid2' and value.get('kind') == 'schedule-fire'
            and isinstance(attrs, dict) and attrs.get('signal') == 'pid2-fire-interrupted-by-boot'):
        schedule = attrs.get('target')
        # Hyalos projects target to 48 characters; that length may hide a suffix.
        if isinstance(schedule, str) and schedule.startswith('backblaze-') and len(schedule) >= 48:
            return None
        stamp = value.get('timestamp')
        try:
            parsed = datetime.fromisoformat(stamp.replace('Z', '+00:00')) if isinstance(stamp, str) else None
            at = parsed.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ') if parsed and parsed.tzinfo else None
        except ValueError:
            at = None
        value = {'verb': 'pid2-fire-interrupted-by-boot', 'target': schedule,
                 'outcome': 'interrupted', 'duration_ms': attrs.get('duration_ms'),
                 'signal': attrs.get('signal'), 'at': at}
    verb = value.get('verb')
    target = value.get('target')
    if not isinstance(verb, str) or not re.fullmatch(r'[a-z0-9-]{1,128}', verb):
        return None
    if verb == 'pid2-fire-interrupted-by-boot':
        if target == 'nas-sync':
            job = 'drives'
        elif isinstance(target, str) and target.startswith('backblaze-') and shared.valid_bucket(target[10:]):
            job, target = 'offsite', target[10:]
        else:
            return None
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


def main(argv=None):
    # No Caduceus door offers a paged backup source to unattended loopback
    # callers. Keep intake in the shared reader; no payload can change that.
    try:
        _envelope.read(quiet_on_tty=True)
    except (OSError, ValueError, RecursionError):
        pass
    print(json.dumps({'ok': False, 'rows': [], 'next': None,
                      'firstMissingSignal': 'agathodaimon-backup-ledger-source-unavailable'},
                     separators=(',', ':')))
    return 1


if __name__ == '__main__':
    raise SystemExit(main())

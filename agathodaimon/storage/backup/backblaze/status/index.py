from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import rows, bucket_name
from agathodaimon.storage.backup.backblaze._units import unit_status, unit_running


def act(data):
    results = []
    for row in rows(data):
        bucket = bucket_name(row.get('bucket'))
        state = unit_status(bucket)
        running = unit_running(state)
        stamp = state.get('ExecMainExitTimestamp', '')
        finished = not running and state.get('LoadState') != 'not-found' and stamp.startswith('@')
        try:
            last_run_at = int(stamp[1:].split('.', 1)[0]) if finished else None
        except ValueError:
            last_run_at = None
        result = state.get('Result')
        entry = {'bucket':bucket, 'running':running, 'last_run_at':last_run_at,
                 'last_run_ok':(result == 'success') if last_run_at is not None and result else None,
                 'connected':None}
        results.append(entry)
    return {'ok':True, 'buckets':results}

def main(argv=None):
    return main_for('status')

if __name__ == '__main__':
    raise SystemExit(main())

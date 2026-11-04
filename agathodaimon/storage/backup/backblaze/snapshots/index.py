import subprocess

from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import Refusal, rows, row_for, bucket_name, valid_bucket
from agathodaimon.storage.backup.backblaze._restic import restic_environment, snapshot_list


def act(metadata, data):
    requested = metadata.get('bucket')
    selected = rows(data) if requested is None else [row_for(data, bucket_name(requested))]
    result, errors = [], []
    for row in selected:
        bucket = row.get('bucket')
        key = None
        try:
            bucket = bucket_name(bucket)
            env, key = restic_environment(row)
            result.extend(snapshot_list(row, env, key))
        except Refusal as error:
            if error.step == 'request':
                raise
            errors.append({'bucket':bucket if valid_bucket(bucket) else None,
                           'step':error.step, 'reason':error.reason})
        except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
            errors.append({'bucket':bucket if valid_bucket(bucket) else None,
                           'step':'snapshots', 'reason':'snapshots-unavailable'})
        finally:
            if key is not None:
                key[:] = b'\0' * len(key)
    return {'ok':True, 'snapshots':result, 'errors':errors}

def main(argv=None):
    return main_for('snapshots')

if __name__ == '__main__':
    raise SystemExit(main())

from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import row_for, fail
from agathodaimon.storage.backup.backblaze._keyman import credentials, authorize


def act(data, bucket):
    row_for(data, bucket)
    username = key = None
    try:
        username, key = credentials(bucket)
        connected = authorize(bucket, username.decode('utf-8'), key.decode('utf-8'))
    except UnicodeError:
        fail('keyman', 'keyman-credential-invalid')
    finally:
        if username is not None:
            username[:] = b'\0' * len(username)
        if key is not None:
            key[:] = b'\0' * len(key)
    return {'ok':True, 'connected':connected}

def main(argv=None):
    return main_for('bucket-verify')

if __name__ == '__main__':
    raise SystemExit(main())

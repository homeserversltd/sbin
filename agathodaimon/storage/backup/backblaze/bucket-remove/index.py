from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import rows
from agathodaimon.storage.backup.backblaze._units import release_result


def act(data, bucket, row):
    release_result(bucket)
    rows(data).remove(row)

def main(argv=None):
    return main_for('bucket-remove')

if __name__ == '__main__':
    raise SystemExit(main())

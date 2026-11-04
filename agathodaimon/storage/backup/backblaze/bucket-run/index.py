from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import row_for, valid_items, manager
from agathodaimon.storage.backup.backblaze._units import launch


def act(data, bucket, scheduled):
    row = row_for(data, bucket)
    valid_items(row.get('items', []))
    manager(row)
    return launch(bucket, scheduled=scheduled)

def main(argv=None):
    return main_for('bucket-run')

if __name__ == '__main__':
    raise SystemExit(main())

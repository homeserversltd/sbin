from agathodaimon.storage.backup.backblaze.shared import main_for
from importlib import import_module


def act(verb, metadata, data, bucket):
    return import_module('agathodaimon.storage.backup.backblaze.bucket-add.index').act(verb, metadata, data, bucket)

def main(argv=None):
    return main_for('bucket-credentials')

if __name__ == '__main__':
    raise SystemExit(main())

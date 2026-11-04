from agathodaimon.storage.backup.backblaze.shared import main_for
from agathodaimon.storage.backup.backblaze._store import valid_items, normalize_skips, fail


def act(metadata, row):
    items = valid_items(metadata.get('items'))
    managers = metadata.get('managers')
    if not isinstance(managers, dict) or not isinstance(managers.get('forgejo'), dict):
        fail('config', 'forgejo-manager-invalid')
    fg = managers['forgejo']
    if not isinstance(fg.get('localNas'), bool) or not isinstance(fg.get('backblazeBackup'), bool):
        fail('config', 'forgejo-manager-invalid')
    skip = normalize_skips(fg.get('skip', []))
    row['items'] = items
    current = row.setdefault('managers', {})
    if not isinstance(current, dict):
        fail('config', 'forgejo-manager-invalid')
    existing_manager = current.get('forgejo', {})
    if not isinstance(existing_manager, dict):
        fail('config', 'forgejo-manager-invalid')
    current['forgejo'] = {'localNas':fg['localNas'], 'backblazeBackup':fg['backblazeBackup'], 'skip':skip}

def main(argv=None):
    return main_for('bucket-save')

if __name__ == '__main__':
    raise SystemExit(main())

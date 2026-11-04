from agathodaimon.storage.backup.backblaze._store import valid_items, fail


def act(metadata, row):
    path, op = metadata.get('path'), metadata.get('op')
    valid_items([{'path':path}])
    if op not in ('add','remove'):
        fail('items', 'operation-invalid')
    items = valid_items(row.get('items', []))
    if op == 'add' and not any(x['path'] == path for x in items):
        items.append({'path':path})
    if op == 'remove':
        items = [x for x in items if x['path'] != path]
    row['items'] = items

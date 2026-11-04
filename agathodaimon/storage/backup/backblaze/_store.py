from __future__ import annotations
from .shared import NAME, SKIP, CONFIG, SKELETON, LOG, fail, os, Path, json, stat, tempfile, time, datetime, timezone

def scratch_root():
    # BACKBLAZE_SCRATCH_ROOT is marker-guarded and for proof only.
    raw = os.environ.get('BACKBLAZE_SCRATCH_ROOT')
    if not raw:
        return None
    root = Path(raw).resolve()
    if not root.is_absolute() or not root.is_dir() or not (root / '.backblaze-scratch').is_file():
        fail('scratch', 'scratch-root-invalid')
    return root

def config_path():
    root = scratch_root()
    return root / 'config.json' if root else CONFIG


def config_lock_path():
    root = scratch_root()
    return root / '.backblaze-config.lock' if root else Path('/run/lock/backblaze-config.lock')

def skeleton_path():
    root = scratch_root()
    return root / 'skeleton.key' if root else SKELETON

def log_path():
    root = scratch_root()
    return root / 'appliance.log' if root else LOG

def restic_bin():
    root = scratch_root()
    return str(root / 'restic') if root else '/usr/bin/restic'

def repository(row):
    root = scratch_root()
    return str(root / 'restic-repos' / row['bucket']) if root else 'b2:' + row['bucket'] + ':' + row.get('prefix', '')

def valid_bucket(value):
    return isinstance(value, str) and bool(NAME.fullmatch(value)) and not value.lower().startswith('b2-')

def bucket_name(value) -> str:
    if not isinstance(value, str) or not valid_bucket(value):
        fail('shape', 'bucket-invalid')
    return value

def keyman_service(bucket):
    name = bucket_name(bucket).lower().replace('-', '_')
    return name if 'a' <= name[0] <= 'z' else 'b' + name


def normalize_skips(value):
    if not isinstance(value, list):
        fail('skip', 'skip-entry-malformed')
    out = []
    for item in value:
        if not isinstance(item, str):
            fail('skip', 'skip-entry-malformed')
        parts = item.strip().split('/')
        if len(parts) not in (1, 2) or any(not SKIP.fullmatch(x) or x in ('.', '..') for x in parts):
            fail('skip', 'skip-entry-malformed')
        if item.strip() not in out:
            out.append(item.strip())
    return out

def valid_items(items):
    if not isinstance(items, list):
        fail('items', 'items-invalid')
    out = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get('path'), str):
            fail('items', 'item-path-invalid')
        p = item['path']
        if not p.startswith('/') or '\x00' in p or '\n' in p or '\r' in p:
            fail('items', 'item-path-invalid')
        out.append({'path':p})
    return out

def load():
    try:
        with config_path().open(encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        fail('config', 'config-unavailable')
    if not isinstance(data, dict):
        fail('config', 'config-invalid')
    return data

def rows(data, create=False):
    try:
        if create:
            config = data.setdefault('tabs', {}).setdefault('backblaze', {}).setdefault('config', {})
            result = config.setdefault('buckets', [])
        else:
            config = data.get('tabs', {}).get('backblaze', {}).get('config', {})
            result = config.get('buckets', [])
    except (AttributeError, TypeError):
        fail('config', 'config-invalid')
    if not isinstance(result, list) or any(not isinstance(x, dict) for x in result):
        fail('config', 'buckets-invalid')
    return result

def row_for(data, bucket):
    matches = [r for r in rows(data) if r.get('bucket') == bucket]
    if not matches:
        fail('config', 'bucket-not-configured')
    if len(matches) != 1:
        fail('config', 'bucket-row-duplicate')
    row = matches[0]
    if not isinstance(row.get('prefix', ''), str) or '\x00' in row.get('prefix', ''):
        fail('config', 'bucket-prefix-invalid')
    valid_items(row.get('items', []))
    return row

def manager(row):
    outer = row.get('managers', {})
    forgejo = outer.get('forgejo', {}) if isinstance(outer, dict) else None
    if not isinstance(forgejo, dict):
        fail('config', 'forgejo-manager-invalid')
    for k in ('localNas', 'backblazeBackup'):
        if k in forgejo and not isinstance(forgejo[k], bool):
            fail('config', 'forgejo-manager-invalid')
    normalize_skips(forgejo.get('skip', []))
    return forgejo

def normalized_row(value):
    if not isinstance(value, dict):
        fail('stale', 'bucket changed; refresh before saving')
    row = json.loads(json.dumps(value))
    row.pop('encrypted', None)
    row.setdefault('prefix', '')
    row.setdefault('items', [])
    outer = row.setdefault('managers', {})
    if not isinstance(outer, dict):
        fail('stale', 'bucket changed; refresh before saving')
    fg = outer.setdefault('forgejo', {})
    if not isinstance(fg, dict):
        fail('stale', 'bucket changed; refresh before saving')
    fg.setdefault('localNas', False)
    fg.setdefault('backblazeBackup', False)
    fg['skip'] = sorted(x.lower() for x in normalize_skips(fg.get('skip', [])))
    return row


def store(data):
    path = config_path()
    fd = None
    tmp = None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
        fd, tmp = tempfile.mkstemp(prefix='.config.', dir=path.parent, text=True)
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            fd = None
            json.dump(data, f, indent=2, ensure_ascii=True)
            f.write('\n')
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        try:
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError:
            return False
        return True
    except OSError:
        fail('config', 'config-write-failed')
    finally:
        if fd is not None:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass

def deed(verb, bucket, outcome, started, error='none', byte_counts=None):
    record = {'who':'agathodaimon', 'verb':verb, 'target':bucket, 'outcome':outcome,
              'duration_ms':int((time.monotonic()-started)*1000), 'signal':error,
              'at':datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}
    if byte_counts:
        record.update(byte_counts)
    line = json.dumps(record, separators=(',', ':'), ensure_ascii=True)
    if len(line.encode()) + 1 >= 1024:
        fail('deed', 'deed-too-large')
    try:
        with log_path().open('a', encoding='utf-8') as f:
            f.write(line + '\n')
    except OSError:
        fail('deed', 'deed-write-failed')


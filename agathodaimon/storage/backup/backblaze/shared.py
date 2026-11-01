"""Native Backblaze bucket staff: configuration, credentials and restic."""
from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import NoReturn
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from agathodaimon.lib.keyman_export.index import KeymanExportError, exchange_session, export_credential

NAME = re.compile(r"[A-Za-z0-9-]{6,63}\Z")
SKIP = re.compile(r"[A-Za-z0-9_.-]+\Z")
ACTUATORS = {name: 'backblaze-' + name for name in ('bucket-add', 'bucket-credentials', 'bucket-verify', 'bucket-remove', 'bucket-items', 'bucket-save', 'bucket-run', 'status', 'snapshots')}
CONFIG = Path('/etc/appliance/config.json')
SKELETON = Path('/root/key/skeleton.key')
LOG = Path('/var/log/appliance/appliance.log')
KEYMAN = '/vault/keyman/keyman'
SEED_ATTEMPTED = False

class Refusal(Exception):
    def __init__(self, step, reason):
        super().__init__(reason)
        self.step, self.reason = step, reason

def fail(step, reason) -> NoReturn:
    raise Refusal(step, reason)

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

def deed(verb, bucket, outcome, started, error='none'):
    record = {'who':'agathodaimon', 'verb':verb, 'target':bucket, 'outcome':outcome,
              'duration_ms':int((time.monotonic()-started)*1000), 'signal':error}
    line = json.dumps(record, separators=(',', ':'), ensure_ascii=True)
    if len(line.encode()) >= 1024:
        fail('deed', 'deed-too-large')
    try:
        with log_path().open('a', encoding='utf-8') as f:
            f.write(line + '\n')
    except OSError:
        fail('deed', 'deed-write-failed')

def derivation(raw, salt):
    return base64.b64encode(hashlib.pbkdf2_hmac('sha256', raw, salt, 100000, 32)).decode('ascii')

def skeleton_password():
    try:
        secret = bytearray(skeleton_path().read_bytes())
    except OSError:
        fail('skeleton', 'skeleton-key-unavailable')
    try:
        if secret.endswith(b'\n'):
            del secret[-1:]
        if not secret:
            fail('skeleton', 'skeleton-key-empty')
        return derivation(secret, b'homeserver_backblaze_restic_v2')
    finally:
        secret[:] = b'\0' * len(secret)

def credentials(bucket):
    try:
        return export_credential(bucket.replace('-', '_'))
    except KeymanExportError as error:
        fail('keyman', 'keyman-' + error.signal)

def seed(bucket, key_id, application_key):
    global SEED_ATTEMPTED
    values = [key_id.encode('utf-8'), application_key.encode('utf-8')]
    if any(not x or len(x) > 511 or any(c in x for c in (0,10,13,34)) for x in values):
        fail('keyman', 'credential-invalid')
    material = bytearray(b'username="' + values[0] + b'"\npassword="' + values[1] + b'"\n')
    service = bucket.replace('-', '_')
    try:
        with exchange_session(native=True):
            SEED_ATTEMPTED = True
            proc = subprocess.run([KEYMAN, 'newkey', '--stdin', '--replace', service], input=bytes(material),
                                  stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12, check=False)
        result = json.loads(proc.stdout)
        if proc.returncode or not isinstance(result, dict) or result.get('ok') is not True or result.get('operation') != 'newkey' or result.get('service') != service or result.get('secret_free') is not True:
            fail('keyman', 'keyman-seed-refused')
    except KeymanExportError as error:
        fail('keyman', 'keyman-' + error.signal)
    except subprocess.TimeoutExpired:
        fail('keyman', 'keyman-seed-deadline-may-have-committed-retry-replace')
    except (OSError, ValueError, subprocess.SubprocessError):
        fail('keyman', 'keyman-seed-unavailable')
    finally:
        material[:] = b'\0' * len(material)
    return service

def authorize(bucket, key_id, application_key, *, mutating=False):
    try:
        basic = base64.b64encode((key_id + ':' + application_key).encode()).decode('ascii')
        request = urllib.request.Request('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', headers={'Authorization':'Basic '+basic})
        with urllib.request.urlopen(request, timeout=6) as response:
            auth = json.load(response)
        api = auth['apiUrl']
        token = auth['authorizationToken']
        account = auth['accountId']
        if (not isinstance(api, str) or urllib.parse.urlsplit(api).scheme != 'https' or
                not urllib.parse.urlsplit(api).hostname or
                not isinstance(token, str) or not token.strip() or token != token.strip() or
                not isinstance(account, str) or not account.strip() or account != account.strip()):
            fail('verify', 'b2-authorization-invalid')
        request = urllib.request.Request(api.rstrip('/')+'/b2api/v2/b2_list_buckets',
             data=json.dumps({'accountId':account,'bucketName':bucket}).encode(),
             headers={'Authorization':token,'Content-Type':'application/json'}, method='POST')
        with urllib.request.urlopen(request, timeout=6) as response:
            listing = json.load(response)
        if (not isinstance(listing, dict) or not isinstance(listing.get('buckets'), list) or
                any(not isinstance(item, dict) or not isinstance(item.get('bucketName'), str)
                    for item in listing['buckets'])):
            fail('verify', 'b2-listing-invalid')
        return any(item['bucketName'] == bucket for item in listing['buckets'])
    except urllib.error.HTTPError as error:
        if error.code in (401, 403) and not mutating:
            return False
        fail('verify', 'b2-check-unavailable')
    except Refusal:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        fail('verify', 'b2-check-unavailable')


def restic_environment(row):
    env = {key:value for key, value in os.environ.items()
           if not key.startswith('RESTIC_') and key not in ('B2_ACCOUNT_ID', 'B2_ACCOUNT_KEY')}
    env['RESTIC_REPOSITORY'] = repository(row)
    env['RESTIC_PASSWORD'] = skeleton_password()
    root = scratch_root()
    key = None
    if root:
        try:
            key = bytearray((root / 'application.key').read_bytes())
        except OSError:
            key = bytearray()
    else:
        username, key = credentials(row['bucket'])
        try:
            env['B2_ACCOUNT_ID'] = username.decode('utf-8')
            env['B2_ACCOUNT_KEY'] = key.decode('utf-8')
        finally:
            username[:] = b'\0' * len(username)
    return env, key


def invoke_restic(args, env, timeout=None, capture=True):
    try:
        return subprocess.run([restic_bin(), '--no-cache', *args], env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                              stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        fail('restic', 'restic-unavailable')


def ensure_repository(row, env, application_key, init_missing=True):
    probe = invoke_restic(['--no-lock', 'snapshots', '--json'], env)
    if probe.returncode == 0:
        return
    error = probe.stderr.decode('utf-8', 'replace').lower()
    if ('config file does not exist' in error or 'not initialized' in error
        or 'repository does not exist' in error or 'is there a repository' in error
        or ('unable to open config file' in error and 'no such file' in error)):
        if init_missing and invoke_restic(['init'], env, capture=False).returncode:
            fail('restic-init', 'restic-init-failed')
        return
    if 'wrong password' not in error and 'no key found' not in error:
        fail('restic', 'restic-repository-unavailable')
    if not application_key:
        fail('rekey', 'legacy-key-unavailable')
    legacy = env.copy()
    legacy['RESTIC_PASSWORD'] = derivation(application_key, b'coronatio_backblaze_restic_v1')
    if invoke_restic(['--no-lock', 'snapshots', '--json'], legacy).returncode:
        fail('rekey', 'legacy-password-refused')
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='backblaze-rekey-') as tmp:
        path = Path(tmp) / 'new-password'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='ascii') as stream:
            stream.write(env['RESTIC_PASSWORD'])
        if invoke_restic(['key', 'add', '--new-password-file', str(path)], legacy, capture=False).returncode:
            fail('rekey', 'restic-rekey-failed')
    deed('backblaze-restic-rekey', row['bucket'], 'ok', started)


def snapshot_list(row, env, application_key):
    response = invoke_restic(['--no-lock', 'snapshots', '--json'], env, timeout=220)
    if response.returncode and application_key:
        error = response.stderr.decode('utf-8', 'replace').lower()
        if 'wrong password' in error or 'no key found' in error:
            legacy = env.copy()
            legacy['RESTIC_PASSWORD'] = derivation(application_key, b'coronatio_backblaze_restic_v1')
            response = invoke_restic(['--no-lock', 'snapshots', '--json'], legacy, timeout=220)
    if response.returncode:
        fail('snapshots', 'snapshots-unavailable')
    try:
        entries = json.loads(response.stdout)
        if not isinstance(entries, list):
            raise ValueError('not a list')
        out = []
        for entry in entries:
            if not isinstance(entry, dict):
                fail('snapshots', 'snapshots-invalid')
            ident, stamp = entry.get('id'), entry.get('time')
            paths, tags = entry.get('paths') or [], entry.get('tags') or []
            if (not isinstance(ident, str) or not isinstance(stamp, str) or
                not isinstance(paths, list) or not all(isinstance(x, str) for x in paths) or
                not isinstance(tags, list) or not all(isinstance(x, str) for x in tags)):
                fail('snapshots', 'snapshots-invalid')
            out.append({'id':ident, 'time':stamp, 'paths':paths, 'tags':tags, 'bucket':row['bucket']})
        return out
    except ValueError:
        fail('snapshots', 'snapshots-invalid')


def scratch_unit_prefix():
    root = scratch_root()
    if root is None:
        return None
    return 'backblaze-proof-' + hashlib.sha256(os.fsencode(str(root))).hexdigest()[:16]


def run_unit(bucket):
    prefix = scratch_unit_prefix()
    return (prefix + '-run-' if prefix else 'backblaze-run-') + bucket + '.service'


def release_result(bucket):
    state = unit_status(bucket)
    if state.get('LoadState') == 'not-found':
        return
    p = subprocess.run(['/usr/bin/systemctl', 'stop', run_unit(bucket)], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
    if p.returncode:
        fail('run', 'finished-unit-stop-failed')
    reset = subprocess.run(['/usr/bin/systemctl', 'reset-failed', run_unit(bucket)],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=5, check=False)
    if reset.returncode and unit_status(bucket).get('LoadState') != 'not-found':
        fail('run', 'finished-unit-reset-failed')
    for _ in range(20):
        if unit_status(bucket).get('LoadState') == 'not-found':
            return
        time.sleep(.05)
    fail('run', 'finished-unit-release-failed')


def unit_status(bucket):
    try:
        p = subprocess.run(['/usr/bin/systemctl', '--timestamp=unix', 'show', run_unit(bucket), '--property=LoadState',
                            '--property=ActiveState', '--property=SubState', '--property=Result', '--property=ExecMainExitTimestamp'],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False, text=True)
    except (OSError, subprocess.SubprocessError):
        fail('status', 'systemd-unavailable')
    fields = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    if p.returncode:
        fail('status', 'systemd-unavailable')
    return fields


def unit_running(state):
    return state.get('SubState') in ('running', 'start', 'start-pre', 'start-post', 'reload', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-sigterm', 'final-sigkill') or state.get('ActiveState') in ('activating', 'deactivating', 'reloading')


def launch(bucket):
    if os.geteuid() != 0:
        fail('run', 'root-required')
    try:
        status = unit_status(bucket)
        if unit_running(status):
            fail('run', 'bucket-run-active')
        release_result(bucket)
        cmd = ['/usr/bin/systemd-run', '--quiet', '--unit=' + run_unit(bucket),
               '--property=Type=exec', '--property=RemainAfterExit=yes']
        root = scratch_root()
        if root:
            cmd.extend(['--setenv=BACKBLAZE_SCRATCH_ROOT=' + str(root), '--setenv=TMPDIR=' + str(root)])
        cmd += ['--', sys.executable, str(Path(__file__).resolve()), '--worker', bucket]
        process = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=8, check=False)
        if process.returncode:
            fail('run', 'bucket-launch-refused')
    except (OSError, subprocess.SubprocessError):
        fail('run', 'bucket-launch-unavailable')
    return {'ok':True, 'status':'accepted', 'unit':run_unit(bucket)}


def run_files(bucket):
    started = time.monotonic()
    outcome, error, key = 'failed', 'unknown', None
    try:
        row = row_for(load(), bucket)
        paths = [x['path'] for x in valid_items(row.get('items', []))]
        forgejo = manager(row)
        env, key = restic_environment(row)
        ensure_repository(row, env, key)
        if paths:
            if invoke_restic(['backup', '--tag', 'files', '--', *paths], env, capture=False).returncode:
                fail('files', 'files-backup-failed')
        if forgejo.get('backblazeBackup', False):
            if scratch_root():
                fail('forgejo', 'scratch-live-forgejo-refused')
            child = Path(__file__).resolve().parents[1] / 'forgejo/backup-b2/index.py'
            result = subprocess.run([sys.executable, str(child), '--worker', bucket],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, check=False)
            if result.returncode:
                fail('forgejo', 'forgejo-backup-failed')
        outcome, error = 'ok', 'none'
    except Refusal as exc:
        error = exc.reason
    except (OSError, ValueError, UnicodeError):
        error = 'run-internal-failure'
    finally:
        if key is not None:
            key[:] = b'\0' * len(key)
        try:
            deed('backblaze-bucket-run', bucket, outcome, started, error)
        except Refusal:
            outcome = 'failed'
    return 0 if outcome == 'ok' else 1


def dispatch(verb, metadata):
    if verb not in ACTUATORS or not isinstance(metadata, dict):
        fail('shape', 'metadata-invalid')
    data = load()
    if verb == 'status':
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
    if verb == 'snapshots':
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
    bucket = bucket_name(metadata.get('bucket'))
    if scratch_root() and verb in ('bucket-add', 'bucket-credentials', 'bucket-verify'):
        fail('scratch', 'scratch-live-authority-refused')
    if scratch_root() and verb in ('bucket-run', 'bucket-remove') and not bucket.startswith('scratch-'):
        fail('scratch', 'scratch-unit-name-required')
    if verb == 'bucket-run':
        row = row_for(data, bucket)
        valid_items(row.get('items', []))
        manager(row)
        return launch(bucket)
    if verb == 'bucket-verify':
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
    started = time.monotonic()
    outcome = 'failed'
    signal_name = 'unknown'
    should_log = True
    mutation_result: dict[str, object] = {}
    before = json.dumps(data, sort_keys=True, separators=(',', ':'))
    try:
        if verb in ('bucket-credentials', 'bucket-remove', 'bucket-items', 'bucket-save') and 'expected' in metadata:
            try:
                unchanged = normalized_row(row_for(data, bucket)) == normalized_row(metadata['expected'])
            except (Refusal, ValueError, TypeError):
                unchanged = False
            if not unchanged:
                fail('stale', 'bucket changed; refresh before saving')
        if verb in ('bucket-credentials', 'bucket-remove', 'bucket-items', 'bucket-save'):
            if unit_running(unit_status(bucket)):
                fail('run', 'bucket-run-active')
        if verb in ('bucket-add', 'bucket-credentials'):
            key_id, application_key = metadata.get('keyId'), metadata.get('applicationKey')
            if not isinstance(key_id, str) or not key_id or not isinstance(application_key, str) or not application_key:
                fail('shape', 'credential-invalid')
            existing = [row for row in rows(data, True) if row.get('bucket') == bucket]
            if verb == 'bucket-add' and existing:
                fail('config', 'bucket-already-exists')
            if verb == 'bucket-credentials' and len(existing) != 1:
                fail('config', 'bucket-not-configured')
            if not authorize(bucket, key_id, application_key, mutating=True):
                fail('verify', 'bucket-not-visible-to-key')
            service = seed(bucket, key_id, application_key)
            if verb == 'bucket-add':
                rows(data, True).append({'bucket':bucket, 'prefix':'', 'items':[],
                                         'managers':{'forgejo':{'localNas':False,'backblazeBackup':False,'skip':[]}}})
            mutation_result = {'ok':True, 'keyman_service':service}
        else:
            row = row_for(data, bucket)
            if verb == 'bucket-remove':
                release_result(bucket)
                rows(data).remove(row)
            elif verb == 'bucket-items':
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
            elif verb == 'bucket-save':
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
            else:
                fail('shape', 'actuator-invalid')
            if verb in ('bucket-items', 'bucket-save'):
                for unknown in set(row) - {'bucket', 'prefix', 'items', 'managers'}:
                    row.pop(unknown)
                if 'managers' in row:
                    managers = row['managers']
                    if not isinstance(managers, dict):
                        fail('config', 'forgejo-manager-invalid')
                    forgejo = managers.get('forgejo', {})
                    if not isinstance(forgejo, dict):
                        fail('config', 'forgejo-manager-invalid')
                    row['managers'] = {'forgejo':{k:v for k,v in forgejo.items()
                                                  if k in ('localNas', 'backblazeBackup', 'skip')}}
            mutation_result = {'ok':True}
        for item in rows(data):
            item.pop('encrypted', None)
        changed = json.dumps(data, sort_keys=True, separators=(',', ':')) != before
        if changed:
            if not store(data):
                mutation_result['durability'] = 'unconfirmed'
        elif verb != 'bucket-credentials':
            should_log = False
        outcome, signal_name = 'ok', 'none'
        return mutation_result
    except Refusal as error:
        signal_name = error.reason
        raise
    finally:
        if should_log and outcome == 'ok':
            try:
                deed(ACTUATORS[verb], bucket, outcome, started, signal_name)
            except Refusal:
                if outcome == 'ok':
                    mutation_result['deed'] = 'unwritten'


def main_for(verb):
    global SEED_ATTEMPTED
    SEED_ATTEMPTED = False
    budgets = {'bucket-add':240, 'bucket-credentials':240, 'bucket-verify':240,
               'bucket-remove':45, 'bucket-items':45, 'bucket-save':45, 'bucket-run':45,
               'status':20, 'snapshots':480}
    def deadline(_sig, _frame):
        fail('request', 'request-deadline-after-keyman-seed-attempt' if SEED_ATTEMPTED else 'request-deadline-exceeded')
    previous = None
    started = time.monotonic()
    request = None
    try:
        previous = signal.signal(signal.SIGALRM, deadline)
        signal.alarm(budgets.get(verb, 20))
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            fail('shape', 'request-too-large')
        try:
            request = json.loads(raw)
        except (ValueError, UnicodeError):
            fail('shape', 'request-invalid')
        if not isinstance(request, dict) or request.get('actuator') != ACTUATORS[verb]:
            fail('shape', 'actuator-envelope-invalid')
        if verb in ('bucket-add', 'bucket-credentials', 'bucket-remove', 'bucket-items', 'bucket-save', 'bucket-run'):
            fd = None
            try:
                lock_path = config_lock_path()
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = dispatch(verb, request.get('metadata'))
            except BlockingIOError:
                fail('config', 'config-update-active')
            finally:
                if fd is not None:
                    os.close(fd)
        else:
            result = dispatch(verb, request.get('metadata'))
    except Refusal as error:
        result = {'ok':False, 'step':error.step, 'reason':error.reason}
    except Exception:
        result = {'ok':False, 'step':'request', 'reason':'request-unavailable'}
    finally:
        if previous is not None:
            try:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
            except Exception:
                result = {'ok':False, 'step':'request', 'reason':'request-unavailable'}
    if not result.get('ok') and verb in ('bucket-add', 'bucket-credentials', 'bucket-remove', 'bucket-items', 'bucket-save', 'bucket-run'):
        metadata = request.get('metadata') if isinstance(request, dict) else None
        value = metadata.get('bucket') if isinstance(metadata, dict) else None
        try:
            deed(ACTUATORS[verb], value if valid_bucket(value) else 'invalid', 'failed', started, result['reason'])
        except Exception:
            result['deed'] = 'unwritten'
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        raise SystemExit(run_files(bucket_name(sys.argv[2])))
    raise SystemExit(1)

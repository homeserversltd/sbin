from __future__ import annotations
from ._store import os, subprocess, json, time, tempfile, Path, re, fail, repository, scratch_root, restic_bin, deed
from ._keyman import skeleton_password, credentials, derivation

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


def summary_counts(message):
    result = {}
    if isinstance(message, dict):
        for source, target in (('data_added', 'added_bytes'), ('total_bytes_processed', 'total_bytes')):
            value = message.get(source)
            if type(value) is int and value >= 0:
                result[target] = value
    return result


def add_counts(total, part):
    for key in ('added_bytes', 'total_bytes'):
        if type(part.get(key)) is int and part[key] >= 0:
            total[key] = total.get(key, 0) + part[key]


def backup_files(paths, env, counts):
    try:
        with subprocess.Popen([restic_bin(), '--no-cache', 'backup', '--json', '--tag', 'files', '--', *paths],
                              env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as child:
            assert child.stdout is not None
            oversized = False
            while True:
                line = child.stdout.readline(65536)
                if not line:
                    break
                if oversized:
                    oversized = not line.endswith(b'\n')
                    continue
                if not line.endswith(b'\n') and len(line) == 65536:
                    oversized = True
                    continue
                try:
                    message = json.loads(line)
                except (ValueError, UnicodeError):
                    continue
                if isinstance(message, dict) and message.get('message_type') == 'summary':
                    add_counts(counts, summary_counts(message))
            if child.wait():
                fail('files', 'files-backup-failed')
    except (OSError, subprocess.SubprocessError):
        fail('restic', 'restic-unavailable')


def _ensure_repository(row, env, application_key, init_missing=True):
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


def ensure_repository(row, env, application_key, init_missing=True):
    _ensure_repository(row, env, application_key, init_missing)
    started = time.monotonic()
    result = invoke_restic(['unlock', '--verbose'], env)
    if result.returncode:
        fail('restic-unlock', 'restic-unlock-failed')
    # Restic reports removals only when at least one stale lock was removed.
    if re.search(rb'\bsuccessfully removed [1-9][0-9]* locks?\b', result.stdout, re.I):
        deed('backblaze-restic-unlock', row['bucket'], 'ok', started)


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



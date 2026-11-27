"""Ensure the household mirror and the Test guest at first boot."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path
import re
import signal as signals
import stat
import time
import urllib.error
import urllib.parse
import urllib.request

from agathodaimon._envelope import EnvelopeError, attach, read_fields

PROOF = Path(__file__).resolve().is_relative_to(Path('/var/lib/work'))
GITHUB_REPO = 'https://github.com/homeserversltd/xenia-hello-world-example'
GITHUB_API = 'https://api.github.com/repos/homeserversltd/xenia-hello-world-example/releases/tags/latest'
GITHUB_HOSTS = {'api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'}
MAX_RESPONSE = 2 * 1024 * 1024


def setting(name, default):
    return os.environ.get(name, default) if PROOF else default


class Failure(Exception):
    pass


class SeedDeadline(BaseException):
    pass


def seed_deadline_expired(_signum, _frame):
    raise SeedDeadline()


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, public):
        self.public = public

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if not self.public or parsed.scheme != 'https' or parsed.hostname not in GITHUB_HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise Failure('release-manifest-unavailable')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url, method='GET', data=None, key=None, public=False, deadline=None, multipart=None):
    headers = {'Accept': 'application/json', 'User-Agent': 'agathodaimon'}
    if key is not None:
        headers['Authorization'] = 'Basic ' + base64.b64encode(b'owner:' + key).decode('ascii')
    if multipart is not None:
        name, content = multipart
        boundary = 'xenia-seed-attachment'
        headers['Content-Type'] = 'multipart/form-data; boundary=' + boundary
        data = (('--' + boundary + '\r\nContent-Disposition: form-data; name="attachment"; filename="' + name + '"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + content + ('\r\n--' + boundary + '--\r\n').encode())
    elif data is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data, separators=(',', ':')).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect(public))
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        timeout = 3 if deadline is None else min(3, max(0.001, deadline - time.monotonic()))
        response = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError('response-too-large')
        return response.status, raw


def decode(raw):
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('object-required')
    return value


def skeleton():
    path = setting('XENIA_TEST_SKELETON', '/root/key/skeleton.key')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != (os.geteuid() if PROOF else 0) or stat.S_IMODE(info.st_mode) & 0o077:
            raise Failure('skeleton-key-invalid')
        raw = os.read(fd, 65537)
    finally:
        os.close(fd)
    if len(raw) > 65536:
        raise Failure('skeleton-key-invalid')
    value = raw[:-1] if raw.endswith(b'\n') else raw
    if not value or any(c < 32 or c == 127 for c in value):
        raise Failure('skeleton-key-invalid')
    value.decode('utf-8')
    return value


def wait(url, signal, deadline):
    while True:
        try:
            status, _ = request(url)
            if status == 200:
                return
        except SeedDeadline:
            raise Failure(signal) from None
        except (OSError, ValueError, urllib.error.URLError, Failure):
            pass
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Failure(signal)
        time.sleep(min(1, remaining))


def message(raw):
    try:
        value = decode(raw)
        text = value.get('message') or value.get('firstMissingSignal') or value.get('signal')
        if isinstance(text, str):
            return re.sub(r'[^A-Za-z0-9._:-]', '-', text)[:160] or 'refused'
    except (ValueError, UnicodeError):
        pass
    return 'refused'


ASSET_NAMES = ('cartridge.json', 'cartridge-test-x86_64', 'cartridge-test-x86_64.sha256', 'release.flag')


class SeedStatus(Exception):
    pass


def seed_load(root):
    seed = decode((root / 'seed.json').read_bytes())
    commit = seed.get('commit')
    if (seed.get('schema') != 'xenia.seed.v1' or seed.get('release_repo') != 'owner/cartridge-test'
            or not isinstance(commit, str) or not re.fullmatch(r'[0-9a-f]{40}', commit)
            or seed.get('tag') != 'sha-' + commit):
        raise ValueError('seed-invalid')
    rows = seed.get('assets')
    if not isinstance(rows, list) or len(rows) != len(ASSET_NAMES):
        raise ValueError('seed-assets-invalid')
    digests = {row['name']: row['sha256'] for row in rows if isinstance(row, dict)}
    if len(digests) != len(ASSET_NAMES) or set(digests) != set(ASSET_NAMES):
        raise ValueError('seed-assets-invalid')
    for name in ASSET_NAMES:
        with (root / 'release' / name).open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != digests[name]:
            raise ValueError('seed-asset-digest-invalid')
    manifest = decode((root / 'release' / 'cartridge.json').read_bytes())
    if manifest.get('id') != 'test':
        raise ValueError('seed-manifest-invalid')
    return seed, manifest


def seed_step(signal, deadline, action):
    try:
        return seed_step_retry(signal, deadline, action)
    except SeedDeadline:
        raise Failure(signal + ':timeout') from None


def seed_step_retry(signal, deadline, action):
    last = 'timeout'
    while time.monotonic() < deadline:
        try:
            return action()
        except SeedStatus as exc:
            last = str(exc)
        except Exception as exc:
            last = type(exc).__name__
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(2, remaining))
    raise Failure(signal + ':' + last) from None


def seed_request(forge, path, key, deadline, **kwargs):
    status, raw = request(forge + path, key=key, deadline=deadline, **kwargs)
    if status not in (200, 201):
        raise SeedStatus(str(status))
    return raw


def seed_push(forge, key, root, seed, deadline):
    repo_api = '/api/v1/repos/owner/cartridge-test'
    created = False
    def create():
        nonlocal created
        if not created:
            seed_request(forge, '/api/v1/user/repos', key, deadline, method='POST',
                         data={'name': 'cartridge-test', 'private': True, 'auto_init': False})
            created = True
        repo = decode(seed_request(forge, repo_api, key, deadline))
        if repo.get('private') is not True:
            raise ValueError('repo-not-private')
    seed_step('seed-repo-create-failed', deadline, create)

    def push():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SeedStatus('timeout')
        # Anonymous memfd config supplies Git's HTTP header; neither argv nor
        # environment contains the credential, and no persistent file exists.
        fd = os.memfd_create('xenia-git-config', 0)
        try:
            header = base64.b64encode(b'owner:' + key).decode('ascii')
            os.write(fd, ('[http "' + forge + '/"]\n\textraHeader = Authorization: Basic ' + header + '\n').encode())
            env = os.environ.copy()
            env.update({'GIT_TERMINAL_PROMPT': '0', 'GIT_CONFIG_NOSYSTEM': '1', 'HOME': '/nonexistent'})
            subprocess.run(['git', '-c', 'include.path=/proc/self/fd/' + str(fd), '-C', str(root / 'repo'),
                            'push', forge + '/owner/cartridge-test.git', seed['commit'] + ':refs/heads/main'],
                           pass_fds=(fd,), env=env, timeout=remaining, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        finally:
            os.close(fd)
        ref = decode(seed_request(forge, repo_api + '/branches/main', key, deadline))
        if ref.get('commit', {}).get('id') != seed['commit']:
            raise ValueError('branch-commit-mismatch')
    seed_step('seed-push-failed', deadline, push)

    release_created = False
    def release():
        nonlocal release_created
        if not release_created:
            data = {'tag_name': seed['tag'], 'target_commitish': seed['commit'], 'name': seed['tag']}
            seed_request(forge, repo_api + '/releases', key, deadline, method='POST', data=data)
            release_created = True
        item = decode(seed_request(forge, repo_api + '/releases/tags/' + seed['tag'], key, deadline))
        if item.get('tag_name') != seed['tag'] or item.get('target_commitish') != seed['commit'] or not isinstance(item.get('id'), int):
            raise ValueError('release-mismatch')
        return item['id']
    release_id = seed_step('seed-release-create-failed', deadline, release)
    for name in ASSET_NAMES:
        asset_id = None
        def upload(name=name):
            nonlocal asset_id
            content = (root / 'release' / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != next(a['sha256'] for a in seed['assets'] if a['name'] == name):
                raise ValueError('seed-asset-digest-invalid')
            path = repo_api + '/releases/' + str(release_id) + '/assets'
            if asset_id is None:
                result = decode(seed_request(forge, path, key, deadline, method='POST', multipart=(name, content)))
                asset_id = result.get('id')
                if not isinstance(asset_id, int):
                    raise ValueError('asset-id-invalid')
            asset = decode(seed_request(forge, path + '/' + str(asset_id), key, deadline))
            url = urllib.parse.urlsplit(asset.get('browser_download_url', ''))
            if (asset.get('name') != name or asset.get('size') != len(content)
                    or url.scheme != 'https' or url.netloc != 'git.home.arpa'):
                raise ValueError('asset-mismatch')
        seed_step('seed-asset-upload-failed', deadline, upload)


def main(argv=None):
    del argv
    started = time.monotonic()
    try:
        envelope = read_fields()
    except EnvelopeError:
        print(json.dumps({'ok': False, 'changed': False, 'firstMissingSignal': 'request-invalid'}))
        return 1
    changed = False
    signal = 'none'
    alarm_handler = None
    deadline_signal = 'seed-repo-create-failed:timeout'
    try:
        if not PROOF and os.geteuid() != 0:
            raise Failure('root-required')
        forge = setting('XENIA_TEST_FORGE', 'http://127.0.0.1:3000').rstrip('/')
        caduceus = setting('XENIA_TEST_CADUCEUS', 'http://127.0.0.1:3014').rstrip('/')
        crown = setting('XENIA_TEST_CORONATIO', 'http://127.0.0.1:3013').rstrip('/')
        api = setting('XENIA_TEST_GITHUB_API', GITHUB_API)
        for base in (forge, caduceus, crown):
            parsed = urllib.parse.urlsplit(base)
            if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
                raise Failure('service-url-invalid')
        if PROOF and api != GITHUB_API:
            parsed = urllib.parse.urlsplit(api)
            if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password:
                raise Failure('release-manifest-unavailable')
        import math
        wait_seconds = float(setting('XENIA_TEST_WAIT_SECONDS', '120'))
        if not math.isfinite(wait_seconds) or not 0 < wait_seconds <= 120:
            raise Failure('wait-duration-invalid')
        deadline = time.monotonic() + wait_seconds
        seed_root = Path(setting('XENIA_TEST_SEED', '/var/lib/xenia/seed/cartridge-test'))
        if seed_root.exists():
            if signals.getitimer(signals.ITIMER_REAL)[0]:
                raise Failure('seed-repo-create-failed:timer-busy')
            alarm_handler = signals.signal(signals.SIGALRM, seed_deadline_expired)
            signals.setitimer(signals.ITIMER_REAL, max(0.001, deadline - time.monotonic()))
        wait(forge + '/api/healthz', 'forge-not-ready', deadline)
        wait(caduceus + '/api/v1/doors', 'caduceus-not-ready', deadline)
        wait(crown + '/api/registry', 'coronatio-not-ready', deadline)
        key = skeleton()
        seed = None
        manifest = None
        if seed_root.exists():
            try:
                seed, manifest = seed_load(seed_root)
            except Exception as exc:
                raise Failure('seed-repo-create-failed:' + type(exc).__name__) from None
        try:
            while True:
                seeding = False
                try:
                    status, raw = request(forge + '/api/v1/repos/owner/cartridge-test', key=key)
                    if status == 200:
                        break
                    if status == 404:
                        if seed is not None:
                            seeding = True
                            seed_push(forge, key, seed_root, seed, deadline)
                            changed = True
                            break
                        payload = {'clone_addr': GITHUB_REPO, 'repo_owner': 'owner', 'repo_name': 'cartridge-test', 'mirror': True, 'private': True}
                        status, raw = request(forge + '/api/v1/repos/migrate', method='POST', data=payload, key=key)
                        if status in (200, 201, 202):
                            changed = True
                            break
                    last = str(status)
                except Failure as exc:
                    if seeding:
                        raise
                    last = type(exc).__name__
                except Exception as exc:
                    last = type(exc).__name__
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Failure(('seed-repo-create-failed:' if seed is not None else 'mirror-create-failed:') + last) from None
                time.sleep(min(2, remaining))
                if time.monotonic() >= deadline:
                    raise Failure(('seed-repo-create-failed:' if seed is not None else 'mirror-create-failed:') + last) from None
        finally:
            key = b''
        deadline_signal = 'admit-refused:timeout'
        status, raw = request(caduceus + '/api/v1/xenia/status/test')
        if status != 200:
            raise Failure('admit-refused:' + message(raw))
        state = decode(raw)
        if state.get('ok') is not True:
            raise Failure('admit-refused:' + message(raw))
        runtime = state.get('runtime')
        if 'entry' not in state and (not isinstance(runtime, dict) or runtime.get('state') != 'entry-absent'):
            raise Failure('admit-refused:status-invalid')
        observed = state.get('observed')
        if 'entry' in state and (not isinstance(observed, dict) or observed.get('row_present') is not True):
            raise Failure('admit-refused:row-missing')
        if 'entry' not in state:
            if seed is None:
                try:
                    status, raw = request(api, public=api == GITHUB_API)
                    release = decode(raw)
                    assets = release.get('assets')
                    if status != 200 or release.get('tag_name') != 'latest' or not isinstance(assets, list):
                        raise ValueError('release-invalid')
                    matches = [item for item in assets if isinstance(item, dict) and item.get('name') == 'cartridge.json']
                    if len(matches) != 1:
                        raise ValueError('asset-missing')
                    asset = matches[0].get('browser_download_url')
                    parsed = urllib.parse.urlsplit(asset)
                    if api == GITHUB_API:
                        if parsed.scheme != 'https' or parsed.hostname != 'github.com' or parsed.username or parsed.password or parsed.port not in (None, 443):
                            raise ValueError('asset-url-invalid')
                    elif parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or parsed.username or parsed.password:
                        raise ValueError('asset-url-invalid')
                    status, raw = request(asset, public=api == GITHUB_API)
                    manifest = decode(raw)
                    if status != 200 or manifest.get('id') != 'test':
                        raise ValueError('manifest-invalid')
                except (OSError, ValueError, TypeError, UnicodeError, urllib.error.URLError, Failure):
                    raise Failure('release-manifest-unavailable') from None
            manifest['source'] = {'release_repo': 'owner/cartridge-test', 'ref': 'main', 'candidates': [{'kind': 'release', 'url': GITHUB_REPO, 'credential_selector': None}]}
            body = {'manifest': manifest, 'tabs': {'displayName': 'Test', 'order': 60, 'adminOnly': False, 'data': {}, 'visibility': {'tab': True, 'elements': {}}}}
            for door in ('validate', 'admit'):
                status, raw = request(caduceus + '/api/v1/xenia/' + door, method='POST', data=body)
                if status != 200 or decode(raw).get('ok') is not True:
                    raise Failure('admit-refused:' + message(raw))
                if door == 'admit':
                    changed = True
    except SeedDeadline:
        signal = deadline_signal
    except Failure as exc:
        signal = str(exc)
    except Exception:
        signal = 'test-tab-operation-failed'
    try:
        if (changed or signal != 'none') and (alarm_handler is None or time.monotonic() < deadline):
            from agathodaimon._deed import send
            send('sbin', 'xenos-test-tab', signal == 'none', target='test',
                 duration_ms=int((time.monotonic() - started) * 1000))
    except SeedDeadline:
        signal = deadline_signal
    finally:
        if alarm_handler is not None:
            signals.setitimer(signals.ITIMER_REAL, 0)
            signals.signal(signals.SIGALRM, alarm_handler)
    receipt = {'ok': signal == 'none', 'changed': changed, 'firstMissingSignal': signal}
    print(json.dumps(attach(receipt, envelope), separators=(',', ':'), sort_keys=True))
    return 0 if receipt['ok'] else 1

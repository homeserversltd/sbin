"""Ensure the household mirror and the Test guest at first boot."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
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


class Redirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, public):
        self.public = public

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlsplit(newurl)
        if not self.public or parsed.scheme != 'https' or parsed.hostname not in GITHUB_HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
            raise Failure('release-manifest-unavailable')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(url, method='GET', data=None, key=None, public=False):
    headers = {'Accept': 'application/json', 'User-Agent': 'agathodaimon'}
    if key is not None:
        headers['Authorization'] = 'Basic ' + base64.b64encode(b'owner:' + key).decode('ascii')
    if data is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(data, separators=(',', ':')).encode()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), Redirect(public))
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        response = opener.open(req, timeout=3)
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
        wait(forge + '/api/healthz', 'forge-not-ready', deadline)
        wait(caduceus + '/api/v1/doors', 'caduceus-not-ready', deadline)
        wait(crown + '/api/registry', 'coronatio-not-ready', deadline)
        key = skeleton()
        try:
            status, raw = request(forge + '/api/v1/repos/owner/cartridge-test', key=key)
            if status == 404:
                payload = {'clone_addr': GITHUB_REPO, 'repo_owner': 'owner', 'repo_name': 'cartridge-test', 'mirror': True, 'private': True}
                status, raw = request(forge + '/api/v1/repos/migrate', method='POST', data=payload, key=key)
                if status not in (200, 201, 202):
                    raise Failure('mirror-create-failed')
                changed = True
            elif status != 200:
                raise Failure('mirror-create-failed')
        except (OSError, ValueError, urllib.error.URLError, Failure):
            raise Failure('mirror-create-failed') from None
        finally:
            key = b''
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
    except Failure as exc:
        signal = str(exc)
    except Exception:
        signal = 'test-tab-operation-failed'
    receipt = {'ok': signal == 'none', 'changed': changed, 'firstMissingSignal': signal}
    if changed or signal != 'none':
        from agathodaimon._deed import send
        if not send('sbin', 'xenos-test-tab', signal == 'none', target='test',
                    duration_ms=int((time.monotonic() - started) * 1000)):
            receipt['ok'] = False
            receipt['firstMissingSignal'] = 'test-tab-log-unavailable'
    print(json.dumps(attach(receipt, envelope), separators=(',', ':'), sort_keys=True))
    return 0 if receipt['ok'] else 1

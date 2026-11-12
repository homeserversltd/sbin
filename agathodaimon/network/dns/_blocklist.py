"""Config-chosen Unbound blocklist, its source collection and refresh ladder."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from agathodaimon import _deed
from agathodaimon._nidus import unit
from agathodaimon._nidus.lock import identity_locked
from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon._nidus.refusal import Refusal
from agathodaimon._nidus.write import write, WriteError

DEFAULT = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'
MAX_SOURCE = 64 * 1024 * 1024
HEADER = re.compile(r'^# homeserver adblock lists=([0-9a-f]{12}) built=(\S+) domains=(\d+)$')
LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')


def paths():
    base = appliance_runtime_path('config').parent.parent / 'unbound'
    return base / 'unbound.conf', base / 'blocklist.conf'


def validate_url(url):
    if not isinstance(url, str) or len(url.encode('utf-8')) > 2048:
        raise Refusal('blocklist-source-invalid')
    try:
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None:
            raise Refusal('blocklist-source-credentials-refused')
        if parsed.scheme != 'https' or not parsed.hostname or parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
    except ValueError as exc:
        raise Refusal('blocklist-source-invalid') from exc
    return parsed


class SecureRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse(lines):
    result = set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith(('#', '!')):
            continue
        line = line.split('#', 1)[0].strip()
        m = re.fullmatch(r'local-zone:\s*"([^"]+)"\s+\S+\s*', line, re.I)
        if m:
            domain = m.group(1)
        elif line.startswith('||') and line.endswith('^'):
            domain = line[2:-1]
        else:
            fields = line.split()
            if len(fields) >= 2 and fields[0] in ('0.0.0.0', '127.0.0.1'):
                for entry in fields[1:]:
                    result.update(parse([entry]))
                continue
            if len(fields) != 1:
                continue
            domain = fields[0]
        domain = domain.lower().rstrip('.')
        if domain.startswith('*.'):
            domain = domain[2:]
        labels = domain.split('.')
        if (len(domain) > 253 or len(labels) < 2 or domain == 'home.arpa'
                or domain.endswith('.home.arpa') or domain == 'localhost.localdomain'
                or labels[-1] in ('localhost', 'local') or all(label.isdigit() for label in labels)):
            continue
        if all(LABEL.fullmatch(label) for label in labels):
            result.add(domain)
    return result


def fetch(url):
    validate_url(url)
    try:
        with build_opener(SecureRedirect()).open(Request(url, headers={'User-Agent': 'HomeServer-adblock/1'}), timeout=60) as response:
            data = response.read(MAX_SOURCE + 1)
        if len(data) > MAX_SOURCE:
            raise ValueError('source too large')
        result = parse(data.decode('utf-8-sig', errors='replace').splitlines())
    except (OSError, ValueError, Refusal) as exc:
        raise Refusal('blocklist-source-unreachable') from exc
    if not result:
        raise Refusal('blocklist-source-empty')
    return result


def _pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate key')
        obj[key] = value
    return obj


def document(raw):
    value = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda x: (_ for _ in ()).throw(ValueError('invalid constant')))
    if not isinstance(value, dict):
        raise ValueError('invalid document')
    return value


def chosen(doc):
    node = doc
    for name in ('settings', 'dns', 'adblock', 'lists'):
        if not isinstance(node, dict):
            raise ValueError('invalid config')
        if name not in node:
            return [{'url': DEFAULT}]
        node = node[name]
    if not isinstance(node, list) or len(node) > 16:
        raise ValueError('invalid sources')
    result = []
    for entry in node:
        if not isinstance(entry, dict) or set(entry) != {'url'}:
            raise ValueError('invalid source')
        validate_url(entry['url'])
        result.append({'url': entry['url']})
    if len({entry['url'] for entry in result}) != len(result):
        raise ValueError('duplicate source')
    return result


def read_sources():
    return chosen(document(appliance_runtime_path('config').read_text(encoding='utf-8')))


def _object_members(text, start):
    """Yield key and value byte-equivalent character spans of a JSON object."""
    decoder = json.JSONDecoder()
    i = start + 1
    while True:
        while text[i].isspace():
            i += 1
        if text[i] == '}':
            return
        key, i = decoder.raw_decode(text, i)
        while text[i].isspace():
            i += 1
        if text[i] != ':':
            raise ValueError('invalid object')
        i += 1
        while text[i].isspace():
            i += 1
        begin = i
        _, i = decoder.raw_decode(text, i)
        yield key, begin, i
        while text[i].isspace():
            i += 1
        if text[i] == '}':
            return
        if text[i] != ',':
            raise ValueError('invalid object')
        i += 1


def splice_lists(text, lists):
    """Replace only the selected value, or insert the smallest missing subtree."""
    names = ('settings', 'dns', 'adblock', 'lists')
    pos = len(text) - len(text.lstrip())
    for depth, name in enumerate(names):
        if text[pos] != '{':
            raise ValueError('invalid config ancestry')
        members = list(_object_members(text, pos))
        found = next(((start, end) for key, start, end in members if key == name), None)
        if found:
            start, end = found
            if depth == len(names) - 1:
                return text[:start] + json.dumps(lists, ensure_ascii=False, separators=(',', ':')) + text[end:]
            pos = start
            continue
        value = lists
        for remaining in reversed(names[depth + 1:]):
            value = {remaining: value}
        fragment = json.dumps(name) + ': ' + json.dumps(value, ensure_ascii=False, separators=(',', ':'))
        # Insert just after '{'; no existing character is rewritten.
        return text[:pos + 1] + fragment + (',' if members else '') + text[pos + 1:]
    raise ValueError('invalid path')


def change_sources(verb, url):
    validate_url(url)
    path = appliance_runtime_path('config')
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    tmp = None
    try:
        fcntl.flock(directory, fcntl.LOCK_EX)
        original = path.read_bytes()
        info = path.stat()
        text = original.decode('utf-8')
        sources = chosen(document(text))
        exists = any(x['url'] == url for x in sources)
        if verb == 'add':
            if exists:
                return sources, False
            if len(sources) >= 16:
                raise Refusal('blocklist-source-limit')
            fetch(url)
            sources.append({'url': url})
        else:
            if not exists:
                return sources, False
            sources = [entry for entry in sources if entry['url'] != url]
        encoded = splice_lists(text, sources).encode('utf-8')
        document(encoded.decode('utf-8'))
        fd, name = tempfile.mkstemp(prefix='.config-adblock-', dir=path.parent)
        tmp = Path(name)
        with os.fdopen(fd, 'wb') as handle:
            os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode))
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if path.read_bytes() != original:
            raise OSError('config changed concurrently')
        os.replace(tmp, path)
        tmp = None
        os.fsync(directory)
        if read_sources() != sources:
            raise OSError('config readback mismatch')
        return sources, True
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
        os.close(directory)


def digest(sources):
    return hashlib.sha256('\n'.join(x['url'] for x in sources).encode()).hexdigest()[:12]


def live_info():
    _, live = paths()
    try:
        mtime = int(live.stat().st_mtime)
        with live.open(encoding='utf-8', errors='replace') as f:
            match = HEADER.fullmatch(f.readline().rstrip('\n'))
            count = sum(1 for line in f if line.lstrip().startswith('local-zone:'))
        return match, count, mtime
    except FileNotFoundError:
        return None, 0, None


def status_info():
    match, count, checked = live_info()
    built = checked
    if match:
        try:
            built = int(datetime.fromisoformat(match.group(2).replace('Z', '+00:00')).timestamp())
        except ValueError:
            pass
    try:
        sources = read_sources()
        signal = 'none'
    except (OSError, ValueError, UnicodeError, Refusal):
        sources, signal = [], 'blocklist-config-unreadable'
    return {'blocklistDomainCount': count, 'blocklistLastUpdate': built,
            'blocklistCheckedAt': checked, 'blocklistSources': sources,
            'blocklistSourcesSignal': signal}


def receipt(ok, outcome, sources, count=0, signal='none', host=None, changed=False):
    return {'ok': ok, 'outcome': outcome, 'domainCount': count, 'sources': sources,
            'firstMissingSignal': signal, 'firstFailingSource': host,
            'changed': changed, 'mutationPerformed': changed}


def verify():
    try:
        sources = read_sources()
        header, count, mtime = live_info()
        current = bool(header and header.group(1) == digest(sources) and mtime is not None and 0 <= time.time() - mtime < 86400)
        return receipt(current, 'current' if current else 'stale', sources, count, 'none' if current else 'blocklist-stale')
    except (OSError, ValueError, Refusal):
        return receipt(False, 'stale', [], signal='blocklist-stale')


def _run(argv):
    return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          text=True, timeout=60, check=False)


@identity_locked
def _install(sources, ordered):
    config, live = paths()
    _, current_count, _ = live_info()
    old = live.read_bytes() if live.exists() else None
    old_lines = old.split(b'\n', 1) if old is not None else []
    body = ''.join(f'local-zone: "{name}" always_nxdomain\n' for name in ordered).encode()
    old_header = HEADER.fullmatch(old_lines[0].decode('ascii', errors='replace')) if old_lines else None
    if old_header and old_header.group(1) == digest(sources) and old_header.group(3) == str(len(ordered)) and len(old_lines) == 2 and old_lines[1] == body:
        os.utime(live, None)
        return receipt(True, 'unchanged', sources, len(ordered))
    built = datetime.now(timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    data = f'# homeserver adblock lists={digest(sources)} built={built} domains={len(ordered)}\n'.encode() + body
    check = os.environ.get('CADUCEUS_UNBOUND_CHECKCONF', '/usr/sbin/unbound-checkconf')
    def verify():
        if _run([check, str(config)]).returncode:
            raise Refusal('blocklist-checkconf-failed')
    def reload():
        if unit.reload('unbound', runner=_run).returncode:
            raise Refusal('blocklist-reload-failed')
    try:
        parts = write([{'path': live, 'candidate': data}], verify=verify, reload=reload)
    except WriteError as exc:
        signal = str(exc.cause) if isinstance(exc.cause, Refusal) else 'blocklist-config-write-failed'
        result = receipt(False, 'failed', sources, current_count, signal)
        result.update({key: exc.parts[key] for key in ('observed', 'could_change_to', 'attempt', 'final_receipt')})
        if exc.restore_errors:
            result['restoreFailed'] = True
        return result
    _, count, _ = live_info()
    result = receipt(True, 'applied', sources, count, changed=parts['changed'])
    result.update({key: parts[key] for key in ('observed', 'could_change_to', 'attempt', 'final_receipt')})
    return result


def refresh(sources):
    _, live = paths()
    domains = set()
    for entry in sources:
        try:
            domains.update(fetch(entry['url']))
        except Refusal as exc:
            try:
                os.utime(live, None)
                _, count, _ = live_info()
            except OSError:
                return receipt(False, 'failed', sources, signal='blocklist-config-write-failed')
            return receipt(True, 'held', sources, count, str(exc), urlsplit(entry['url']).hostname)
    try:
        return _install(sources, sorted(domains))
    except (OSError, ValueError, subprocess.SubprocessError):
        return receipt(False, 'failed', sources, signal='blocklist-config-write-failed')


def execute(verb, url=None):
    started = time.monotonic()
    if verb == 'list':
        try:
            return receipt(True, 'unchanged', read_sources(), live_info()[1])
        except (OSError, ValueError, UnicodeError, Refusal):
            return receipt(False, 'failed', [], signal='blocklist-config-unreadable')
    try:
        if verb == 'verify':
            return verify()
        if verb in ('add', 'remove'):
            sources, changed = change_sources(verb, url)
            result = refresh(sources)
            result['changed'] = changed
            result['mutationPerformed'] = changed or result['mutationPerformed']
            target = ('added' if verb == 'add' else 'removed') if changed else 'unchanged'
        else:
            result = refresh(read_sources())
            target = result['outcome']
    except Refusal as exc:
        host = None
        if verb == 'add' and str(exc) in ('blocklist-source-unreachable', 'blocklist-source-empty'):
            host = urlsplit(url).hostname
        result = receipt(False, 'failed', [], signal=str(exc), host=host)
        target = 'failed'
    except (OSError, ValueError, UnicodeError):
        result = receipt(False, 'failed', [], signal='blocklist-config-write-failed')
        target = 'failed'
    signal = result['firstMissingSignal']
    _deed.send('network-dns-blocklist', verb, result['ok'] and result['outcome'] != 'held', target=target,
               duration_ms=int((time.monotonic() - started) * 1000), signal=signal)
    return result

"""Release-only Xenia installation, invoked by the root launcher."""
from __future__ import annotations

import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import _launcher as launcher

SCHEMA = "appliance.xenia.install.v1"
FORBIDDEN = ("MemoryHigh", "MemoryMax", "MemorySwapMax", "MemoryMin", "MemoryLow", "ManagedOOM", "OOMScoreAdjust", "CPUQuota", "TasksMax", "Protect", "Private", "Restrict", "NoNewPrivileges", "ReadOnlyPaths", "ReadWritePaths", "InaccessiblePaths", "SystemCall", "LockPersonality", "MemoryDenyWriteExecute", "CapabilityBoundingSet", "AmbientCapabilities", "DynamicUser")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
SEGMENT = re.compile(r"^[A-Za-z0-9_.-]+$")
MAX_ASSET = 128 * 1024 * 1024

# Overrides are a ground-only proof instrument, never an installed root door.
PROOF = Path(__file__).resolve().is_relative_to(Path('/var/lib/work'))
def setting(name: str, default: str) -> str:
    return os.environ.get(name, default) if PROOF else default

class Failure(Exception):
    def __init__(self, signal: str, refused: bool = False):
        self.signal = signal
        self.refused = refused

class SameHostRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if target.scheme != 'https' or target.hostname != 'git.home.arpa':
            raise Failure('release-redirect-refused')
        return super().redirect_request(req, fp, code, msg, headers, newurl)

GITHUB_HOSTS = frozenset(('api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com'))

def github_url(url):
    parsed = urllib.parse.urlsplit(url)
    try:
        valid = (parsed.scheme == 'https' and parsed.hostname in GITHUB_HOSTS and
                 not parsed.username and not parsed.password and parsed.port in (None, 443))
    except ValueError:
        valid = False
    if not valid:
        raise Failure('candidate-url-refused')

class GitHubRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        github_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def github_fetch(url, maximum=MAX_ASSET):
    github_url(url)
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), GitHubRedirect())
        with opener.open(urllib.request.Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'xenia'}), timeout=30) as response:
            data = response.read(maximum + 1)
    except urllib.error.HTTPError as exc:
        raise Failure('candidate-http-' + str(exc.code)) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise Failure('candidate-fetch-failed') from exc
    if len(data) > maximum:
        raise Failure('release-asset-too-large')
    return data

def credential() -> str | None:
    path = Path(setting('XENIA_FORGE_CREDENTIAL', '/etc/default/forgejo'))
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Failure('forgejo-credential-unreadable') from exc
    for line in lines:
        if line.startswith('FORGEJO_TOKEN='):
            token = line.split('=', 1)[1].strip().strip("\"'")
            if token and '\n' not in token and '\r' not in token:
                return token
    raise Failure('forgejo-token-empty')

def fetch(url: str, token: str | None, maximum: int = MAX_ASSET) -> bytes:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname != 'git.home.arpa' or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise Failure('release-url-refused')
    headers = {'Accept': 'application/json'}
    if token:
        headers['Authorization'] = 'token ' + token
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), SameHostRedirect())
        with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response:
            data = response.read(maximum + 1)
    except urllib.error.HTTPError as exc:
        raise Failure('release-http-' + str(exc.code)) from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise Failure('release-fetch-failed') from exc
    if len(data) > maximum:
        raise Failure('release-asset-too-large')
    return data

def fetch_json(url: str, token: str | None):
    try:
        return json.loads(fetch(url, token, 1024 * 1024))
    except (ValueError, UnicodeError) as exc:
        raise Failure('release-json-invalid') from exc

def release(entry: dict, ident: str, receipt: dict):
    source = entry.get('source') or {}
    repo, ref = source.get('release_repo'), source.get('ref')
    if not isinstance(repo, str) or not isinstance(ref, str) or not ref:
        raise Failure('release-source-missing')
    parts = repo.split('/')
    if len(parts) != 2 or any(not SEGMENT.fullmatch(part) or part in ('.', '..') for part in parts) or parts[1] != 'cartridge-' + ident:
        raise Failure('release-repository-invalid')
    base = 'https://git.home.arpa/api/v1/repos/' + repo
    token = credential()
    declared = source.get('candidates') or []
    if not isinstance(declared, list):
        raise Failure('candidate-list-invalid')
    urls = []
    for candidate in declared:
        if not isinstance(candidate, dict) or candidate.get('kind') != 'release' or candidate.get('credential_selector') is not None:
            raise Failure('candidate-invalid')
        url = candidate.get('url')
        if not isinstance(url, str) or not re.fullmatch(r'https://github\.com/[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*', url):
            raise Failure('candidate-url-invalid')
        owner, name = url.removeprefix('https://github.com/').split('/')
        if owner in ('.', '..') or name in ('.', '..'):
            raise Failure('candidate-url-invalid')
        urls.append((url, 'https://api.github.com/repos/' + owner + '/' + name + '/releases/tags/latest'))
    cached = {}
    def fallback(commit):
        for url, api in urls:
            if api not in cached:
                try:
                    cached[api] = json.loads(github_fetch(api, 1024 * 1024))
                except Failure as exc:
                    if exc.signal != 'candidate-http-404':
                        raise
                    cached[api] = None
                except (ValueError, UnicodeError) as exc:
                    raise Failure('candidate-json-invalid') from exc
            row = cached[api]
            if isinstance(row, dict) and not row.get('draft') and row.get('tag_name') == 'latest' and row.get('target_commitish') == commit:
                return row, url
        return None, None
    selected_url = None
    sha = ''
    if SHA.fullmatch(ref):
        metadata = None
        for tag in ('sha-' + ref, ref):
            try:
                metadata = fetch_json(base + '/releases/tags/' + tag, token)
                break
            except Failure as exc:
                if exc.signal != 'release-http-404':
                    raise
        sha = ref
        if metadata is None:
            metadata, selected_url = fallback(sha)
        if metadata is None:
            raise Failure('candidate-release-not-found' if urls else 'release-not-found')
    else:
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', ref) or '..' in ref or ref.startswith('/'):
            raise Failure('release-ref-invalid')
        releases = []
        for page in range(1, 101):
            batch = fetch_json(base + f'/releases?limit=50&page={page}', token)
            if not isinstance(batch, list) or any(not isinstance(row, dict) for row in batch):
                raise Failure('release-list-invalid')
            releases.extend(batch)
            if len(batch) < 50:
                break
        else:
            raise Failure('release-list-limit')
        candidates = [row for row in releases if not row.get('draft') and isinstance(row.get('target_commitish'), str) and SHA.fullmatch(row['target_commitish'])]
        candidates.sort(key=lambda x: (x.get('created_at', ''), x.get('id', 0)), reverse=True)
        by_commit = {}
        for row in candidates:
            by_commit.setdefault(row['target_commitish'], row)
        metadata = None
        for page in range(1, 101):
            commits = fetch_json(base + '/commits?sha=' + urllib.parse.quote(ref, safe='') + f'&limit=50&page={page}', token)
            if not isinstance(commits, list) or any(not isinstance(row, dict) for row in commits):
                raise Failure('release-branch-history-invalid')
            for commit in commits:
                sha = commit.get('sha')
                if not isinstance(sha, str) or not SHA.fullmatch(sha):
                    raise Failure('release-branch-history-invalid')
                metadata = by_commit.get(sha)
                if metadata is None:
                    metadata, selected_url = fallback(sha)
                if metadata is not None:
                    break
            if metadata is not None or len(commits) < 50:
                break
        else:
            raise Failure('release-branch-history-limit')
        if metadata is None:
            raise Failure('candidate-release-not-found' if urls else 'release-branch-not-found')
    if not isinstance(metadata, dict):
        raise Failure('release-metadata-invalid')
    receipt['source'] = 'candidate' if selected_url else 'forge'
    receipt['candidate_url'] = selected_url
    receipt['source_sha'] = sha
    if metadata.get('draft') or metadata.get('target_commitish') != sha or metadata.get('tag_name') not in (('latest',) if selected_url else (sha, 'sha-' + sha)):
        raise Failure('release-target-mismatch')
    assets = {a.get('name'): a for a in metadata.get('assets', []) if isinstance(a, dict)}
    binary_name = parts[1] + '-x86_64'
    def asset(name, maximum=MAX_ASSET):
        row = assets.get(name)
        if not isinstance(row, dict) or not isinstance(row.get('browser_download_url'), str):
            raise Failure('release-asset-missing-' + name)
        return github_fetch(row['browser_download_url'], maximum) if selected_url else fetch(row['browser_download_url'], token, maximum)
    try:
        flag = json.loads(asset('release.flag', 1024 * 1024))
    except (ValueError, UnicodeError) as exc:
        raise Failure('release-flag-invalid') from exc
    if not isinstance(flag, dict) or flag.get('schema') != 'estate.release-flag.v1' or flag.get('component') != parts[1] or flag.get('source_sha') != sha:
        raise Failure('release-flag-binding-mismatch')
    expected = flag.get('sha256')
    env_sha = flag.get('env_sha')
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected) or (env_sha is not None and (not isinstance(env_sha, str) or not DIGEST.fullmatch(env_sha))):
        raise Failure('release-flag-digest-invalid')
    data = asset(binary_name)
    digest = hashlib.sha256(data).hexdigest()
    if digest != expected:
        raise Failure('release-flag-digest-mismatch')
    try:
        checksum = asset(binary_name + '.sha256', 1024 * 1024).decode('ascii').split()[0]
        manifest = json.loads(asset('cartridge.json', 1024 * 1024))
    except (ValueError, UnicodeError, IndexError) as exc:
        raise Failure('release-sidecar-invalid') from exc
    if checksum != digest or not isinstance(manifest, dict):
        raise Failure('release-sidecar-mismatch')
    return sha, digest, data

def schema_base() -> str:
    path = setting('XENIA_CONFIG', '/etc/appliance/config.json')
    try:
        bind = json.loads(Path(path).read_bytes())['caduceus']['bind']
        host, port = bind.rsplit(':', 1)
        if not host or not port.isascii() or not port.isdecimal() or not 0 < int(port) < 65536 or any(c in bind for c in '\r\n /'):
            raise ValueError
        if host.startswith('[') and host.endswith(']'):
            address = ipaddress.IPv6Address(host[1:-1])
        else:
            try:
                address = ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError:
                name = host.removesuffix('.')
                if len(name) > 253 or not name or all(c.isdigit() or c == '.' for c in name) or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in name.split('.')):
                    raise ValueError
                address = None
        if address is not None and address.is_unspecified:
            host = '127.0.0.1'
        return 'http://' + host + ':' + port
    except (OSError, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise Failure('caduceus-bind-undeclared') from exc

def render_unit(ident: str, seat: Path, binary: Path, owner: str, base: str) -> str:
    values = (ident, str(seat), str(binary), owner, base)
    if any(not value or '\n' in value or '\r' in value for value in values) or not base.startswith('http://'):
        raise Failure('xenia-unit-contract-mismatch')
    text = (f'[Unit]\nDescription=Xenia guest {ident}\nX-Xenia-Id={ident}\nAfter=network.target caduceus.service\n\n'
            f'[Service]\nType=simple\nUser={owner}\nGroup={owner}\nWorkingDirectory={seat}\n'
            f'Environment=XENIA_ID={ident}\nEnvironment=XENIA_SEAT={seat}\nEnvironment=XENIA_SCHEMA_BASE={base}\n'
            f'ExecStart={binary}\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n')
    if any(line.split('=', 1)[0].strip().startswith(FORBIDDEN) for line in text.splitlines() if '=' in line):
        raise Failure('xenia-unit-forbidden-directives')
    return text

def systemctl(*args: str, check: bool = True, absent_unit: str | None = None) -> bool:
    exe = setting('XENIA_SYSTEMCTL', '/usr/bin/systemctl')
    environment = None
    if absent_unit is not None:
        environment = {**os.environ, 'LC_ALL': 'C'}
    try:
        result = subprocess.run([exe, *args], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30, check=False, env=environment)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Failure('xenia-systemctl-unavailable') from exc
    if result.returncode:
        if not check and args[0] == 'is-active' and result.returncode in (3, 4) and not result.stderr:
            return False
        if not check and args[0] == 'is-enabled' and result.returncode in (1, 4):
            if not result.stderr:
                return False
            missing = f'Failed to get unit file state for {absent_unit}: No such file or directory'.encode()
            if absent_unit is not None and args[-1] == absent_unit and result.stderr.strip() == missing:
                return False
        raise Failure('xenia-systemctl-' + args[0] + '-failed')
    return True

class NoHealthRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Failure('xenia-health-redirect-refused')

def health(ident: str, sha: str, wait: bool):
    deadline = time.monotonic() + (15 if wait else 0)
    while True:
        try:
            override = setting('XENIA_PROOF_HEALTH_ENDPOINT', '')
            if override:
                endpoint = override
            else:
                rows = launcher.census_xenos(ident)['listeners']
                tcp = [r for r in rows if r.get('port') is not None and str(r.get('endpoint', '')).startswith('http://127.0.0.1:')]
                if len(rows) != 1 or len(tcp) != 1:
                    raise Failure('xenia-listener-not-single-loopback')
                endpoint = tcp[0]['endpoint'].removeprefix('http://')
            if not re.fullmatch(r'127\.0\.0\.1:[0-9]{1,5}', endpoint) or not 0 < int(endpoint.split(':')[1]) < 65536:
                raise Failure('xenia-health-endpoint-invalid')
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoHealthRedirect())
            with opener.open('http://' + endpoint + '/health', timeout=2) as response:
                body = json.loads(response.read(65537))
            actual = body.get('source_sha') if isinstance(body, dict) else None
            if actual != sha:
                raise Failure('xenia-health-source-mismatch')
            return {'ok': True, 'source_sha': actual, 'endpoint': endpoint}
        except (OSError, ValueError, launcher.Refusal, Failure) as exc:
            if time.monotonic() >= deadline:
                raise Failure(exc.signal if isinstance(exc, Failure) else 'xenia-health-unavailable') from exc
            time.sleep(0.25)

def safe_read(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise Failure('xenia-file-unreadable') from exc
    try:
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise Failure('xenia-file-not-regular')
            return stream.read(MAX_ASSET + 1)
    except OSError as exc:
        raise Failure('xenia-file-unreadable') from exc

def deed(verb, ident, ok, signal, started):
    from agathodaimon._deed import send
    send("sbin", "xenia-" + verb, ok, target=ident,
         duration_ms=int((time.monotonic() - started) * 1000))

def run(verb: str, ident: str, dry: bool):
    started = time.monotonic()
    receipt = {'schema': SCHEMA, 'verb': verb, 'id': ident, 'ok': False, 'road': 'release', 'source': None, 'candidate_url': None, 'source_sha': None, 'sha256': None, 'unit': None, 'active': None, 'health': None, 'signal': 'none', 'changed': False}
    changed = False
    try:
        try:
            entry = launcher._registered_entry(ident)
        except launcher.Refusal as exc:
            raise Failure(exc.first_missing_signal, exc.first_missing_signal in ('xenos-not-registered', 'xenos-id-invalid')) from exc
        source = entry.get('source') or {}
        if not isinstance(source, dict):
            raise Failure('release-source-invalid')
        if source.get('kind') == 'own-service':
            raise Failure('own-service-is-not-installed' if verb == 'install' else 'own-service-unit-is-the-owners', True)
        if source.get('kind') == 'clone':
            raise Failure('clone-road-retired', True)
        if source.get('kind') not in (None, 'release'):
            raise Failure('release-source-kind-invalid')
        unit = ident + '.service'
        declaration = entry.get('install') or {}
        if not isinstance(declaration, dict) or declaration.get('unit') not in (None, unit):
            raise Failure('xenia-unit-name-mismatch')
        receipt['unit'] = unit
        unit_root = Path(setting('XENIA_UNIT_ROOT', '/etc/systemd/system'))
        unit_fd = launcher._open_absolute_directory(unit_root, 'xenia-unit-root-missing', 'xenia-unit-root-invalid', 'xenia-unit-root-unavailable')
        try:
            root_metadata = os.fstat(unit_fd)
            if root_metadata.st_uid != 0 or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise Failure('xenia-unit-root-untrusted')
        finally:
            os.close(unit_fd)
        unit_path = unit_root / unit
        if verb == 'uninstall':
            old_unit = safe_read(unit_path)
            if old_unit is not None and ('X-Xenia-Id=' + ident).encode() not in old_unit.splitlines():
                raise Failure('xenia-unit-not-managed')
            active = systemctl('is-active', '--quiet', unit, check=False)
            enabled = systemctl('is-enabled', '--quiet', unit, check=False,
                                absent_unit=unit if old_unit is None and not active else None)
            if old_unit is None and (active or enabled):
                raise Failure('xenia-unit-not-managed')
            receipt['active'] = active
            changed = bool(old_unit is not None or active or enabled)
            if changed and not dry:
                if active:
                    systemctl('stop', unit)
                if enabled:
                    systemctl('disable', unit)
                if old_unit is not None:
                    unit_path.unlink()
                    systemctl('daemon-reload')
                receipt['active'] = False
        else:
            owner, identity = launcher._registered_owner(entry)
            try:
                group = grp.getgrnam('xenia')
            except KeyError as exc:
                if not PROOF:
                    raise Failure('xenos-xenia-group-missing') from exc
                group = grp.getgrgid(identity.pw_gid)
            root = Path(setting('XENIA_SEAT_ROOT', '/var/lib/xenia'))
            seat = root / ident
            raw_bin = declaration.get('bin')
            canonical = Path('/var/lib/xenia') / ident
            if not isinstance(raw_bin, str):
                raise Failure('xenia-install-bin-missing')
            try:
                relative = Path(raw_bin).relative_to(canonical)
            except ValueError as exc:
                raise Failure('xenia-install-bin-path-mismatch') from exc
            if len(relative.parts) != 1 or relative.name in ('.', '..') or not SEGMENT.fullmatch(relative.name):
                raise Failure('xenia-install-bin-path-mismatch')
            binary = seat / relative
            base = schema_base()
            text = render_unit(ident, seat, binary, owner, base).encode()
            sha, digest, data = release(entry, ident, receipt)
            receipt['source_sha'], receipt['sha256'] = sha, digest
            old_unit = safe_read(unit_path)
            if old_unit is not None and ('X-Xenia-Id=' + ident).encode() not in old_unit.splitlines():
                raise Failure('xenia-unit-not-managed')
            root_fd = launcher._open_absolute_directory(root, 'xenos-seat-root-missing', 'xenos-seat-root-invalid', 'xenos-seat-root-unavailable')
            try:
                root_stat = os.fstat(root_fd)
                if root_stat.st_uid != 0 or root_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                    raise Failure('xenos-seat-root-untrusted')
                try:
                    seat_stat = os.stat(ident, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    seat_stat = None
                if seat_stat is not None and not stat.S_ISDIR(seat_stat.st_mode):
                    raise Failure('xenos-seat-not-a-directory')
                old_binary = safe_read(binary) if seat_stat is not None else None
                binary_stat = binary.stat(follow_symlinks=False) if old_binary is not None else None
                ownership_ok = (seat_stat is not None and seat_stat.st_uid == identity.pw_uid and seat_stat.st_gid == group.gr_gid and stat.S_IMODE(seat_stat.st_mode) == 0o750 and binary_stat is not None and binary_stat.st_uid == identity.pw_uid and binary_stat.st_gid == group.gr_gid and stat.S_IMODE(binary_stat.st_mode) == 0o755)
            finally:
                os.close(root_fd)
            active = systemctl('is-active', '--quiet', unit, check=False)
            if old_unit is None and active:
                raise Failure('xenia-unit-not-managed')
            receipt['active'] = active
            current_health = None
            if active:
                try:
                    current_health = health(ident, sha, False)
                except Failure:
                    pass
            changed = old_binary != data or old_unit != text or not ownership_ok or not active or current_health is None
            if changed and not dry:
                launcher.SEAT_ROOT = root
                launcher.seat_xenos(ident)
                seat_fd = launcher._open_absolute_directory(seat, 'xenos-seat-missing', 'xenos-seat-invalid', 'xenos-seat-unavailable')
                try:
                    name = '.xenia-install-' + str(os.getpid())
                    fd = os.open(name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o755, dir_fd=seat_fd)
                    try:
                        with os.fdopen(fd, 'wb') as stream:
                            stream.write(data)
                            stream.flush()
                            os.fchown(stream.fileno(), identity.pw_uid, group.gr_gid)
                            os.fchmod(stream.fileno(), 0o755)
                        os.replace(name, relative.name, src_dir_fd=seat_fd, dst_dir_fd=seat_fd)
                    finally:
                        try:
                            os.unlink(name, dir_fd=seat_fd)
                        except FileNotFoundError:
                            pass
                finally:
                    os.close(seat_fd)
                if old_unit != text:
                    fd = os.open(unit_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
                    with os.fdopen(fd, 'wb') as stream:
                        stream.write(text)
                    systemctl('daemon-reload')
                systemctl('enable', '--now', unit)
                if active:
                    systemctl('restart', unit)
                receipt['active'] = systemctl('is-active', '--quiet', unit, check=False)
                if not receipt['active']:
                    raise Failure('xenia-unit-inactive')
                current_health = health(ident, sha, True)
            receipt['health'] = current_health
        receipt['ok'] = True
        receipt['changed'] = changed
        if changed and not dry:
            deed(verb, ident, True, 'none', started)
        return receipt, 0
    except launcher.Refusal as exc:
        failure = Failure(exc.first_missing_signal)
    except Failure as exc:
        failure = exc
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        failure = Failure('xenia-operation-failed')
    receipt['signal'] = failure.signal
    receipt['changed'] = changed
    if changed and not dry:
        try:
            deed(verb, ident, False, failure.signal, started)
        except OSError:
            pass
    return receipt, 2 if failure.refused else 1

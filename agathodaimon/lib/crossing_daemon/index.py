"""A bounded local warm-fork staff crossing server."""
from __future__ import annotations

import contextlib
import errno
import hashlib
import io
import json
import os
import pwd
import selectors
import signal
import socket
import stat
import struct
import sys
import syslog
import threading
import time
from pathlib import Path

from agathodaimon import cli

SCHEMA = 'caduceus.staff.crossing.v1'
REQUEST_LIMIT = 256 * 1024
STDOUT_LIMIT = 1024 * 1024
STDERR_LIMIT = 64 * 1024
GRACE = 0.25


class OutputLimit(BaseException):
    pass


class MissingField(ValueError):
    pass


class BoundedText(io.StringIO):
    def __init__(self, limit):
        super().__init__()
        self.limit = limit
        self.size = 0

    @property
    def buffer(self):
        return _BinaryOutput(self)

    def write(self, value):
        count = len(value.encode('utf-8'))
        if self.size + count > self.limit:
            raise OutputLimit()
        self.size += count
        return super().write(value)


class _BinaryOutput:
    def __init__(self, output):
        self.output = output

    def write(self, value):
        self.output.write(bytes(value).decode('utf-8'))
        return len(value)

    def flush(self):
        self.output.flush()


def reply(code, out='', err=''):
    return (json.dumps({'schema': SCHEMA, 'exit': code, 'stdout': out, 'stderr': err},
                       ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')


def request_fields(data):
    """Parse top-level values while preserving the envelope's original bytes."""
    text = data.decode('utf-8')
    decoder = json.JSONDecoder()
    i = 0
    def whitespace(pos):
        while pos < len(text) and text[pos] in ' \t\r\n':
            pos += 1
        return pos
    i = whitespace(i)
    if i == len(text) or text[i] != '{':
        raise ValueError('request-object-required')
    i += 1
    fields, raw_envelope = {}, None
    while True:
        i = whitespace(i)
        if i < len(text) and text[i] == '}':
            i += 1
            break
        key, i = decoder.raw_decode(text, i)
        if not isinstance(key, str) or key in fields:
            raise ValueError('request-key-invalid')
        i = whitespace(i)
        if i >= len(text) or text[i] != ':':
            raise ValueError('request-invalid')
        i = whitespace(i + 1)
        start = i
        value, i = decoder.raw_decode(text, i)
        fields[key] = value
        if key == 'envelope':
            raw_envelope = value if isinstance(value, str) else text[start:i]
        i = whitespace(i)
        if i < len(text) and text[i] == ',':
            i = whitespace(i + 1)
            if i >= len(text) or text[i] == '}':
                raise ValueError('request-invalid')
            continue
        if i < len(text) and text[i] == '}':
            i += 1
            break
        raise ValueError('request-invalid')
    if whitespace(i) != len(text):
        raise ValueError('request-invalid')
    for field in ('schema', 'band', 'envelope', 'timeoutMs'):
        if field not in fields:
            raise MissingField(field)
    if fields['schema'] != SCHEMA:
        raise ValueError('crossing-schema-invalid')
    band, envelope, timeout = fields['band'], fields['envelope'], fields['timeoutMs']
    if not isinstance(band, str) or not band or len(band) > 256:
        raise ValueError('crossing-band-invalid')
    if not isinstance(envelope, (dict, str)):
        raise ValueError('crossing-envelope-invalid')
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 600000:
        raise ValueError('crossing-timeout-invalid')
    return band, raw_envelope, timeout


def peer_identity(conn):
    _pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid == 0:
        return uid, 'root'
    for name in ('owner', 'caduceus'):
        try:
            if uid == pwd.getpwnam(name).pw_uid:
                return uid, name
        except KeyError:
            pass
    return uid, 'other'


def set_socket_acl(path):
    """Root plus exactly the named owner and service users, not a shared group."""
    owner = pwd.getpwnam('owner').pw_uid
    service = pwd.getpwnam('caduceus').pw_uid
    if owner == service or 0 in (owner, service):
        raise ValueError('crossing-socket-identities-invalid')
    undefined = 0xffffffff
    entries = [(0x01, 6, undefined)]
    entries += [(0x02, 6, uid) for uid in sorted((owner, service))]
    entries += [(0x04, 0, undefined), (0x10, 6, undefined), (0x20, 0, undefined)]
    acl = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)
    os.setxattr(path, 'system.posix_acl_access', acl, follow_symlinks=False)


def grant_directory_search(path):
    """Add search for the two peers without broadening other ACL entries."""
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise OSError('crossing-parent-not-directory')
    accounts = [pwd.getpwnam('owner'), pwd.getpwnam('caduceus')]
    undefined = 0xffffffff
    try:
        raw = os.getxattr(path, 'system.posix_acl_access', follow_symlinks=False)
    except OSError as error:
        if error.errno != errno.ENODATA:
            raise
        entries = [(1, (info.st_mode >> 6) & 7, undefined),
                   (4, (info.st_mode >> 3) & 7, undefined),
                   (32, info.st_mode & 7, undefined)]
    else:
        if len(raw) < 4 or (len(raw) - 4) % 8 or struct.unpack_from('<I', raw)[0] != 2:
            raise ValueError('crossing-directory-acl-invalid')
        entries = [struct.unpack_from('<HHI', raw, offset) for offset in range(4, len(raw), 8)]
    mask = next((perm for tag, perm, _ in entries if tag == 16), (info.st_mode >> 3) & 7)
    original = list(entries)
    # Preserve the old effective permissions before widening the mask for x.
    entries = [(tag, perm & mask if tag in (2, 4, 8) else perm, ident)
               for tag, perm, ident in entries if tag != 16]
    other = next(perm for tag, perm, _ in original if tag == 32)
    for account in accounts:
        if account.pw_uid == info.st_uid:
            entries = [(tag, perm | 1 if tag == 1 else perm, ident) for tag, perm, ident in entries]
            continue
        existing = next((perm & mask for tag, perm, ident in original
                         if tag == 2 and ident == account.pw_uid), None)
        if existing is None:
            groups = set(os.getgrouplist(account.pw_name, account.pw_gid))
            matches = [perm for tag, perm, ident in original
                       if (tag == 4 and info.st_gid in groups) or (tag == 8 and ident in groups)]
            existing = 0
            for perm in matches:
                existing |= perm & mask
            if not matches:
                existing = other
        entries = [(tag, perm, ident) for tag, perm, ident in entries
                   if not (tag == 2 and ident == account.pw_uid)]
        entries.append((2, existing | 1, account.pw_uid))
    entries.append((16, mask | 1, undefined))
    order = {1: 0, 2: 1, 4: 2, 8: 3, 16: 4, 32: 5}
    entries.sort(key=lambda item: (order[item[0]], item[2]))
    value = struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *entry) for entry in entries)
    os.setxattr(path, 'system.posix_acl_access', value, follow_symlinks=False)


def audit(uid, band, outcome, started, signal_name=None, missing_field=None):
    if not isinstance(band, str) or not band or len(band) > 256 or any(
        c not in 'abcdefghijklmnopqrstuvwxyz0123456789/_.-' for c in band
    ):
        band = 'invalid'
    signal_name = signal_name or ('none' if outcome == 'ok' else outcome)
    missing_field = missing_field or ('none' if outcome == 'ok' else 'unknown')
    msg = (f'who={uid} verb=crossing target={band} outcome={outcome} '
           f'duration_ms={int((time.monotonic()-started)*1000)} '
           f'signal={signal_name} first_missing_field={missing_field}')
    syslog.syslog(syslog.LOG_INFO, msg)


def _close_inherited(keep):
    for name in os.listdir('/proc/self/fd'):
        if name.isdecimal():
            fd = int(name)
            if fd > 2 and fd not in keep:
                try:
                    os.close(fd)
                except OSError:
                    pass


def _child(conn, notice, control, stdout_fd, stderr_fd, identity, band, raw, deadline):
    delivered = False
    try:
        os.setsid()
        os.dup2(stdout_fd, 1)
        os.dup2(stderr_fd, 2)
        _close_inherited({conn.fileno(), notice, control})
        sys.stdout = os.fdopen(1, 'w', encoding='utf-8', buffering=1, closefd=False)
        sys.stderr = os.fdopen(2, 'w', encoding='utf-8', buffering=1, closefd=False)
        os.environ.clear()
        os.environ.update({'HOME': '/root', 'LOGNAME': 'root', 'USER': 'root',
                           'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                           'SHELL': '/bin/bash'})
        if identity == 'caduceus':
            os.environ['SUDO_USER'] = 'caduceus'
        # Bound the front door's internal envelope-hand capture as well as the
        # OS-level pipes drained by the parent.
        cli.StringIO = lambda: BoundedText(STDOUT_LIMIT)
        outcome, mutation, code, signal_name = 'failed', True, 1, 'unknown'
        try:
            if identity == 'other':
                outcome, signal_name = 'refused', 'peer-refused'
                raise PermissionError('crossing-peer-refused')
            if identity == 'caduceus' and not cli._admit_caduceus_crossing([band]):
                outcome, code, signal_name = 'refused', 1, 'band-not-published'
            else:
                target = cli._slash_target(band)
                mutation = target is None or cli._mutation_allowed(target.parent if target.is_file() else target) is not False
                sys.stdin = cli._EnvelopeStdin(raw)
                try:
                    code = cli.main([band])
                except SystemExit as exc:
                    code = exc.code if isinstance(exc.code, int) else 1
                outcome = 'ok' if code == 0 else 'failed'
                signal_name = 'none' if code == 0 else 'band-nonzero-exit'
        except OutputLimit:
            code, outcome, signal_name = 1, 'output-limit', 'output-limit'
            print('crossing-output-limit', file=sys.stderr)
        except BaseException as exc:
            code = 1
            if outcome != 'refused':
                outcome = 'failed'
                known = (OSError, ValueError, TypeError, RuntimeError, ImportError, PermissionError)
                signal_name = type(exc).__name__ if type(exc) in known else 'band-exception'
            print('crossing-child-failed', file=sys.stderr)
        sys.stdout.flush()
        sys.stderr.flush()
        os.close(1)
        os.close(2)
        os.write(notice, json.dumps({'outcome': outcome, 'mutation': mutation,
                                     'exit': int(code or 0), 'signal': signal_name}).encode())
        os.close(notice)
        # Only the forked child writes a normal crossing response.  The parent
        # drains bounded OS pipes and sends the resulting wire bytes back here.
        while True:
            chunk = os.read(control, 65536)
            if not chunk:
                break
            conn.settimeout(max(0.001, deadline - time.monotonic()))
            conn.sendall(chunk)
        delivered = True
    except BaseException:
        pass
    finally:
        os._exit(0 if delivered else 1)


def _kill_group(pid, sig):
    try:
        os.killpg(pid, sig)
    except ProcessLookupError:
        try:
            os.kill(pid, sig)
        except ProcessLookupError:
            pass


class CrossingDaemon:
    def __init__(self, path):
        absolute = os.path.abspath(os.fspath(path))
        self.path = os.path.join(os.path.realpath(os.path.dirname(absolute)), os.path.basename(absolute))
        self.server = None
        self.guard = None
        self.stop = threading.Event()
        self.slots = threading.BoundedSemaphore(64)

    def serve_forever(self):
        # The abstract guard has kernel lifetime and survives no process restart;
        # unlike probing/unlinking a live socket it cannot race another starter.
        guard = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        guard.bind('\0crossing-' + hashlib.sha256(os.path.abspath(self.path).encode()).hexdigest())
        self.guard = guard
        parent = Path(self.path).parent
        try:
            parent.mkdir(mode=0o711, parents=True, exist_ok=False)
        except FileExistsError:
            pass
        else:
            # Search the new directory without granting directory listing;
            # the socket ACL itself decides who can connect.
            os.chmod(parent, 0o711)
        if os.geteuid() == 0:
            parent_info = os.stat(parent, follow_symlinks=False)
            if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise OSError('crossing-parent-not-root-controlled')
            grant_directory_search(parent)
        try:
            existing = os.lstat(self.path)
            if not stat.S_ISSOCK(existing.st_mode):
                raise OSError('crossing-path-not-socket')
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.25)
                try:
                    probe.connect(self.path)
                except ConnectionRefusedError:
                    current = os.lstat(self.path)
                    if (current.st_dev, current.st_ino) != (existing.st_dev, existing.st_ino):
                        raise OSError('crossing-path-changed')
                    os.unlink(self.path)
                else:
                    raise OSError('crossing-path-in-use')
        except FileNotFoundError:
            pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server = server
        server.bind(self.path)
        bound = os.lstat(self.path)
        try:
            os.chmod(self.path, 0o600)
            if os.geteuid() == 0:
                set_socket_acl(self.path)
            server.listen(64)
            server.settimeout(1)
            while not self.stop.is_set():
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    continue
                if not self.slots.acquire(blocking=False):
                    started = time.monotonic()
                    uid = -1
                    try:
                        conn.settimeout(5)
                        uid, _ = peer_identity(conn)
                        conn.sendall(reply(1, err='crossing-busy'))
                    except OSError:
                        pass
                    finally:
                        conn.close()
                        audit(uid, '', 'busy', started)
                    continue
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        finally:
            server.close()
            try:
                current = os.lstat(self.path)
                if (current.st_dev, current.st_ino) == (bound.st_dev, bound.st_ino):
                    os.unlink(self.path)
            except FileNotFoundError:
                pass
            guard.close()

    def _handle(self, conn):
        started = time.monotonic()
        uid, band, outcome, mutation = -1, '', 'failed', True
        signal_name, missing_field = None, None
        try:
            with contextlib.nullcontext(conn):
                read_deadline = time.monotonic() + 5
                uid, identity = peer_identity(conn)
                data = bytearray()
                while b'\n' not in data:
                    remaining = read_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('crossing-request-timeout')
                    conn.settimeout(remaining)
                    chunk = conn.recv(min(65536, REQUEST_LIMIT + 1 - len(data)))
                    if not chunk:
                        raise ValueError('crossing-request-incomplete')
                    data.extend(chunk)
                    if len(data) > REQUEST_LIMIT:
                        raise ValueError('crossing-request-limit')
                if not data.endswith(b'\n') or data.count(b'\n') != 1:
                    raise ValueError('crossing-request-framing')
                band, raw, timeout = request_fields(bytes(data[:-1]))
                deadline = time.monotonic() + timeout / 1000
                pipes = []
                try:
                    for _ in range(4):
                        pipes.append(os.pipe2(os.O_CLOEXEC))
                    (out_r, out_w), (err_r, err_w), (notice_r, notice_w), (control_r, control_w) = pipes
                    pid = os.fork()
                except OSError:
                    for pair in pipes:
                        for fd in pair:
                            os.close(fd)
                    raise
                if pid == 0:
                    for fd in (out_r, err_r, notice_r, control_w):
                        os.close(fd)
                    _child(conn, notice_w, control_r, out_w, err_w, identity, band, raw, deadline)
                for fd in (out_w, err_w, notice_w, control_r):
                    os.close(fd)
                killed = False
                handed_to_child = False
                open_fds = {out_r, err_r, notice_r, control_w}
                try:
                    chunks = {out_r: bytearray(), err_r: bytearray(), notice_r: bytearray()}
                    limits = {out_r: STDOUT_LIMIT, err_r: STDERR_LIMIT, notice_r: 4096}
                    with selectors.DefaultSelector() as selector:
                        for fd in chunks:
                            os.set_blocking(fd, False)
                            selector.register(fd, selectors.EVENT_READ)
                        while selector.get_map():
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                outcome = 'timeout'
                                break
                            events = selector.select(remaining)
                            if not events:
                                outcome = 'timeout'
                                break
                            for key, _ in events:
                                fd = key.fd
                                chunk = os.read(fd, 65536)
                                if not chunk:
                                    selector.unregister(fd)
                                else:
                                    chunks[fd].extend(chunk)
                                    if len(chunks[fd]) > limits[fd]:
                                        outcome = 'output-limit'
                                        break
                            if outcome == 'output-limit':
                                break
                    if outcome in ('timeout', 'output-limit'):
                        _kill_group(pid, signal.SIGTERM)
                        time.sleep(GRACE)
                        _kill_group(pid, signal.SIGKILL)
                        killed = True
                        conn.sendall(reply(1, err='crossing-' + outcome))
                    elif not chunks[notice_r]:
                        outcome = 'child-died'
                        conn.sendall(reply(1, err='crossing-child-died'))
                    else:
                        result = json.loads(chunks[notice_r])
                        outcome, mutation = result['outcome'], result['mutation']
                        signal_name = result['signal']
                        if outcome == 'failed':
                            try:
                                body = json.loads(chunks[out_r])
                                known_signals = {'agathodaimon-band-not-published',
                                                 'agathodaimon-envelope-invocation-failed',
                                                 'chord-secret-carrier-refused'}
                                if isinstance(body, dict) and body.get('firstMissingSignal') in known_signals:
                                    signal_name = body['firstMissingSignal']
                            except (ValueError, UnicodeError, TypeError):
                                pass
                        wire = reply(result['exit'], chunks[out_r].decode('utf-8', 'replace'),
                                     chunks[err_r].decode('utf-8', 'replace'))
                        view = memoryview(wire)
                        while view:
                            view = view[os.write(control_w, view):]
                        os.close(control_w)
                        open_fds.remove(control_w)
                        handed_to_child = True
                finally:
                    for fd in open_fds:
                        os.close(fd)
                    if not killed and not handed_to_child:
                        _kill_group(pid, signal.SIGKILL)
                    _, status = os.waitpid(pid, 0)
                    if handed_to_child and (not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0):
                        outcome, signal_name = 'response-failed', 'response-failed'
        except MissingField as exc:
            outcome, signal_name, missing_field = 'failed', 'missing-required-field', str(exc)
            try:
                conn.sendall(reply(1, err='crossing-request-failed'))
            except OSError:
                pass
        except (OSError, ValueError, UnicodeError) as exc:
            outcome = 'failed'
            known = {'request-invalid', 'request-object-required', 'request-key-invalid',
                     'crossing-schema-invalid', 'crossing-band-invalid', 'crossing-envelope-invalid',
                     'crossing-timeout-invalid', 'crossing-request-incomplete',
                     'crossing-request-limit', 'crossing-request-framing'}
            if type(exc) is ValueError and str(exc) in known:
                signal_name = str(exc)
            elif isinstance(exc, json.JSONDecodeError):
                signal_name = 'invalid-json'
            elif isinstance(exc, UnicodeError):
                signal_name = 'invalid-utf8'
            elif isinstance(exc, TimeoutError):
                signal_name = 'request-timeout'
            else:
                signal_name = 'request-io-failed'
            try:
                conn.sendall(reply(1, err='crossing-request-failed'))
            except OSError:
                pass
        finally:
            conn.close()
            if outcome != 'ok' or mutation:
                audit(uid, band, outcome, started, signal_name, missing_field)
            self.slots.release()

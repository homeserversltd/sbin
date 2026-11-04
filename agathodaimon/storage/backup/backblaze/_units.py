from __future__ import annotations
from ._store import hashlib, os, subprocess, time, socket, struct, sys, Path, select, signal, json, re, Refusal, fail, scratch_root, row_for, load, valid_items, manager, deed
from ._restic import restic_environment, ensure_repository, backup_files, add_counts

# The unchanged worker bodies resolve paths relative to the facade entrypoint.
__file__ = str(Path(__file__).with_name('shared.py'))

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
                            '--property=ActiveState', '--property=SubState', '--property=Result', '--property=ExecMainExitTimestamp',
                            '--property=ExecMainCode', '--property=ExecMainStatus', '--property=MainPID'],
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5, check=False, text=True)
    except (OSError, subprocess.SubprocessError):
        fail('status', 'systemd-unavailable')
    fields = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
    if p.returncode:
        fail('status', 'systemd-unavailable')
    return fields


def unit_running(state):
    return state.get('SubState') in ('running', 'start', 'start-pre', 'start-post', 'reload', 'stop', 'stop-sigterm', 'stop-sigkill', 'stop-post', 'final-sigterm', 'final-sigkill') or state.get('ActiveState') in ('activating', 'deactivating', 'reloading')


def launch(bucket, scheduled=False):
    if os.geteuid() != 0:
        fail('run', 'root-required')
    listener = None
    connection = None
    pidfd = None
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
        cmd += ['--', sys.executable, str(Path(__file__).resolve())]
        if scheduled:
            address = 'backblaze-run-' + os.urandom(16).hex()
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind('\0' + address)
            listener.listen(1)
            listener.settimeout(8)
            cmd += ['--worker-scheduled', bucket, address]
        else:
            cmd += ['--worker', bucket]
        process = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=8, check=False)
        if process.returncode:
            fail('run', 'bucket-launch-refused')
        if scheduled:
            connection, _ = listener.accept()
            connection.settimeout(8)
            peer_pid, peer_uid, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if peer_uid != 0 or str(peer_pid) != unit_status(bucket).get('MainPID'):
                fail('run', 'bucket-launch-peer-invalid')
            pidfd = os.pidfd_open(peer_pid)
            if connection.recv(1) != b'R':
                fail('run', 'bucket-launch-refused')
            connection.sendall(b'G')
            connection.settimeout(None)
            result = connection, pidfd
            connection, pidfd = None, None
            return result
    except (OSError, subprocess.SubprocessError):
        fail('run', 'bucket-launch-unavailable')
    finally:
        if listener is not None:
            listener.close()
        if connection is not None:
            connection.close()
        if pidfd is not None:
            os.close(pidfd)
    return {'ok':True, 'status':'accepted', 'unit':run_unit(bucket)}


def wait_for_run(handshake, bucket):
    connection, pidfd = handshake
    try:
        with connection.makefile('rb') as stream:
            line = stream.readline(1024)
        select.select([pidfd], [], [])
        state = unit_status(bucket)
        if state.get('ExecMainCode') in ('2', '3'):
            number = int(state.get('ExecMainStatus', '0'))
            if 0 < number < signal.NSIG:
                return {'ok':False, 'step':'run', 'reason':'worker-signal-' + str(number)}, False
        value = json.loads(line)
        if not isinstance(value, dict) or type(value.get('ok')) is not bool:
            raise ValueError('invalid outcome')
        if value['ok']:
            if state.get('ExecMainCode') == '1' and state.get('ExecMainStatus') == '0':
                return {'ok':True}, True
            raise ValueError('worker-exit-unconfirmed')
        step, reason = value.get('step'), value.get('reason')
        if (isinstance(step, str) and isinstance(reason, str)
                and re.fullmatch(r'[a-z0-9-]{1,96}', step) and re.fullmatch(r'[a-z0-9-]{1,128}', reason)):
            return {'ok':False, 'step':step, 'reason':reason}, step != 'deed'
    except (ValueError, OSError, subprocess.SubprocessError, Refusal):
        try:
            state = unit_status(bucket)
        except Refusal:
            state = {}
    finally:
        connection.close()
        os.close(pidfd)
    if state.get('ExecMainCode') in ('2', '3'):
        try:
            number = int(state.get('ExecMainStatus', '0'))
            if 0 < number < signal.NSIG:
                return {'ok':False, 'step':'run', 'reason':'worker-signal-' + str(number)}, False
        except ValueError:
            pass
    return {'ok':False, 'step':'run', 'reason':'worker-outcome-unavailable'}, False


def run_files(bucket, result_socket=None):
    started = time.monotonic()
    outcome, error, step, key = 'failed', 'unknown', 'run', None
    counts = {}
    try:
        row = row_for(load(), bucket)
        paths = [x['path'] for x in valid_items(row.get('items', []))]
        forgejo = manager(row)
        env, key = restic_environment(row)
        ensure_repository(row, env, key)
        if paths:
            backup_files(paths, env, counts)
        if forgejo.get('backblazeBackup', False):
            if scratch_root():
                fail('forgejo', 'scratch-live-forgejo-refused')
            child = Path(__file__).resolve().parents[1] / 'forgejo/backup-b2/_backup.py'
            with subprocess.Popen([sys.executable, str(child), '--worker', bucket],
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL) as process:
                assert process.stdout is not None
                line = process.stdout.readline(65536)
                while process.stdout.read(65536):
                    pass
                code = process.wait()
            try:
                result = json.loads(line)
                if isinstance(result, dict):
                    add_counts(counts, result)
            except (ValueError, UnicodeError):
                pass
            if code:
                fail('forgejo', 'forgejo-backup-failed')
        outcome, error = 'ok', 'none'
    except Refusal as exc:
        step, error = exc.step, exc.reason
    except (OSError, ValueError, UnicodeError):
        error = 'run-internal-failure'
    finally:
        if key is not None:
            key[:] = b'\0' * len(key)
        try:
            deed('backblaze-bucket-run', bucket, outcome, started, error, counts)
        except Refusal:
            outcome, step, error = 'failed', 'deed', 'deed-write-failed'
    if result_socket is not None:
        result = {'ok':True} if outcome == 'ok' else {'ok':False, 'step':step, 'reason':error}
        try:
            result_socket.sendall((json.dumps(result, separators=(',', ':')) + '\n').encode('utf-8'))
        except OSError:
            pass
    return 0 if outcome == 'ok' else 1



"""Native Backblaze bucket staff: configuration, credentials and restic."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from agathodaimon.storage.backup.backblaze._store import base64, datetime, timezone, errno, fcntl, hashlib, json, os, re, select, signal, socket, stat, struct, subprocess, tempfile, time, NoReturn, urllib, KeymanExportError, exchange_session, export_credential, NAME, SKIP, CONFIG, SKELETON, KEYMAN, Refusal, fail

ACTUATORS = {name: 'backblaze-' + name for name in ('bucket-add', 'bucket-credentials', 'bucket-verify', 'bucket-remove', 'bucket-items', 'bucket-save', 'bucket-run', 'status', 'snapshots')}

from agathodaimon.storage.backup.backblaze import _keyman
from agathodaimon.storage.backup.backblaze._store import scratch_root, config_path, config_lock_path, skeleton_path, restic_bin, repository, valid_bucket, bucket_name, keyman_service, normalize_skips, valid_items, load, rows, row_for, manager, normalized_row, store, deed
from agathodaimon.storage.backup.backblaze._keyman import derivation, skeleton_password, credentials, seed, authorize
from agathodaimon.storage.backup.backblaze._restic import restic_environment, invoke_restic, summary_counts, add_counts, backup_files, _ensure_repository, ensure_repository, snapshot_list
from agathodaimon.storage.backup.backblaze._units import scratch_unit_prefix, run_unit, release_result, unit_status, unit_running, launch, wait_for_run, run_files

def __getattr__(name):
    if name == 'SEED_ATTEMPTED':
        return _keyman.SEED_ATTEMPTED
    raise AttributeError(name)

def __dir__():
    return sorted(set(globals()) | {'SEED_ATTEMPTED'})

def dispatch(verb, metadata, scheduled=False, deed_verb=None):
    if verb not in ACTUATORS or not isinstance(metadata, dict):
        fail('shape', 'metadata-invalid')
    data = load()
    if verb == 'status':
        from agathodaimon.storage.backup.backblaze.status.index import act
        return act(data)
    if verb == 'snapshots':
        from agathodaimon.storage.backup.backblaze.snapshots.index import act
        return act(metadata, data)
    bucket = bucket_name(metadata.get('bucket'))
    if scratch_root() and verb in ('bucket-add', 'bucket-credentials', 'bucket-verify'):
        fail('scratch', 'scratch-live-authority-refused')
    if scratch_root() and verb in ('bucket-run', 'bucket-remove') and not bucket.startswith('scratch-'):
        fail('scratch', 'scratch-unit-name-required')
    if verb == 'bucket-run':
        from importlib import import_module
        return import_module('agathodaimon.storage.backup.backblaze.bucket-run.index').act(data, bucket, scheduled)
    if verb == 'bucket-verify':
        from importlib import import_module
        return import_module('agathodaimon.storage.backup.backblaze.bucket-verify.index').act(data, bucket)
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
            from importlib import import_module
            mutation_result = import_module('agathodaimon.storage.backup.backblaze.' + verb + '.index').act(verb, metadata, data, bucket)
        else:
            row = row_for(data, bucket)
            if verb == 'bucket-remove':
                from importlib import import_module
                import_module('agathodaimon.storage.backup.backblaze.bucket-remove.index').act(data, bucket, row)
            elif verb == 'bucket-items':
                from importlib import import_module
                import_module('agathodaimon.storage.backup.backblaze.bucket-items._items').act(metadata, row)
            elif verb == 'bucket-save':
                from importlib import import_module
                import_module('agathodaimon.storage.backup.backblaze.bucket-save.index').act(metadata, row)
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
                deed(deed_verb or ACTUATORS[verb], bucket, outcome, started, signal_name)
            except Refusal:
                if outcome == 'ok':
                    mutation_result['deed'] = 'unwritten'


def main_for(verb, request_override=None, return_result=False, deed_verb=None):
    _keyman.SEED_ATTEMPTED = False
    budgets = {'bucket-add':240, 'bucket-credentials':240, 'bucket-verify':240,
               'bucket-remove':45, 'bucket-items':45, 'bucket-save':45, 'bucket-run':45,
               'status':20, 'snapshots':480}
    def deadline(_sig, _frame):
        fail('request', 'request-deadline-after-keyman-seed-attempt' if _keyman.SEED_ATTEMPTED else 'request-deadline-exceeded')
    previous = None
    started = time.monotonic()
    request = None
    worker_reported = False
    run_lease = None
    try:
        previous = signal.signal(signal.SIGALRM, deadline)
        signal.alarm(budgets.get(verb, 20))
        if request_override is None:
            raw = sys.stdin.buffer.read(16385)
            if len(raw) > 16384:
                fail('shape', 'request-too-large')
            try:
                request = json.loads(raw)
            except (ValueError, UnicodeError):
                fail('shape', 'request-invalid')
        else:
            request = request_override
        scheduled = (isinstance(request, dict) and verb == 'bucket-run'
                     and request.get('actuator') == 'bucket-run'
                     and request.get('transition') == 'storage/backup/backblaze/bucket-run')
        if not isinstance(request, dict) or (not scheduled and request.get('actuator') != ACTUATORS[verb]):
            fail('shape', 'actuator-envelope-invalid')
        if scheduled:
            signal.alarm(0)
        if verb == 'bucket-run' and isinstance(request.get('metadata'), dict):
            bucket = bucket_name(request['metadata'].get('bucket'))
            run_lease = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            name = hashlib.sha256(run_unit(bucket).encode('utf-8')).hexdigest()
            try:
                run_lease.bind('\0backblaze-run-lease-' + name)
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    fail('run', 'bucket-run-active')
                raise
        if verb in ('bucket-add', 'bucket-credentials', 'bucket-remove', 'bucket-items', 'bucket-save', 'bucket-run'):
            fd = None
            try:
                lock_path = config_lock_path()
                fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                result = dispatch(verb, request.get('metadata'), scheduled=scheduled, deed_verb=deed_verb)
            except BlockingIOError:
                fail('config', 'config-update-active')
            finally:
                if fd is not None:
                    os.close(fd)
            if scheduled:
                result, worker_reported = wait_for_run(result, bucket_name(request['metadata'].get('bucket')))
        else:
            result = dispatch(verb, request.get('metadata'))
    except Refusal as error:
        result = {'ok':False, 'step':error.step, 'reason':error.reason}
    except Exception:
        result = {'ok':False, 'step':'request', 'reason':'request-unavailable'}
    finally:
        if run_lease is not None:
            run_lease.close()
        if previous is not None:
            try:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, previous)
            except Exception:
                result = {'ok':False, 'step':'request', 'reason':'request-unavailable'}
    if not result.get('ok') and not worker_reported and verb in ('bucket-add', 'bucket-credentials', 'bucket-remove', 'bucket-items', 'bucket-save', 'bucket-run'):
        metadata = request.get('metadata') if isinstance(request, dict) else None
        value = metadata.get('bucket') if isinstance(metadata, dict) else None
        try:
            deed(deed_verb or ACTUATORS[verb], value if valid_bucket(value) else 'invalid', 'failed', started, result['reason'])
        except Exception:
            result['deed'] = 'unwritten'
    if return_result:
        return result
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result.get('ok') else 1


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker':
        raise SystemExit(run_files(bucket_name(sys.argv[2])))
    if len(sys.argv) == 4 and sys.argv[1] == '--worker-scheduled':
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.connect('\0' + sys.argv[3])
            connection.sendall(b'R')
            if connection.recv(1) != b'G':
                raise SystemExit(1)
            raise SystemExit(run_files(bucket_name(sys.argv[2]), result_socket=connection))
    raise SystemExit(1)

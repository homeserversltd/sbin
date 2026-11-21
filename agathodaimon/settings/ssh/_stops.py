"""Single-act SSH exposure stops over the standing toggle primitives."""
import json
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import NamedTuple

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon._nidus.lock import held
from agathodaimon._nidus.path import appliance_runtime_path
from agathodaimon._nidus.refusal import named_signal
from agathodaimon._nidus.run import run
from agathodaimon._nidus.write import WriteError, write
from agathodaimon.settings.ssh import _acts as ssh


PUBKEY = 'PubkeyAuthentication'
LIVE_CONFIG = Path(ssh.SSH_CONFIG)
_MATCH_EQUALS = re.compile(r'^[ \t]*Match=', re.IGNORECASE | re.MULTILINE)
_AUTH_VALUE = re.compile(r'[ \t]*(?:=[ \t]*)?(?P<quote>"?)(?P<value>yes|no)(?P=quote)[ \t]*(?:#.*)?',
                         re.IGNORECASE)


class _AuthLine(NamedTuple):
    offset: int
    text: str
    start: int
    end: int
    value: str


def _config_path():
    path = appliance_runtime_path('profile').parent.parent / 'ssh' / LIVE_CONFIG.name
    if path != LIVE_CONFIG and not path.resolve().is_relative_to(path.parents[2].resolve()):
        raise ssh.Refusal('agathodaimon-ssh-exposure-scratch-config-outside-root')
    return path


def _config_lock():
    return held('ssh-config', path=appliance_runtime_path('identity-lock').with_name('ssh-config.lock'))


def _read_text(path):
    try:
        if not stat.S_ISREG(path.lstat().st_mode):
            raise OSError
        return path.read_bytes().decode('utf-8', 'surrogateescape')
    except OSError:
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-read-refused') from None


def _global(raw):
    region, rest = ssh._split_global(raw)
    # OpenSSH also accepts Match=User ..., which has no standalone Match token.
    boundary = _MATCH_EQUALS.search(region)
    if boundary:
        return region[:boundary.start()], raw[boundary.start():]
    return region, rest


def _auth_line(raw, directive):
    """Locate only the requested global directive, retaining its exact span."""
    region, _ = _global(raw)
    prefix = re.compile(r'^[ \t]*' + directive + r'(?=[ \t=]|$)', re.IGNORECASE)
    found = None
    offset = 0
    for line in region.splitlines(keepends=True):
        body = line.rstrip('\r\n')
        key = prefix.match(body)
        if key:
            match = _AUTH_VALUE.fullmatch(body, key.end())
            if match is None:
                raise ssh.Refusal('agathodaimon-ssh-exposure-directive-unsupported')
            if found is not None:
                raise ssh.Refusal('agathodaimon-ssh-exposure-directive-ambiguous')
            start, end = match.span('value')
            found = _AuthLine(offset, line, start, end, match.group('value').lower())
        offset += len(line)
    return found


def _edit_auth(raw, directive, desired):
    entry = _auth_line(raw, directive)
    if entry is not None:
        # Use the standing editor's transition on a canonical single line,
        # then splice just that value back into the exact original bytes.
        _, change = ssh._replace_directive(f'{directive} {entry.value}', directive, desired)
        if change is None:
            return raw, None
        return raw[:entry.offset + entry.start] + change['to'] + raw[entry.offset + entry.end:], change
    region, rest = _global(raw)
    replacement, change = ssh._replace_directive(region, directive, desired)
    if region.endswith('\r\n'):
        replacement = region + replacement[len(region):].replace('\n', '\r\n')
    return replacement + rest, change


def _scratch_tool(path, name):
    tool = shutil.which(name)
    if tool is None or not Path(tool).resolve().is_relative_to(path.parents[2].resolve()):
        raise ssh.Refusal('agathodaimon-ssh-exposure-scratch-tool-unavailable')
    return tool


def _command(commands, argv, signal):
    commands.append(argv)
    try:
        return run(argv)
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise ssh.Refusal(signal) from None


def _sshd(path, flag, commands, signal, *, parse_if_no_privsep=False):
    tool = ssh.SSHD if path == LIVE_CONFIG else _scratch_tool(path, 'sshd')
    result = _command(commands, [tool, flag, '-f', str(path)], signal)
    if (parse_if_no_privsep and flag == '-t' and result.returncode != 0
            and result.stderr.strip() == 'Missing privilege separation directory: /run/sshd'):
        # An inactive service may not have its runtime directory. Validate the
        # configuration without creating that directory or checking host keys.
        result = _command(commands, [tool, '-G', '-f', str(path)], signal)
    ssh._must(result, signal)
    return result.stdout


def _write_auth(path, original, updated, commands, *, validator=None, reload=None, after=None, check_current=True):
    validated = False

    def validate():
        if validator is not None:
            validator()
        elif path == LIVE_CONFIG:
            commands.extend(ssh._validate())
        else:
            _sshd(path, '-t', commands, 'agathodaimon-ssh-exposure-config-invalid')

    def check():
        if _read_text(path) != original:
            raise ssh.Refusal('agathodaimon-ssh-exposure-config-changed')
        if check_current:
            validate()

    def verify():
        nonlocal validated
        validate()
        validated = True

    def refresh():
        # Nidus also invokes this on compensation; don't reload a unit
        # when the new file was rejected before its first reload.
        if validated and reload is not None:
            reload()

    def readback():
        if _read_text(path) != updated:
            raise ssh.Refusal('agathodaimon-ssh-exposure-config-readback-mismatch')
        if after is not None:
            after()

    return write([{'path': path, 'candidate': updated.encode('utf-8', 'surrogateescape')}],
                 check=check, verify=verify, reload=refresh if reload else None, readback=readback)


def _state(value):
    if value not in ('on', 'off'):
        raise ssh.Refusal('unsupported-operation')
    return value


def config_read(payload, commands):
    raw, steps = ssh._read_config()
    commands.extend(steps)
    return {'directives': ssh._directive_values(raw), 'raw': raw}


def config_set(payload, commands, witness):
    state = _state(payload.get('state'))
    desired = 'yes' if state == 'on' else 'no'
    path = _config_path()
    with _config_lock():
        original = _read_text(path)
        witness.update(original=original, changedFlag=False)
        updated, transition = _edit_auth(original, PUBKEY, desired)
        try:
            _write_auth(path, original, updated, commands)
        except WriteError as failure:
            if failure.restore_errors:
                witness['changedFlag'] = True
                raise ssh.Refusal('agathodaimon-ssh-exposure-config-restore-refused') from None
            raise ssh.Refusal(named_signal(failure.cause, 'agathodaimon-ssh-exposure-config-set')) from None
    return {'original': original, 'changed': [transition] if transition else [],
            'changedFlag': transition is not None,
            'unchanged': [] if transition else [{'directive': PUBKEY, 'value': desired}],
            'mutation_performed': transition is not None}


def config_restore(payload, commands):
    changed = payload.get('changed')
    if changed is not True:
        return {'restored': False, 'reason': 'unchanged', 'mutation_performed': False}
    original = payload.get('original')
    if not isinstance(original, str):
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-original-missing')
    path = _config_path()
    try:
        with _config_lock():
            current = _read_text(path)
            previous = _auth_line(original, PUBKEY)
            present = _auth_line(current, PUBKEY)
            prior_line = previous.text if previous else ''
            present_line = present.text if present else ''
            restored = current
            if present_line != prior_line:
                # A password stop can run between arpeggio stages. Undo only
                # the pubkey line that config-set wrote, not the whole witness.
                for value in ('yes', 'no'):
                    candidate, change = _edit_auth(original, PUBKEY, value)
                    added = _auth_line(candidate, PUBKEY) if change else None
                    if present and added and added.text.rstrip('\r\n') == present_line.rstrip('\r\n'):
                        if current == candidate:
                            restored = original
                        elif previous:
                            restored, _ = _edit_auth(current, PUBKEY, previous.value)
                        else:
                            restored = current[:present.offset] + current[present.offset + len(present_line):]
                        break
                else:
                    raise ssh.Refusal('agathodaimon-ssh-exposure-config-restore-conflict')
            _write_auth(path, current, restored, commands, check_current=False)
    except WriteError:
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-restore-refused') from None
    return {'restored': True, 'mutation_performed': restored != current}


def unit_resolve(payload, commands):
    unit, steps = ssh._service_unit()
    commands.extend(steps)
    return {'unit': unit}


def verify(payload, commands):
    state = _state(payload.get('state'))
    unit = payload.get('unit')
    if unit not in ('ssh.service', 'sshd.service'):
        raise ssh.Refusal('agathodaimon-ssh-exposure-service-missing')
    pubkey = _auth_line(_read_text(_config_path()), PUBKEY)
    service, steps = ssh._service_readback(unit)
    commands.extend(steps)
    expected = state == 'on'
    if service['active'] != expected or service['enabled'] != expected:
        raise ssh.Refusal('agathodaimon-ssh-exposure-service-readback-mismatch')
    if pubkey is None or pubkey.value != ('yes' if expected else 'no'):
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-readback-mismatch')
    return {'directives': {PUBKEY: pubkey.value}, 'service': service}


def main(name, known_fields):
    commands = []
    witness = {}
    try:
        request = read(known_fields=known_fields)
        source = request.value.get('payload', {}) if request.envelope else request.value
        if not isinstance(source, dict):
            raise ssh.Refusal('payload-not-object')
        unknown = next((field for field in source if field not in known_fields), None)
        if unknown is not None:
            raise ssh.Refusal('unknown-field:' + unknown)
        if name == 'config_set':
            result = config_set(request.payload, commands, witness)
        else:
            result = globals()[name](request.payload, commands)
        result.update(ok=True, commands=commands, firstMissingSignal='none')
        result = attach(result, request)
    except (EnvelopeError, ssh.Refusal, OSError) as error:
        result = {'ok': False, 'commands': commands,
                  'firstMissingSignal': named_signal(error, 'agathodaimon-ssh-exposure') if isinstance(error, OSError) else str(error)}
        if name == 'config_set':
            result.update(witness)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 1

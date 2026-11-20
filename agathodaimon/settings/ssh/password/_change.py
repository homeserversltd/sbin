"""Keep the global SSH password setting independently of the service switch."""
import json

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon._nidus.refusal import named_signal
from agathodaimon._nidus.unit import systemctl
from agathodaimon._nidus.write import WriteError
from agathodaimon.settings.ssh import _acts as ssh, _stops as stops


DIRECTIVE = 'PasswordAuthentication'
SIGNAL = 'agathodaimon-ssh-password'


def _unit_state(call):
    for unit in reversed(ssh.SSH_UNITS):
        result = call('show', '--property=FragmentPath', '--value', unit)
        if result.returncode == 0 and result.stdout.strip().startswith('/'):
            break
    else:
        raise ssh.Refusal('agathodaimon-ssh-exposure-service-missing')
    result = call('show', '--property=ActiveState', '--value', unit)
    state = result.stdout.strip()
    if result.returncode or state not in ('active', 'inactive', 'failed'):
        raise ssh.Refusal(f'{SIGNAL}-service-state-unobserved')
    return unit, state


def _change(desired, receipt):
    commands = receipt['commands']
    path = stops._config_path()

    def call(*args):
        def runner(argv):
            if path != stops.LIVE_CONFIG:
                argv = [stops._scratch_tool(path, 'systemctl'), *argv[1:]]
            return stops._command(commands, argv, f'{SIGNAL}-systemctl-failed')
        return systemctl(*args, runner=runner)

    reloading = False

    def reload():
        nonlocal reloading
        rollback = reloading
        if rollback and stops._read_text(path) != original:
            raise ssh.Refusal(f'{SIGNAL}-rollback-config-unrestored')
        reloading = True
        ssh._must(call('reload', unit), f'{SIGNAL}-reload-refused')
        receipt['rollbackReloaded' if rollback else 'reloaded'] = True

    def effective_readback():
        if not change:
            # An identical file can still be ahead of the running unit.
            reload()
        output = stops._sshd(path, '-T', commands, f'{SIGNAL}-effective-read-refused')
        effective = stops._auth_line(output, DIRECTIVE)
        receipt['effective'] = effective.value if effective else None
        if receipt['effective'] != desired:
            raise ssh.Refusal(f'{SIGNAL}-effective-readback-mismatch')

    with stops._config_lock():
        original = stops._read_text(path)
        updated, change = stops._edit_auth(original, DIRECTIVE, desired)
        receipt['from'] = change['from'] if change else desired
        unit, state = _unit_state(call)
        receipt['observed'] = {'value': receipt['from'], 'unit': unit, 'activeState': state}
        active = state == 'active'
        try:
            parts = stops._write_auth(path, original, updated, commands, reload=reload if active else None,
                                      after=effective_readback if active else None)
        except WriteError as failure:
            parts = failure.parts
            receipt['firstMissingSignal'] = named_signal(failure.cause, SIGNAL)
            if failure.restore_errors:
                receipt['rollbackSignal'] = named_signal(failure.restore_errors[0], f'{SIGNAL}-rollback')
        else:
            receipt.update(ok=True, firstMissingSignal='none')
        steps = [step for step in parts['attempt']['steps']
                 if step['step'] != 'reload-again' or reloading]
        receipt['restored'] = any(step['step'] == 'restore' and step['outcome'] == 'ok' for step in steps)
        receipt['changed'] = any(row['before'] != row['after'] for row in parts['observed'])
        receipt['mutationPerformed'] = reloading or receipt['restored'] or receipt['changed']
        receipt['attempt'] = {'attempted': receipt['mutationPerformed'], 'steps': steps}


def main(desired):
    receipt = {'ok': False, 'directive': DIRECTIVE, 'from': None, 'to': desired,
               'reloaded': False, 'rollbackReloaded': False, 'restored': False,
               'changed': False, 'mutationPerformed': False, 'commands': [],
               'could_change_to': {'value': desired}}
    try:
        request = read()
    except EnvelopeError as error:
        receipt['firstMissingSignal'] = named_signal(error, f'{SIGNAL}-request')
    else:
        try:
            _change(desired, receipt)
        except (ssh.Refusal, OSError) as error:
            receipt['firstMissingSignal'] = named_signal(error, SIGNAL)
        receipt = attach(receipt, request)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt['ok'] else 1

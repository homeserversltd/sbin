"""Single-act SSH exposure stops over the standing toggle primitives."""
import json

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.ssh import index as ssh


SCHEMAS = {name: 'caduceus.settings.ssh.' + name.replace('_', '.') + '.v1'
           for name in ('config_read', 'config_set', 'config_restore', 'unit_resolve', 'verify')}
def _state(value):
    if value not in ('on', 'off'):
        raise ssh.Refusal('unsupported-operation')
    return value


def config_read(payload, commands):
    raw, steps = ssh._read_config()
    commands.extend(steps)
    return {'directives': ssh._directive_values(raw), 'raw': raw}


def config_set(payload, commands):
    state = _state(payload.get('state'))
    desired = {'PasswordAuthentication': 'no',
               'PubkeyAuthentication': 'yes' if state == 'on' else 'no'}
    original, steps = ssh._read_config()
    commands.extend(steps)
    ssh._directive_values(original)
    updated = original
    changed, unchanged = [], []
    for directive in ssh.DIRECTIVES:
        updated, transition = ssh._replace_directive(updated, directive, desired[directive])
        if transition is None:
            unchanged.append({'directive': directive, 'value': desired[directive]})
        else:
            changed.append(transition)
    commands.extend(ssh._validate())
    if updated != original:
        commands.extend(ssh._write_config(updated))
        try:
            commands.extend(ssh._validate())
        except ssh.Refusal:
            try:
                commands.extend(ssh._write_config(original))
                commands.extend(ssh._validate())
            except ssh.Refusal:
                raise ssh.Refusal('agathodaimon-ssh-exposure-config-restore-refused')
            raise
    return {'original': original, 'changed': changed, 'changedFlag': bool(changed),
            'unchanged': unchanged, 'mutation_performed': bool(changed)}


def config_restore(payload, commands):
    changed = payload.get('changed')
    if changed is not True:
        return {'restored': False, 'reason': 'unchanged', 'mutation_performed': False}
    original = payload.get('original')
    if not isinstance(original, str):
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-original-missing')
    try:
        commands.extend(ssh._write_config(original))
        commands.extend(ssh._validate())
    except ssh.Refusal:
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-restore-refused')
    return {'restored': True, 'mutation_performed': True}


def unit_resolve(payload, commands):
    unit, steps = ssh._service_unit()
    commands.extend(steps)
    return {'unit': unit}


def verify(payload, commands):
    state = _state(payload.get('state'))
    unit = payload.get('unit')
    if unit not in ('ssh.service', 'sshd.service'):
        raise ssh.Refusal('agathodaimon-ssh-exposure-service-missing')
    raw, steps = ssh._read_config()
    commands.extend(steps)
    directives = ssh._directive_values(raw)
    service, steps = ssh._service_readback(unit)
    commands.extend(steps)
    expected = state == 'on'
    if service['active'] != expected or service['enabled'] != expected:
        raise ssh.Refusal('agathodaimon-ssh-exposure-service-readback-mismatch')
    desired = {'PasswordAuthentication': 'no', 'PubkeyAuthentication': 'yes' if expected else 'no'}
    if directives != desired:
        raise ssh.Refusal('agathodaimon-ssh-exposure-config-readback-mismatch')
    return {'directives': directives, 'service': service}


def main(name, known_fields):
    schema = SCHEMAS[name]
    commands = []
    try:
        request = read(known_fields=known_fields)
        source = request.value.get('payload', {}) if request.envelope else request.value
        if not isinstance(source, dict):
            raise ssh.Refusal('payload-not-object')
        unknown = next((field for field in source if field not in known_fields), None)
        if unknown is not None:
            raise ssh.Refusal('unknown-field:' + unknown)
        result = globals()[name](request.payload, commands)
        result.update(schema=schema, ok=True, commands=commands, firstMissingSignal='none')
        result = attach(result, request)
    except (EnvelopeError, ssh.Refusal) as error:
        result = {'schema': schema, 'ok': False, 'commands': commands,
                  'firstMissingSignal': str(error)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['ok'] else 1

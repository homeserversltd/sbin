"""Sway shortcut settings: the staff owns only the final override file."""
from __future__ import annotations

import ctypes
import ctypes.util
import glob
import json
import os
import pwd
import re
import sys
from pathlib import Path

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.gui.plugs.shortcuts import _expand, _logical_lines, _sway_bindings, _tokens
from agathodaimon.settings import _parity, _shared
from agathodaimon.settings.display import backends


def _override() -> Path:
    return _shared.home() / '.config/sway/bindings-overrides.conf'


def _loaded() -> tuple[list[Path], bool]:
    """Follow includes from the actual root; an unreferenced fragment is not loaded."""
    root = _shared.home() / '.config/sway/config'
    override = _override()
    paths: list[Path] = []
    active: set[Path] = set()
    variables: dict[str, str] = {}
    found = False

    def visit(path: Path) -> None:
        nonlocal found
        path = path.absolute()
        if path == override.absolute():
            found = True
            return
        if path in active:
            raise ValueError('shortcuts-include-cycle')
        if not path.is_file():
            return
        active.add(path)
        paths.append(path)
        for line in _logical_lines(path.read_text(encoding='utf-8')):
            tokens, _, _ = _tokens(line)
            if len(tokens) >= 3 and tokens[0] == 'set' and tokens[1].startswith('$'):
                variables[tokens[1][1:]] = ' '.join(tokens[2:])
            elif len(tokens) >= 2 and tokens[0] == 'include':
                for raw in tokens[1:]:
                    value = _expand(raw, variables)
                    if value.startswith('~/'):
                        value = str(_shared.home() / value[2:])
                    elif not os.path.isabs(value):
                        value = str(path.parent / value)
                    if Path(value).absolute() == override.absolute():
                        found = True
                    for match in sorted(glob.glob(value)):
                        visit(Path(match))
        active.remove(path)
    visit(root)
    return paths, found


def _blocks(text: str) -> dict[str, tuple[str, str]]:
    lines = text.splitlines(keepends=True)
    blocks: dict[str, tuple[str, str]] = {}
    i = 0
    while i < len(lines):
        marker = re.fullmatch(r'# settings-shortcut-(.+)-begin\s*', lines[i].rstrip('\n'))
        if not marker:
            if re.match(r'# settings-shortcut-.*-(?:begin|end)', lines[i]):
                raise ValueError('shortcuts-override-invalid')
            i += 1
            continue
        key = marker.group(1)
        end = f'# settings-shortcut-{key}-end'
        j = i + 1
        while j < len(lines) and lines[j].rstrip('\r\n') != end:
            if re.match(r'# settings-shortcut-.*-(?:begin|end)', lines[j]):
                raise ValueError('shortcuts-override-invalid')
            j += 1
        if j == len(lines) or key in blocks:
            raise ValueError('shortcuts-override-invalid')
        chunk = ''.join(lines[i:j + 1])
        binds = [line for line in lines[i + 1:j] if line.lstrip().startswith('bindsym ')]
        if len(binds) != 1:
            raise ValueError('shortcuts-override-invalid')
        tokens, _, _ = _tokens(binds[0])
        index = 1
        while index < len(tokens) and tokens[index].startswith('--'):
            option = tokens[index]
            index += 1
            if option == '--input-device':
                index += 1
        if index >= len(tokens):
            raise ValueError('shortcuts-override-invalid')
        blocks[key] = (tokens[index], chunk)
        i = j + 1
    return blocks


def _key_id(value: str) -> tuple[frozenset[str], int]:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        raise ValueError('invalid:to')
    parts = value.split('+')
    aliases = {'Mod1': 'Mod1', 'Alt': 'Mod1', 'Mod2': 'Mod2', 'Mod3': 'Mod3',
               'Mod4': 'Mod4', 'Super': 'Mod4', 'Mod5': 'Mod5', 'Shift': 'Shift',
               'Ctrl': 'Ctrl', 'Control': 'Ctrl'}
    if any(part not in aliases for part in parts[:-1]) or not re.fullmatch(r'[A-Za-z0-9_]+', parts[-1]):
        raise ValueError('invalid:to')
    mods = [aliases[part] for part in parts[:-1]]
    if len(set(mods)) != len(mods):
        raise ValueError('invalid:to')
    library = ctypes.util.find_library('xkbcommon')
    if not library:
        raise ValueError('shortcuts-keysym-library-unavailable')
    xkb = ctypes.CDLL(library)
    xkb.xkb_keysym_from_name.argtypes = (ctypes.c_char_p, ctypes.c_int)
    xkb.xkb_keysym_from_name.restype = ctypes.c_uint32
    # Sway 1.10.1 uses XKB_KEYSYM_CASE_INSENSITIVE for both binds and unbinds.
    symbol = xkb.xkb_keysym_from_name(parts[-1].encode('ascii'), 1)
    if not symbol:
        raise ValueError('invalid:to')
    return frozenset(mods), symbol


def values() -> dict:
    paths, included = _loaded()
    defaults = _sway_bindings(paths, detailed=True)
    path = _override()
    blocks = _blocks(path.read_text(encoding='utf-8') if path.exists() else '')
    bindings = []
    for binding in defaults:
        key = binding['keys']
        selected = blocks.get(key) if binding['editable'] else None
        bindings.append({'name': binding['name'], 'default_keys': key,
                         'keys': selected[0] if selected else key,
                         'command': binding['command'], 'flags': binding['flags'],
                         'overridden': bool(selected), 'editable': binding['editable'],
                         'type': binding['type'], 'mode': binding['mode']})
    return {'bindings': bindings, 'override_path': str(path), 'include_present': included}


def set_shortcut(source, target):
    current = values()
    rows = [row for row in current['bindings'] if row['default_keys'] == source and row['editable']]
    if len(rows) != 1:
        raise ValueError('unknown:from')
    row = rows[0]
    override = _override()
    saved_blocks = _blocks(override.read_text(encoding='utf-8') if override.exists() else '')
    for default_key in saved_blocks:
        matches = [item for item in current['bindings']
                   if item['editable'] and item['default_keys'] == default_key]
        if len(matches) != 1:
            raise ValueError('shortcuts-orphaned-override')
    # Keycodes and --to-code can address the same physical key as a keysym.
    # Without an authoritative keymap we cannot certify that the target is free.
    if any(item['mode'] is None and
           (item['type'] == 'bindcode' or any(_tokens(flag)[0] == ['--to-code'] for flag in item['flags']))
           for item in current['bindings']):
        raise ValueError('shortcuts-keycode-conflict-unknown')
    if target is not None:
        wanted = _key_id(target)
        for other in current['bindings']:
            if not other['editable'] or other is row:
                continue
            # Mouse-button bindings cannot collide with an accepted keysym.
            if re.search(r'(?:^|\+)button[0-9]+$', other['keys']):
                continue
            try:
                occupied = _key_id(other['keys'])
            except ValueError:
                raise ValueError('shortcuts-effective-key-unrecognized')
            if occupied == wanted:
                raise ValueError('shortcuts-key-taken:' + (other['name'] or other['default_keys']))
    else:
        # Reset also refuses to steal a key another override now occupies.
        wanted = _key_id(source)
        for other in current['bindings']:
            if other is row or not other['editable']:
                continue
            if re.search(r'(?:^|\+)button[0-9]+$', other['keys']):
                continue
            try:
                occupied = _key_id(other['keys'])
            except ValueError:
                raise ValueError('shortcuts-effective-key-unrecognized')
            if occupied == wanted:
                raise ValueError('shortcuts-key-taken:' + (other['name'] or other['default_keys']))
    if not current['include_present']:
        raise ValueError('shortcuts-override-include-absent')
    path = _override()
    original = path.read_text(encoding='utf-8') if path.exists() else ''
    blocks = _blocks(original)
    # Sway applies blocks in order. If A moves onto B's old key, B must be
    # unbound before A is bound; appending an updated block can break that.
    remaining = original
    for _, chunk in blocks.values():
        remaining = remaining.replace(chunk, '', 1)
    if any(_tokens(line)[0] for line in _logical_lines(remaining)):
        raise ValueError('shortcuts-override-unmanaged')
    planned = dict(blocks)
    planned.pop(source, None)
    if target is not None and target != source:
        flags = (' '.join(row['flags']) + ' ') if row['flags'] else ''
        label = row['name'].replace('\n', ' ').replace('\r', ' ')
        chunk = (f'# settings-shortcut-{source}-begin\n'
                 f'unbindsym {flags}{source}\n# name: {label}\n'
                 f'bindsym {flags}{target} {row["command"]}\n'
                 f'# settings-shortcut-{source}-end\n')
        planned[source] = (target, chunk)
    ordered = []
    visiting = set()
    done = set()
    source_ids = {_key_id(key): key for key in planned}
    def place(key):
        if key in done:
            return
        if key in visiting:
            raise ValueError('shortcuts-override-cycle')
        visiting.add(key)
        dependency = source_ids.get(_key_id(planned[key][0]))
        if dependency is not None and dependency != key:
            place(dependency)
        visiting.remove(key)
        done.add(key)
        ordered.append(planned[key][1])
    for key in planned:
        place(key)
    if remaining and ordered and not remaining.endswith('\n'):
        remaining += '\n'
    payload = (remaining + ''.join(ordered)).encode()
    if (path.exists() and path.read_bytes() == payload) or (not path.exists() and not payload):
        return {'ok': True, 'changed': False, 'mutationPerformed': False}
    if not backends.select_backend() and os.environ.get('CADUCEUS_SETTINGS_DRY_RUN') != '1':
        raise ValueError('sway-session-unavailable')
    receipt = _shared.Receipt('shortcuts', ['from', 'to'])
    attempted = False
    try:
        receipt.replace(path, payload)
        if os.geteuid() == 0 and _shared.home() == _shared.OWNER_HOME:
            owner = pwd.getpwnam(_shared.OWNER_USER)
            os.chown(path, owner.pw_uid, owner.pw_gid)
        if os.environ.get('CADUCEUS_SETTINGS_DRY_RUN') == '1':
            receipt.commands.append({'argv': ['swaymsg', 'reload'], 'dryRun': True})
        else:
            attempted = True
            _parity._sway_reload(receipt)
        result = receipt.finish(True, receipt.changed)
        result['mutationPerformed'] = receipt.changed
        return result
    except Exception as error:
        mutated = receipt.changed
        signal = str(error)
        try:
            receipt.restore_backups()
            if attempted:
                _parity._sway_reload(receipt)
            uncertain = False
        except Exception as rollback_error:
            signal = 'rollback-failed:' + str(rollback_error) + ':' + signal
            uncertain = mutated
        failure = receipt.finish(False, error=signal)
        raise _shared.ReceiptFailure(signal, failure['receipt'], uncertain) from error


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    request = None
    try:
        if not args:
            request = read(known_fields=('from', 'to', 'args'))
            if isinstance(request.payload.get('args'), list):
                args = request.payload['args']
            elif request.verb in {'read', 'get', 'state'} or (request.verb in {'shortcuts', 'settings'} and not request.payload):
                args = ['get', '--json']
            else:
                if 'from' not in request.payload or 'to' not in request.payload:
                    raise ValueError('invalid:request')
                result = set_shortcut(request.payload['from'], request.payload['to'])
                print(json.dumps(attach(result, request), sort_keys=True))
                return 0
        if args == ['get', '--json']:
            result = {'ok': True, 'values': values(), 'mutationPerformed': False}
        elif args and args[0] == 'set':
            changes = {}
            i = 1
            while i < len(args):
                if i + 3 >= len(args) or args[i] != '--field' or args[i+2] != '--value-json':
                    raise ValueError('cli-parse-failure')
                changes[args[i+1]] = json.loads(args[i+3])
                i += 4
            if set(changes) != {'from', 'to'}:
                raise ValueError('invalid:request')
            result = set_shortcut(changes['from'], changes['to'])
        else:
            raise ValueError('cli-parse-failure')
        print(json.dumps(attach(result, request) if request else result, sort_keys=True))
        return 0
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = error.reply() if isinstance(error, _shared.ReceiptFailure) else {'ok': False, 'changed': False, 'mutationPerformed': False, 'firstMissingSignal': str(error)}
        print(json.dumps(attach(result, request) if request else result, sort_keys=True))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

"""Serve warm forked staff crossings or install their unit."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from agathodaimon.lib.crossing_daemon.index import CrossingDaemon

UNIT_NAME = "agathodaimon-crossing-daemon.service"
UNIT = """[Unit]
Description=Agathodaimon warm crossing daemon

[Service]
Type=simple
ExecStart=/usr/local/sbin/agathodaimon/cli.py python/crossing-daemon
StandardInput=data
StandardInputText={"payload":{}}
Restart=always

[Install]
WantedBy=multi-user.target
"""


def unit_change(directory: Path, remove: bool, plan: bool) -> dict:
    target = directory / UNIT_NAME
    # Installing the declaration never starts or enables the service; that
    # separate live-body decision belongs to the operator.
    commands = [['systemctl', 'daemon-reload']]
    result = {'ok': True, 'operation': 'remove' if remove else 'install',
              'unit': str(target), 'planned': plan, 'commands': commands}
    if plan:
        return result
    directory.mkdir(parents=True, exist_ok=True)
    if remove:
        target.unlink(missing_ok=True)
    else:
        with tempfile.NamedTemporaryFile('w', encoding='utf-8', dir=directory, delete=False) as out:
            temporary = out.name
            out.write(UNIT)
            out.flush()
            os.fsync(out.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    for command in commands:
        step = subprocess.run(command, capture_output=True, text=True, check=False)
        if step.returncode:
            return {**result, 'ok': False, 'error': 'unit-command-failed', 'command': command}
    return result


def main(argv=None) -> int:
    if os.environ.get('SUDO_USER') == 'caduceus':
        print(json.dumps({'ok': False, 'error': 'owner-only-management'}, separators=(',', ':')))
        return 1
    parser = argparse.ArgumentParser(prog='agathodaimon-crossing-daemon')
    parser.add_argument('--socket', default='/run/caduceus/agathodaimon-crossing.sock')
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument('--install', action='store_true')
    choice.add_argument('--remove', action='store_true')
    parser.add_argument('--plan', action='store_true')
    parser.add_argument('--unit-dir', type=Path, default=Path('/etc/systemd/system'))
    args = parser.parse_args(argv)
    if args.install or args.remove:
        if os.geteuid() == 0 and args.unit_dir.resolve() != Path('/etc/systemd/system').resolve():
            print(json.dumps({'ok': False, 'error': 'unit-directory-refused'}, separators=(',', ':')))
            return 1
        directory = Path('/etc/systemd/system') if os.geteuid() == 0 else args.unit_dir
        result = unit_change(directory, args.remove, args.plan)
        print(json.dumps(result, separators=(',', ':')))
        return 0 if result['ok'] else 1
    if os.geteuid() != 0 and args.socket == '/run/caduceus/agathodaimon-crossing.sock':
        print('crossing daemon requires root for the production socket', file=sys.stderr)
        return 1
    try:
        CrossingDaemon(args.socket).serve_forever()
    except (OSError, KeyError, ValueError) as error:
        print(f'crossing-daemon-start-failed: {error}', file=sys.stderr)
        return 1
    return 0

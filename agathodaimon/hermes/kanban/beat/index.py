"""Envelope door for the Hermes Kanban management beat."""
from __future__ import annotations

import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

from agathodaimon import _envelope
from agathodaimon.lib.receipts.index import emit
from agathodaimon.hermes.kanban import runner


def main(arguments=None):
    try:
        request = _envelope.read(known_fields=('board', 'cause', 'dry_run'))
        user = os.environ.get('CADUCEUS_HERMES_USER', 'hermes')
        if pwd.getpwuid(os.geteuid()).pw_name == user:
            receipt = runner.run(request.payload)
        else:
            env_names = ('CADUCEUS_HERMES_USER', 'CADUCEUS_HERMES_HOME', 'CADUCEUS_HERMES_CLI')
            assignments = [f'{key}={os.environ[key]}' for key in env_names if key in os.environ]
            cmd = ['sudo', '-n', '-u', user, 'env', *assignments, sys.executable, '-B', str(Path(runner.__file__).resolve())]
            proc = subprocess.run(cmd, input=json.dumps(request.payload), text=True, capture_output=True)
            receipt = json.loads(proc.stdout)
        return emit(_envelope.attach(receipt, request))
    except (OSError, KeyError, ValueError, _envelope.EnvelopeError, subprocess.SubprocessError):
        return emit({'ok': False, 'boards': [], 'beats': 0, 'event_through': None,
                     'mutationPerformed': False, 'firstMissingSignal': 'hermes-kanban-beat-failed'})

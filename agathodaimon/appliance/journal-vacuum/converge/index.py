"""Run the declared journal vacuum once."""
import importlib
import json
import os
import subprocess

from agathodaimon import _envelope

_band = importlib.import_module('agathodaimon.appliance.journal-vacuum.index')


def main(argv=None):
    del argv
    try:
        request = _envelope.read(max_input_bytes=4 * _band._MAX_REQUEST)
        payload = request.value.get('payload') if request.envelope else request.value
        if len(request.raw_envelope) > _band._MAX_REQUEST or not isinstance(payload, dict) or payload:
            raise ValueError
    except ValueError:
        print(json.dumps(_band._receipt(False, 'journal-vacuum-payload-invalid')))
        return 1
    try:
        executable = '/usr/bin/journalctl'
        scratch = os.environ.get('AGATHODAIMON_SCRATCH_ROOT')
        if scratch and os.environ.get('AGATHODAIMON_JOURNALCTL'):
            root = os.path.realpath(scratch)
            candidate = os.path.realpath(os.environ['AGATHODAIMON_JOURNALCTL'])
            if root == '/' or os.path.commonpath([root, candidate]) != root or candidate == root:
                raise OSError('journalctl stand-in outside scratch root')
            executable = candidate
        command = [executable, '--vacuum-size=300M']
        code, freed = _band._run_vacuum(command)
    except (OSError, subprocess.SubprocessError):
        print(json.dumps(_band._receipt(False, 'journal-vacuum-command-failed')))
        return 1
    ok = code == 0
    print(json.dumps(_band._receipt(ok, 'none' if ok else 'journal-vacuum-command-failed', freed)))
    return 0 if ok else 1

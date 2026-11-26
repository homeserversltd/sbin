"""Read the journal's disk usage without changing it."""
import importlib
import json
import os
import re
import subprocess
from decimal import Decimal, InvalidOperation

from agathodaimon import _envelope

_band = importlib.import_module('agathodaimon.appliance.journal-vacuum.index')
_USAGE = re.compile(r'take up\s+([0-9]+(?:\.[0-9]+)?)\s*([KMGTPE]?i?B?)\b', re.IGNORECASE)
_LIMIT = 300 * 1024**2


def main(argv=None):
    del argv
    try:
        request = _envelope.read(max_input_bytes=4 * _band._MAX_REQUEST)
        payload = request.value.get('payload') if request.envelope else request.value
        if len(request.raw_envelope) > _band._MAX_REQUEST or not isinstance(payload, dict) or payload:
            raise ValueError
    except ValueError:
        print(json.dumps({'ok': False, 'outcome': 'over', 'usageBytes': None, 'firstMissingSignal': 'journal-vacuum-payload-invalid'}))
        return 1

    usage = None

    def consume(line):
        nonlocal usage
        match = _USAGE.search(line)
        if match:
            try:
                factor = _band._SIZE_FACTORS.get(match.group(2).upper())
                if factor is not None:
                    usage = int(Decimal(match.group(1)) * factor)
            except (InvalidOperation, ValueError, OverflowError):
                pass

    try:
        executable = '/usr/bin/journalctl'
        scratch = os.environ.get('AGATHODAIMON_SCRATCH_ROOT')
        if scratch and os.environ.get('AGATHODAIMON_JOURNALCTL'):
            root = os.path.realpath(scratch)
            candidate = os.path.realpath(os.environ['AGATHODAIMON_JOURNALCTL'])
            if root == '/' or os.path.commonpath([root, candidate]) != root or candidate == root:
                raise OSError('journalctl stand-in outside scratch root')
            executable = candidate
        command = [executable, '--disk-usage']
        code = _band._run_bounded(command, consume)
        if code != 0:
            usage = None
    except (OSError, subprocess.SubprocessError):
        usage = None
    current = usage is not None and usage <= _LIMIT
    signal = 'journal-vacuum-usage-unread' if usage is None else 'none'
    print(json.dumps({'ok': current, 'outcome': 'current' if current else 'over', 'usageBytes': usage, 'firstMissingSignal': signal}))
    return 0 if current else 1

"""DNS blocklist list stop."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dns._blocklist import execute


def main(argv=None):
    try:
        request = _envelope.read_fields()
        result = execute('list')
        result = _envelope.attach(result, request)
    except _envelope.EnvelopeError as exc:
        result = {'ok': False, 'mutationPerformed': False, 'firstMissingSignal': str(exc)}
    print(json.dumps(result, separators=(',', ':')))
    return 0 if result['ok'] else 1

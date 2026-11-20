"""HDMI held-link stop."""
import json
from agathodaimon import _envelope
from agathodaimon._nidus.refusal import named_signal
from agathodaimon.settings.display import _hdmi_hold as manager

def main(argv=None):
    try:
        request = _envelope.read_fields("connector", "dry-run")
        result = manager.execute("hold", request.payload)
        result = _envelope.attach(result, request)
    except (_envelope.EnvelopeError, ValueError, OSError) as error:
        signal = named_signal(error, "hdmi-hold-hold")
        result = {"ok": False, "firstMissingSignal": signal, "mutationPerformed": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

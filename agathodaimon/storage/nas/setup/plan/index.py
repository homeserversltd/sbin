"""Observe the preflight plan for a NAS setup device and role."""
import json
from agathodaimon import _envelope
from agathodaimon.storage.nas.setup import _setup



def main(argv=None):
    try:
        envelope = _envelope.read_fields("device", "role")
        request = _setup._request(envelope)
    except (_envelope.EnvelopeError, _setup.Refusal) as error:
        failure = _setup._envelope_refusal(error) if isinstance(error, _envelope.EnvelopeError) else error
        receipt = {"ok": False, "firstMissingSignal": failure.signal_name,
                   "role": None, "device": None, "partition": None, "partlabel": None,
                   "mapper": None, "mountpoint": None,
                   "steps": [{"step": failure.step, "ok": False, "readback": {"rc": failure.return_code}}],
                   "servicesStarted": [], "servicesNotRunning": [], "rolledBack": False, "rollbackSteps": []}
        if 'envelope' in locals():
            receipt = _envelope.attach(receipt, envelope)
    else:
        receipt = _envelope.attach(_setup.plan(request), envelope)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

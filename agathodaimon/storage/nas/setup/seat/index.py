"""Seat a newly formatted NAS role under its attachment guard."""
import json
import re
import time
from agathodaimon import _envelope
from agathodaimon.storage.nas import deed
from agathodaimon.storage.nas.setup import _setup



def main(argv=None):
    started = time.monotonic()
    missing_identity = False
    try:
        envelope = _envelope.read_fields("device", "role", "createdPartitionIdentity")
        request = _setup._request(envelope)
        identity = envelope.payload.get("createdPartitionIdentity")
        if not isinstance(identity, str) or not re.fullmatch(r"[0-9]+:[0-9]+", identity):
            missing_identity = True
            raise _setup.Refusal("agathodaimon-nas-request-invalid", "request")
        request["createdPartitionIdentity"] = identity
    except (_envelope.EnvelopeError, _setup.Refusal) as error:
        failure = _setup._envelope_refusal(error) if isinstance(error, _envelope.EnvelopeError) else error
        receipt = {"ok": False, "firstMissingSignal": failure.signal_name,
                   "role": None, "device": None, "partition": None, "partlabel": None,
                   "mapper": None, "mountpoint": None, "createdPartitionIdentity": None,
                   "steps": [{"step": failure.step, "ok": False, "readback": {"rc": failure.return_code}}],
                   "servicesStarted": [], "servicesNotRunning": [], "rolledBack": False, "rollbackSteps": [],
                   "mutationAttempted": False}
        if missing_identity:
            receipt["firstMissingField"] = "createdPartitionIdentity"
        if 'envelope' in locals():
            receipt = _envelope.attach(receipt, envelope)
    else:
        receipt = _setup.seat(request)
        deed.finish("nas-setup", "nas-" + request["role"], receipt, started, request=envelope.intent_id)
        receipt = _envelope.attach(receipt, envelope)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

"""Stop the native unit only when nativeActiveBefore identifies it as inactive."""
from agathodaimon.transmission import runtime as rt

SCHEMA = "caduceus.transmission.vpn.rollback-stop.v1"


def main(argv=None):
    del argv
    request = None
    mutation_attempted = False
    try:
        request = rt.read_request(known_fields=("nativeActiveBefore", "nativeStartAttempted"))
        before = request.payload.get("nativeActiveBefore")
        attempted = request.payload.get("nativeStartAttempted", True)
        result = rt.receipt(SCHEMA)
        result.update(nativeUnit=rt.NATIVE_UNIT, nativeActiveBefore=before, mutationPerformed=False)
        if attempted is not True:
            result.update(ok=True, firstMissingSignal="none", reason="native-start-not-attempted")
        elif before is True or before in ("active", "reloading", "activating", "deactivating"):
            result.update(ok=True, firstMissingSignal="none", reason="native-unit-already-active-or-transitioning")
        elif before is False or before in ("inactive", "failed"):
            mutation_attempted = True
            stopped = rt.run([rt.SYSTEMCTL, "stop", rt.NATIVE_UNIT], timeout=180, step="rollback-native-stop")
            result["mutationPerformed"] = True
            state = rt.unit_state(rt.NATIVE_UNIT, step="rollback-readback")
            result["nativeState"] = state
            if stopped.returncode != 0 or state != "inactive":
                raise rt.TransmissionError("transmission-rollback-stop-failed", "rollback-stop", {"nativeState": state, "mutationPerformed": True})
            result.update(ok=True, firstMissingSignal="none")
        else:
            raise rt.TransmissionError("transmission-native-before-unavailable", "rollback-stop")
    except Exception as failure:
        result = rt.failure_receipt(SCHEMA, failure)
        if mutation_attempted:
            result["mutationPerformed"] = True
            result["mutationOutcome"] = "unknown"
    return rt.print_receipt(rt.finish(result, request))

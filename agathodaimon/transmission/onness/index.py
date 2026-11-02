"""Read Transmission onness until on or deadline_seconds expires."""
import time
from agathodaimon.transmission import runtime as rt

SCHEMA = "caduceus.transmission.onness.v1"


def main(argv=None):
    del argv
    request = None
    try:
        request = rt.read_request(known_fields=("provider", "deadline_seconds"), declared_flags=("vpn",))
        seconds = request.payload.get("deadline_seconds", 180)
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 < seconds <= 180:
            raise rt.TransmissionError("transmission-onness-deadline-invalid", "onness")
        options, providers = rt.resolve_vpn(request)
        provider = options["provider"]
        result = rt.receipt(SCHEMA, provider)
        deadline = time.monotonic() + seconds
        while True:
            latest = rt.status_read(provider, providers)
            result["onness"] = {key: latest.get(key) for key in ("on", "conditions", "forwardPort", "peerPort", "rpcPort", "firstMissingSignal")}
            if latest.get("ok") is True and latest.get("on") is True:
                result.update(ok=True, firstMissingSignal="none", mutationPerformed=False)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result.update(ok=False, firstMissingSignal="transmission-onness-not-confirmed", failedStep="onness", mutationPerformed=False)
                break
            time.sleep(min(1, remaining))
    except Exception as failure:
        result = rt.failure_receipt(SCHEMA, failure)
    result = rt.finish(result, request)
    if rt._journal_stdout():
        return 0 if result.get("ok") is True else 1
    return rt.print_receipt(result)

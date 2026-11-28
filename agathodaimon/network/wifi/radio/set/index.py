"""One NetworkManager Wi-Fi operation."""
import json
from agathodaimon import _envelope
from agathodaimon.network.wifi import _nmcli

def main(argv=None, *, enabled=None):
    try:
        request = _envelope.read_fields('enabled', 'device')
    except _envelope.EnvelopeError:
        receipt = _nmcli._receipt("invalid", False, "wifi-input-invalid")
    else:
        receipt = _nmcli._dispatch({"kind": 'radio', **request.payload, **({"enabled": enabled} if enabled is not None else {})})
        if receipt.get("firstMissingSignal") != "wifi-device-invalid":
            receipt = _envelope.attach(receipt, _nmcli.redacted_request(request))
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

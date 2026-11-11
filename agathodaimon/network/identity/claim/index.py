"""Claim a DHCP reservation and DNS device name as one transaction."""
import json

from agathodaimon import _envelope
from agathodaimon.network.dhcp._manager import DhcpError
from agathodaimon.network.dns._manager import DnsError
from agathodaimon.network.identity._claim import IdentityClaimCoordinator, IdentityError


def main(argv=None):
    request = None
    try:
        request = _envelope.read_fields("mac", "hostname", "ip", "auto-ip")
        payload = request.payload
        if not isinstance(payload.get("mac"), str) or not isinstance(payload.get("hostname"), str):
            receipt = {"state": "blocked", "first_failing_boundary": "claim-mac-and-hostname-required", "mutationPerformed": False}
        elif not isinstance(payload.get("auto-ip", False), bool):
            receipt = {"state": "blocked", "first_failing_boundary": "claim-auto-ip-must-be-boolean", "mutationPerformed": False}
        else:
            receipt = IdentityClaimCoordinator().claim(payload["mac"], payload["hostname"], ip=payload.get("ip"), auto_ip=payload.get("auto-ip", False))
        receipt["ok"] = receipt.get("state") in ("applied", "noop")
    except (DhcpError, DnsError, IdentityError, _envelope.EnvelopeError) as exc:
        receipt = {"ok": False, "state": "blocked", "mutationPerformed": False, "first_failing_boundary": str(exc)}
    boundary = receipt.get("first_failing_boundary", "")
    if receipt["ok"]:
        receipt["firstMissingSignal"] = "none"
    elif boundary.startswith("invalid MAC address:"):
        receipt["firstMissingSignal"] = "claim-mac-invalid"
    elif boundary in {"invalid JSON", "JSON object required", "foreign envelope schema"} or boundary.startswith("missing envelope kernel keys:"):
        receipt["firstMissingSignal"] = "claim-envelope-invalid"
    else:
        receipt["firstMissingSignal"] = "claim-failed"
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

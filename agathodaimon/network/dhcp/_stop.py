"""Envelope and receipt handling for fixed DHCP stops."""
import json
from agathodaimon import _envelope
from agathodaimon.network.dhcp._manager import DhcpError, DhcpManager


def run(request, schema, act, fields=(), boundary=False):
    try:
        values = [request.payload.get(name) for name in fields]
        for name, value in zip(fields, values):
            if name in ("ip_address", "hostname") and value is None:
                continue
            if name == "max_reservations":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise DhcpError("max_reservations must be an integer")
            elif not isinstance(value, str):
                raise DhcpError(f"{name} must be a string")
        manager = DhcpManager()
        result = act(manager, *values)
        receipt = {"schema": schema, "ok": True, "result": result, "firstMissingSignal": "none"}
        if boundary:
            receipt["active_leases_count"] = len(manager.get_leases())
    except DhcpError as exc:
        receipt = {"schema": schema, "ok": False, "mutationPerformed": False, "firstMissingSignal": str(exc)}
    receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1


def invalid(schema):
    print(json.dumps({"schema": schema, "ok": False, "mutationPerformed": False, "firstMissingSignal": "invalid-envelope"}, separators=(",", ":")))
    return 1

"""Envelope and receipt handling for fixed DHCP stops."""
import json
from agathodaimon import _envelope
from agathodaimon._nidus.lock import IDENTITY_LOCK, IdentityLockUnavailable
from agathodaimon.network.dhcp._manager import DhcpError, DhcpManager


ADD_FIELDS = ("hw_address", "ip_address", "hostname")
RENAME_FIELDS = ("identifier", "hostname")


def run(request, act, fields=(), boundary=False):
    manager = None
    try:
        values = [request.payload.get(name) for name in fields]
        for name, value in zip(fields, values):
            if fields == ADD_FIELDS and name in ("ip_address", "hostname") and value is None:
                continue
            if name == "max_reservations":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise DhcpError("max_reservations must be an integer")
            elif not isinstance(value, str):
                raise DhcpError(f"{name} must be a string")
        manager = DhcpManager()
        result = act(manager, *values)
        receipt = {"ok": True, "result": result, "firstMissingSignal": "none"}
        if fields in (ADD_FIELDS, ("identifier",), RENAME_FIELDS):
            receipt["changed"] = manager.changed
        if fields == RENAME_FIELDS:
            receipt["mutationPerformed"] = manager.mutation_performed
        if boundary:
            receipt["active_leases_count"] = len(manager.get_leases())
    except IdentityLockUnavailable:
        receipt = {
            "ok": False,
            "mutationPerformed": manager.mutation_performed if manager else False,
            "firstMissingSignal": f"identity-lock-unavailable:{IDENTITY_LOCK}",
        }
    except DhcpError as exc:
        receipt = {"ok": False, "mutationPerformed": manager.mutation_performed if manager else False, "firstMissingSignal": str(exc)}
    receipt = _envelope.attach(receipt, request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1


def invalid():
    print(json.dumps({"ok": False, "mutationPerformed": False, "firstMissingSignal": "invalid-envelope"}, separators=(",", ":")))
    return 1

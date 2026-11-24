"""One dispatcher for notification actions, owned by the staff."""
import json

from agathodaimon import _envelope


def _pending():
    return {"ok": True, "state_after": "pending"}


def _caduceus_accept():
    return {"ok": False, "firstMissingSignal": "notify-act-accept-is-caduceus-own"}


KINDS = {"update": {"open-updates": _pending}, "house-link-up": {"accept": _caduceus_accept}}


def main(argv=None):
    try:
        request = _envelope.read_fields("id", "verb", "row").payload
    except ValueError:
        request = {}
    row = request.get("row") if isinstance(request.get("row"), dict) else {}
    kind, verb = row.get("kind"), request.get("verb")
    receipt = {"id": request.get("id"), "verb": verb, "kind": kind}
    if verb == "dismiss":
        result = {"ok": True, "state_after": "dismissed"}
    else:
        actions = KINDS.get(kind, {}) if isinstance(kind, str) else {}
        action = actions.get(verb) if isinstance(verb, str) else None
        result = action() if action else {"ok": False, "firstMissingSignal": "notify-act-unknown"}
    receipt.update(result)
    print(json.dumps(receipt))
    return 0 if receipt["ok"] else 1

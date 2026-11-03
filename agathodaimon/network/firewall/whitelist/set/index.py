"""Firewall whitelist-set stop."""
import json
from agathodaimon import _envelope
from agathodaimon.network.firewall import _core


def main(argv=None):
    try:
        request = _envelope.read_fields('mac', 'hostnames', 'revision')
    except _envelope.EnvelopeError as exc:
        value = _core._receipt("invalid", False, False, "Firewall envelope refused.", None, str(exc))
    else:
        if len(request.raw_envelope.encode("utf-8")) > _core.MAX_INPUT_BYTES:
            value = _core._receipt("invalid", False, False, "Firewall input refused.", None, "firewall-input-too-large")
        else:
            value = _core.dispatch({"action": 'whitelist-set', **request.payload})
        value = _envelope.attach(value, request)
    value["schema"] = 'caduceus.network.firewall.whitelist.set.v1'
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))
    return 0 if value.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

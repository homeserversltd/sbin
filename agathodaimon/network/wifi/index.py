"""NetworkManager Wi-Fi staff actuator."""
from __future__ import annotations

import json
import sys
from typing import Sequence

from agathodaimon.network.wifi._nmcli import _dispatch, _receipt

def main(argv: Sequence[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        value = _receipt("invalid", False, "wifi-arguments-invalid")
    else:
        try:
            raw = sys.stdin.read()
            request = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            value = _receipt("invalid", False, "wifi-input-invalid")
        else:
            if not isinstance(request, dict):
                value = _receipt("invalid", False, "wifi-body-not-object")
            else:
                payload = request.get("payload") if "schema" in request else request
                value = _dispatch(payload)
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

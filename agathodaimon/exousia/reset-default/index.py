#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.exousia._common import invoke_library

_SIGNAL = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")


def _valid_hex(value):
    return isinstance(value, str) and len(value) == 64 and all(
        char in "0123456789abcdefABCDEF" for char in value
    )


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        return 2
    try:
        request = read()
    except EnvelopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    try:
        value = invoke_library("reset-default-pin", {})
    except Exception:  # noqa: BLE001
        print("exousia reset refused", file=sys.stderr)
        return 1

    if not isinstance(value, dict):
        print("exousia reset returned invalid status", file=sys.stderr)
        return 1

    if value.get("ok") is False:
        signal = value.get("firstMissingSignal")
        if not isinstance(signal, str) or _SIGNAL.fullmatch(signal) is None:
            signal = "exousia-reset-refused"
        result = {"ok": False, "firstMissingSignal": signal}
    elif value.get("ok") is True:
        public_key, epoch = value.get("publicKey"), value.get("epoch")
        if not _valid_hex(public_key) or not _valid_hex(epoch):
            print("exousia reset returned invalid public state", file=sys.stderr)
            return 1
        result = {"ok": True, "publicKey": public_key, "epoch": epoch}
    else:
        print("exousia reset returned invalid status", file=sys.stderr)
        return 1

    print(json.dumps(attach(result, request), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

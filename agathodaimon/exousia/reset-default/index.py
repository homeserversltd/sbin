#!/usr/bin/env python3
import json
import sys


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        return 2
    try:
        value = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("invalid JSON", file=sys.stderr)
        return 2
    if not isinstance(value, dict) or set(value):
        print("unexpected exousia fields", file=sys.stderr)
        return 2
    print(json.dumps({"ok": False, "firstMissingSignal": "keyman-default-pin-authority-absent"}, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

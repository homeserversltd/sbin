#!/usr/bin/env python3
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parents[3]))
from agathodaimon._envelope import EnvelopeError, attach, read


def main(argv=None):
    if list(sys.argv[1:] if argv is None else argv):
        print("one exousia verb is required", file=sys.stderr)
        return 2
    try:
        request = read()
    except EnvelopeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(attach({"ok": False, "firstMissingSignal": "keyman-default-pin-authority-absent"}, request), separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

"""Keyman noun help and verb registration."""
from __future__ import annotations
import json

VERBS = ["newkey"]


def main(argv=None):
    args = list(argv or [])
    if args and args != ["--help"]:
        print(json.dumps({"ok": False,
                          "firstMissingSignal": "keyman-verb-unknown",
                          "mutationPerformed": False}, separators=(",", ":")))
        return 1
    print(json.dumps({"ok": True,
                      "firstMissingSignal": "none", "noun": "keyman", "verbs": VERBS,
                      "mutationPerformed": False}, separators=(",", ":")))
    return 0

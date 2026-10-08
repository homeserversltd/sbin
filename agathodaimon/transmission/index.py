"""Transmission staff sequence root."""
from __future__ import annotations
import json


def main(argv=None):
    del argv
    print(json.dumps({"schema": "agathodaimon.transmission.v1", "ok": True,
                      "verbs": ["up", "down", "status", "vpn"]}, separators=(",", ":")))
    return 0

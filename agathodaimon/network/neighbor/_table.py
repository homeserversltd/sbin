"""The common neighbor readback for the passive and active stops."""

import ipaddress
import json
from pathlib import Path
import re
from subprocess import TimeoutExpired
import sys
from time import monotonic

from agathodaimon import _envelope
from agathodaimon._nidus.run import run

_INTERFACE = "lan0"
_IP_TIMEOUT = 0.8
_ASK_TIMEOUT = 1.0
_PROBE_BUDGET = 2.8  # Reserve the rest of the 3 s for the CLI front door.
_QUIET = {"STALE", "DELAY", "PROBE"}
_MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")


def _failure(signal):
    return {"ok": False, "mutationPerformed": False, "firstMissingSignal": signal}


def read(timeout=_IP_TIMEOUT):
    # Without "nud all", ip omits NOARP rows. With "dev", ip may omit the dev key.
    if timeout <= 0:
        return _failure("agathodaimon-neighbor-ip-timeout")
    try:
        result = run(("ip", "-j", "-4", "neigh", "show", "dev", _INTERFACE, "nud", "all"), timeout=timeout)
    except TimeoutExpired:
        return _failure("agathodaimon-neighbor-ip-timeout")
    except (OSError, UnicodeError):
        return _failure("agathodaimon-neighbor-ip-failed")
    if result.returncode != 0:
        return _failure("agathodaimon-neighbor-ip-failed")

    try:
        entries = json.loads(result.stdout)
    except (ValueError, RecursionError):
        entries = None
    if not isinstance(entries, list):
        return _failure("agathodaimon-neighbor-ip-output-invalid")

    rows = []
    for entry in entries:
        if not isinstance(entry, dict):
            return _failure("agathodaimon-neighbor-ip-output-invalid")
        if entry.get("dev", _INTERFACE) != _INTERFACE:
            continue
        mac, dst = entry.get("lladdr"), entry.get("dst")
        if not isinstance(mac, str) or not _MAC.fullmatch(mac) or not isinstance(dst, str):
            continue
        try:
            ip = ipaddress.IPv4Address(dst)
        except ipaddress.AddressValueError:
            continue
        states = entry.get("state", [])
        if not isinstance(states, list) or (states and not isinstance(states[0], str)):
            return _failure("agathodaimon-neighbor-ip-output-invalid")
        rows.append((ip, mac.lower(), states[0] if states else None))
    return {
        "ok": True,
        "neighbors": [{"mac": mac, "ip": str(ip), "state": state}
                      for ip, mac, state in sorted(rows, key=lambda row: row[0])],
        "mutationPerformed": False,
        "firstMissingSignal": "none",
    }


def probe():
    deadline = monotonic() + _PROBE_BUDGET
    before = read()
    if not before["ok"]:
        return before
    targets = [f"{row['ip']},{row['mac']}" for row in before["neighbors"] if row["state"] in _QUIET]
    if not targets:
        return before
    helper = Path(__file__).with_name("_arp.py")
    # Save time for the final read; the whole send batch is bounded to one second.
    timeout = min(_ASK_TIMEOUT, deadline - monotonic() - _IP_TIMEOUT)
    if timeout > 0:
        try:
            run((sys.executable, "-I", "-B", str(helper), _INTERFACE, *targets), timeout=timeout)
        except (OSError, TimeoutExpired, UnicodeError):
            pass
    # A probe is best effort. Only this fresh kernel snapshot assigns a state.
    return read(min(_IP_TIMEOUT, deadline - monotonic()))


def answer(observe):
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        receipt = _failure("invalid-envelope")
    else:
        receipt = _envelope.attach(observe(), request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

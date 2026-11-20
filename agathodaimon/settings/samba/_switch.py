"""Switch the fixed Samba and Windows discovery units and confirm the result."""
from __future__ import annotations

import json
from typing import Any

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings.samba import _acts as samba

SWITCH_UNITS = (*samba.UNITS, ("wsdd2", "wsdd2.service"))


def _apply(enabled: bool) -> dict[str, Any]:
    command = "enable" if enabled else "disable"
    observed: dict[str, dict[str, str]] = {}
    signals = []
    for name, unit in SWITCH_UNITS:
        try:
            observed[unit] = {"loadState": samba._load_state(name, unit)}
        except samba.ObservationFailure as exc:
            observed[unit] = {"firstMissingSignal": exc.signal}
            signals.append(exc.signal)

    steps = []
    units_acted_on = []
    for name, unit in SWITCH_UNITS:
        if observed[unit].get("loadState") != "loaded":
            continue
        signal = "none"
        returncode = None
        try:
            result = samba._run(
                [samba.SYSTEMCTL, command, "--now", unit],
                f"agathodaimon-settings-samba-{name}-{command}-launch-failed",
            )
            returncode = result.returncode
            units_acted_on.append(unit)
            if returncode != 0:
                signal = f"agathodaimon-settings-samba-{name}-{command}-failed"
        except samba.ObservationFailure as exc:
            signal = exc.signal
        if signal != "none":
            signals.append(signal)
        steps.append({"unit": unit, "ok": signal == "none", "returncode": returncode,
                      "firstMissingSignal": signal})

    status = samba.status()
    readback = status["readback"]
    if not status["ok"]:
        signals.append(status["firstMissingSignal"])
    else:
        smbd = readback["services"]["smbd"]
        # The status booleans alone can read false for a transition or runtime enablement.
        expected = ("active", "enabled") if enabled else ("inactive", "disabled")
        if (smbd["activeState"], smbd["enabledState"]) != expected:
            signals.append("agathodaimon-settings-samba-smbd-readback-mismatch")

    return {
        "ok": not signals,
        "firstMissingSignal": signals[0] if signals else "none",
        "observed": {"loadStates": observed},
        "could_change_to": {"active": enabled, "enabled": enabled},
        "attempt": {"attempted": bool(steps), "command": command, "steps": steps},
        "unitsActedOn": units_acted_on,
        "readback": readback,
    }


def main(*, enabled: bool) -> int:
    try:
        request = read()
    except EnvelopeError:
        receipt = {"ok": False, "firstMissingSignal": "agathodaimon-settings-samba-envelope-read-failed"}
    else:
        receipt = attach(_apply(enabled), request)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1

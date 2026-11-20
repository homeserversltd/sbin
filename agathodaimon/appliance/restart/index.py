"""Schedule the restart of one currently listed name after two seconds."""
import json
import subprocess

from agathodaimon import _envelope
from agathodaimon._nidus.run import run
from agathodaimon.appliance._restartable import list_restartable


DELAY_SECONDS = 2


def _schedule(name):
    rows, _ = list_restartable()
    unit = next((row["unit"] for row in rows if row["name"] == name), None)
    if unit is None:
        return {"ok": False, "firstMissingSignal": "appliance-restart-not-listed"}
    try:
        scheduled = run([
            "systemd-run", "--no-block", f"--on-active={DELAY_SECONDS}",
            "/usr/bin/systemctl", "restart", unit,
        ])
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return {"ok": False, "firstMissingSignal": "appliance-restart-schedule-failed"}
    ok = scheduled.returncode == 0
    receipt = {
        "ok": ok,
        "firstMissingSignal": "none" if ok else "appliance-restart-schedule-failed",
        "output": (scheduled.stdout or scheduled.stderr).strip(),
    }
    if ok:
        receipt.update(unit=unit, delayedSeconds=DELAY_SECONDS)
    return receipt


def main(argv=None):
    try:
        request = _envelope.read_fields("name")
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "firstMissingSignal": "appliance-restart-request-invalid"}
    else:
        receipt = _envelope.attach(_schedule(request.payload.get("name")), request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

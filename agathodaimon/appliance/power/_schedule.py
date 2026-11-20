"""Schedule a fixed appliance power action without waiting for it to run."""
import json
import subprocess

from agathodaimon import _envelope
from agathodaimon._nidus.run import run


DELAY_SECONDS = 2
SCHEDULE_FAILED = "appliance-power-schedule-failed"


def _schedule(action: str) -> dict:
    try:
        scheduled = run([
            "/usr/bin/systemd-run", "--no-block", f"--on-active={DELAY_SECONDS}",
            "/usr/bin/systemctl", action,
        ])
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return {"ok": False, "firstMissingSignal": SCHEDULE_FAILED}
    if scheduled.returncode != 0:
        return {"ok": False, "firstMissingSignal": SCHEDULE_FAILED}
    return {"ok": True, "firstMissingSignal": "none", "action": action, "delayedSeconds": DELAY_SECONDS}


def main(action: str) -> int:
    try:
        request = _envelope.read_fields()
    except _envelope.EnvelopeError:
        receipt = {"ok": False, "firstMissingSignal": "appliance-power-request-invalid"}
    else:
        receipt = _envelope.attach(_schedule(action), request)
    print(json.dumps(receipt, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

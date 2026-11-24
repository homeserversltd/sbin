"""Receipt-bearing staff entry for the owner group actuator."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import re
import sys

from agathodaimon import _envelope


def main(argv=None):
    try:
        request = _envelope.read(known_fields=("action",), quiet_on_tty=True)
    except _envelope.EnvelopeError as error:
        cause = error.__cause__
        if isinstance(cause, OSError):
            raise cause
        if isinstance(cause, json.JSONDecodeError) and not cause.doc.strip():
            request = None
        else:
            print(json.dumps({"ok": False, "firstMissingSignal": str(error)}))
            return 1
    action = (request.payload.get("action") or request.verb) if request and not argv else None
    if action == "observe":
        action = "check"
    if action not in ("check", "apply"):
        receipt = {"ok": False, "firstMissingSignal": "owner-group-action-invalid"}
        print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
        return 1
    spec = importlib.util.spec_from_file_location("owner_group_actuator", Path(__file__).with_name("owner-group.py"))
    if spec is None or spec.loader is None:
        raise RuntimeError("owner-group-loader-unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output = io.StringIO()
    errors = io.StringIO()
    original_argv = sys.argv
    try:
        sys.argv = ["owner-group", action]
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = module.main()
    finally:
        sys.argv = original_argv
    observed = output.getvalue().strip() or None
    error_text = errors.getvalue()
    if error_text:
        sys.stderr.write(error_text)
    signal = re.search(r"(?:^| )signal=([^\s]+)", error_text)
    missing = (observed or (signal.group(1) if signal else "owner-group-failed")) if status else "none"
    receipt = {"ok": status == 0, "action": action, "observed": observed, "firstMissingSignal": missing}
    print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
    return status

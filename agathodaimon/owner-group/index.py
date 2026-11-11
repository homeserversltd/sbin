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
    args = list(argv or [])
    request = None
    raw = "" if sys.stdin.isatty() else sys.stdin.read()
    if raw.strip():
        original_stdin = sys.stdin
        try:
            sys.stdin = io.StringIO(raw)
            request = _envelope.read(known_fields=("action",))
        except _envelope.EnvelopeError as error:
            print(json.dumps({"ok": False, "firstMissingSignal": str(error)}))
            return 1
        finally:
            sys.stdin = original_stdin
    if args:
        action = args[0] if len(args) == 1 else None
    elif request:
        action = request.payload.get("action") or request.verb
    else:
        action = None
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

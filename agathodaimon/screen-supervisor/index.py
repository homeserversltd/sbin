"""Receipt-bearing staff entry for the long-running Sway supervisor."""
import contextlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
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
    if action != "run":
        receipt = {"ok": False, "firstMissingSignal": "screen-supervisor-action-invalid"}
        print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
        return 1
    path = str(Path(__file__).with_name("sway-seat-screen-supervisor"))
    loader = importlib.machinery.SourceFileLoader("screen_supervisor_actuator", path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("screen-supervisor-loader-unavailable")
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    try:
        with contextlib.redirect_stdout(sys.stderr):
            module.main()
    except (OSError, RuntimeError) as error:
        receipt = {"ok": False, "firstMissingSignal": str(error)}
        print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
        return 1
    except SystemExit as error:
        if error.code not in (None, 0):
            receipt = {"ok": False, "firstMissingSignal": str(error.code)}
            print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
            return 1
    receipt = {"ok": True, "firstMissingSignal": "none"}
    print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
    return 0

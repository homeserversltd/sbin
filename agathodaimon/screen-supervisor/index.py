"""Receipt-bearing staff entry for the long-running Sway supervisor."""
import contextlib
import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
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
            print(json.dumps({"schema": "caduceus.staff.screen-supervisor.v1", "ok": False, "firstMissingSignal": str(error)}))
            return 1
        finally:
            sys.stdin = original_stdin
    if args:
        action = args[0] if len(args) == 1 else None
    elif request:
        action = request.payload.get("action") or request.verb
    else:
        action = None
    if action != "run":
        receipt = {"schema": "caduceus.staff.screen-supervisor.v1", "ok": False, "firstMissingSignal": "screen-supervisor-action-invalid"}
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
        receipt = {"schema": "caduceus.staff.screen-supervisor.v1", "ok": False, "firstMissingSignal": str(error)}
        print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
        return 1
    except SystemExit as error:
        if error.code not in (None, 0):
            receipt = {"schema": "caduceus.staff.screen-supervisor.v1", "ok": False, "firstMissingSignal": str(error.code)}
            print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
            return 1
    receipt = {"schema": "caduceus.staff.screen-supervisor.v1", "ok": True, "firstMissingSignal": "none"}
    print(json.dumps(_envelope.attach(receipt, request) if request else receipt))
    return 0

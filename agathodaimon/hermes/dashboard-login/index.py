"""Set the Hermes dashboard password from stdin without returning it."""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import uuid

from agathodaimon import _envelope
from agathodaimon._envelope import appliance_runtime_path
from agathodaimon._nidus.run import run as nidus_run
from agathodaimon.lib.receipts.index import emit
from agathodaimon.unit import _control

UNIT = "hermes-dashboard.service"
WRITER = Path(__file__).with_name("writer.py")


class Refusal(Exception):
    pass


def _root():
    return appliance_runtime_path("config").parents[2]


def _password():
    try:
        request = _envelope.read(known_fields=("password",), secret_bytes=("password",),
                                 max_input_bytes=65536)
    except _envelope.EnvelopeError as error:
        if str(error) == "agathodaimon-envelope-input-too-large":
            signal = "hermes-request-too-large"
        elif str(error) == "agathodaimon-vault-open-request-invalid":
            signal = "hermes-password-invalid"
        else:
            signal = "hermes-input-invalid"
        raise Refusal(signal) from None
    return request.secret_bytes.get("password")


def _unit_identity():
    argv = ["systemctl", "--user", "-M", "hermes@.host", "show", UNIT,
            "--property=MainPID,ActiveEnterTimestamp"]
    try:
        result = nidus_run(argv, timeout=30)
    except (OSError, subprocess.SubprocessError):
        raise Refusal("hermes-unit-observation-failed") from None
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    pid = values.get("MainPID")
    entered = values.get("ActiveEnterTimestamp")
    if result.returncode != 0 or not pid or not pid.isdecimal() or int(pid) == 0 or not entered or entered == "n/a":
        raise Refusal("hermes-unit-observation-failed")
    return {"MainPID": pid, "ActiveEnterTimestamp": entered}


def _deed(receipt, started):
    from agathodaimon._deed import send
    send("sbin", "hermes-dashboard-login", receipt["ok"], target="hermes-dashboard",
         duration_ms=int((time.monotonic() - started) * 1000))


def main(arguments=None):
    started = time.monotonic()
    receipt = {"ok": False, "firstMissingSignal": "none",
               "mutationPerformed": False, "file": None, "restart": None, "restarted": False, "argv": []}
    password_bytes = None
    try:
        password_bytes = _password()
        if password_bytes is None:
            raise Refusal("hermes-password-invalid")
        password = password_bytes.decode("utf-8")
        if not 12 <= len(password) <= 256 or not password.isprintable() or any(c in password for c in "\0\r\n"):
            raise Refusal("hermes-password-invalid")
        root = _root()
        path = root / "home/hermes/.hermes/config.yaml"
        scratch = os.environ.get("AGATHODAIMON_SCRATCH_ROOT") is not None
        if scratch:
            argv = [sys.executable, "-B", str(WRITER), str(path)]
        else:
            argv = ["sudo", "-n", "-u", "hermes", "/opt/hermes/venv/bin/python", "-B", "-I", str(WRITER), str(path)]
        receipt["argv"].append(argv)
        if not scratch:
            receipt["before"] = _unit_identity()
        data = json.dumps({"password": password, "secret": secrets.token_hex(32)})
        password = None
        try:
            result = nidus_run(argv, input=data, discard_stdout=True, discard_stderr=True, timeout=30)
        finally:
            data = None
            _envelope.wipe_bytes(password_bytes)
            password_bytes = None
        if result.returncode != 0:
            raise Refusal("hermes-config-write-failed")
        receipt["file"] = str(path)
        receipt["mutationPerformed"] = True
        if scratch:
            receipt["restart"] = "skipped"
        else:
            result = _control.control("restart", UNIT, "hermes")
            receipt["restart"] = result
            if not result["ok"]:
                raise Refusal("hermes-unit-restart-failed")
            receipt["after"] = _unit_identity()
            if (receipt["before"]["MainPID"] == receipt["after"]["MainPID"] or
                receipt["before"]["ActiveEnterTimestamp"] == receipt["after"]["ActiveEnterTimestamp"]):
                raise Refusal("hermes-unit-identity-unchanged")
            # The door and the face read this boolean; the restart object stays for the record.
            receipt["restarted"] = True
        receipt["ok"] = True
    except Refusal as error:
        receipt["firstMissingSignal"] = str(error)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        receipt["firstMissingSignal"] = "hermes-operation-failed"
    finally:
        if password_bytes is not None:
            _envelope.wipe_bytes(password_bytes)
    try:
        _deed(receipt, started)
    except (OSError, ValueError):
        receipt.update(ok=False, firstMissingSignal="hermes-ledger-unavailable")
    receipt["final"] = {"ok": receipt["ok"], "signal": receipt["firstMissingSignal"],
                        "mutationPerformed": receipt["mutationPerformed"]}
    return emit(receipt)

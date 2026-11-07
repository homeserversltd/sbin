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

from agathodaimon._envelope import appliance_runtime_path
from agathodaimon.lib.receipts.index import emit
from agathodaimon.unit import _control

UNIT = "hermes-dashboard.service"
WRITER = Path(__file__).with_name("writer.py")


class Refusal(Exception):
    pass


def _root():
    return appliance_runtime_path("config").parents[2]


def _password(arguments):
    # The shared router can otherwise forward a slash-form JSON argv object.
    # Refuse it here without parsing, printing, or forwarding its contents.
    if arguments or (len(sys.argv) > 2 and sys.argv[1] == "hermes/dashboard-login"):
        raise Refusal("hermes-password-stdin-required")
    raw = sys.stdin.read(65537)
    if len(raw) > 65536:
        raise Refusal("hermes-request-too-large")
    if raw.lstrip().startswith("{"):
        try:
            obj = json.loads(raw)
        except ValueError:
            obj = None
        if obj is None:
            value = raw[:-1] if raw.endswith("\n") else raw
        elif isinstance(obj, dict):
            if isinstance(obj.get("payload"), dict):
                obj = obj["payload"]
            value = obj.get("password")
        else:
            raise Refusal("hermes-input-invalid")
    else:
        value = raw[:-1] if raw.endswith("\n") else raw
    if not isinstance(value, str) or not 12 <= len(value) <= 256 or not value.isprintable() or any(c in value for c in "\0\r\n"):
        raise Refusal("hermes-password-invalid")
    return value


def _unit_identity():
    argv = ["systemctl", "--user", "-M", "hermes@.host", "show", UNIT,
            "--property=MainPID,ActiveEnterTimestamp"]
    try:
        result = subprocess.run(argv, text=True, capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        raise Refusal("hermes-unit-observation-failed") from None
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    pid = values.get("MainPID")
    entered = values.get("ActiveEnterTimestamp")
    if result.returncode != 0 or not pid or not pid.isdecimal() or int(pid) == 0 or not entered or entered == "n/a":
        raise Refusal("hermes-unit-observation-failed")
    return {"MainPID": pid, "ActiveEnterTimestamp": entered}


def _deed(receipt, started):
    line = json.dumps({"who": "agathodaimon", "verb": "hermes-dashboard-login",
                       "target": "hermes-dashboard", "outcome": "ok" if receipt["ok"] else "failed",
                       "duration_ms": int((time.monotonic() - started) * 1000), "id": uuid.uuid4().hex,
                       "signal": receipt["firstMissingSignal"],
                       "first_missing_field": None if receipt["ok"] else "hermes/dashboard-login"},
                      separators=(",", ":")) + "\n"
    path = _root() / "var/log/appliance/appliance.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        encoded = line.encode("utf-8")
        if len(encoded) >= 1024 or os.write(fd, encoded) != len(encoded):
            raise OSError("ledger-write-failed")
    finally:
        os.close(fd)


def main(arguments=None):
    started = time.monotonic()
    receipt = {"schema": "caduceus.staff.v1", "ok": False, "firstMissingSignal": "none",
               "mutationPerformed": False, "file": None, "restart": None, "argv": []}
    try:
        password = _password(list(arguments or []))
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
            result = subprocess.run(argv, input=data, text=True, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=30, check=False)
        finally:
            data = None
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
        receipt["ok"] = True
    except Refusal as error:
        receipt["firstMissingSignal"] = str(error)
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError):
        receipt["firstMissingSignal"] = "hermes-operation-failed"
    try:
        _deed(receipt, started)
    except (OSError, ValueError):
        receipt.update(ok=False, firstMissingSignal="hermes-ledger-unavailable")
    receipt["final"] = {"ok": receipt["ok"], "signal": receipt["firstMissingSignal"],
                        "mutationPerformed": receipt["mutationPerformed"]}
    return emit(receipt)

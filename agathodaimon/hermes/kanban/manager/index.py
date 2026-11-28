"""Read the kanban manager and set Hermes's gateway dispatcher."""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import subprocess
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

from agathodaimon import _envelope
from agathodaimon._deed import send
from agathodaimon.lib.receipts.index import emit

KEY = "kanban.dispatch_in_gateway"
ROUTINE = "hermes-kanban-beat"


class Refusal(Exception):
    pass


def _run_cli(user, home, cli, *args):
    env = {"HOME": str(home.parent), "HERMES_HOME": str(home),
           "PATH": "/usr/local/bin:/usr/bin:/bin"}
    argv = [str(cli), *args]
    if pwd.getpwuid(os.geteuid()).pw_name != user:
        argv = ["sudo", "-n", "-u", user, "env", "-i",
                *(f"{key}={value}" for key, value in env.items()), *argv]
    try:
        return subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal("hermes-kanban-config-read-failed" if args[1] == "get"
                      else "hermes-kanban-config-write-failed") from error


def _dispatch(user, home, cli):
    result = _run_cli(user, home, cli, "config", "get", KEY, "--json")
    if result.returncode != 0:
        raise Refusal("hermes-kanban-config-read-failed")
    try:
        value = json.loads(result.stdout)
    except ValueError:
        raise Refusal("hermes-kanban-config-read-failed") from None
    if value is None:
        return True
    if type(value) is not bool:
        raise Refusal("hermes-kanban-config-read-failed")
    return value


def _routine():
    url = os.environ.get("CADUCEUS_URL", "http://127.0.0.1:3014").rstrip("/")
    try:
        with build_opener(ProxyHandler({})).open(url + "/api/v1/pid2/status/" + ROUTINE, timeout=10) as response:
            data = json.load(response)
        if not isinstance(data, dict) or data.get("ok") is not True or "registration" not in data:
            raise ValueError("invalid status")
        registration = data["registration"]
        if registration is None:
            return False
        if not isinstance(registration, dict) or type(registration.get("enabled")) is not bool:
            raise ValueError("invalid registration")
        return registration["enabled"]
    except (OSError, URLError, ValueError, TypeError):
        raise Refusal("hermes-kanban-routine-move-failed") from None


def _position(dispatch, routine):
    if routine and not dispatch:
        return "ours"
    if not routine and dispatch:
        return "theirs"
    if not routine and not dispatch:
        return "none"
    return "mixed"


def _observe(receipt, user, home, cli):
    dispatch = _dispatch(user, home, cli)
    routine = _routine()
    receipt.update(dispatch_in_gateway=dispatch, routine_enabled=routine,
                   position=_position(dispatch, routine))


def _restart(user):
    override = os.environ.get("CADUCEUS_HERMES_GATEWAY_RESTART")
    prefix = [override or "systemctl", "--user", "-M", f"{user}@.host"]
    unit = "hermes-gateway.service"

    def identity():
        result = subprocess.run([*prefix, "show", unit, "--property=ActiveState,InvocationID"],
                                capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
        if not values.get("ActiveState") or "InvocationID" not in values:
            return None
        return values

    try:
        before = identity()
        if before is None:
            return None
        result = subprocess.run([*prefix, "try-restart", unit], capture_output=True, timeout=30)
        if result.returncode != 0:
            return None
        after = identity()
        if after is None:
            return None
        if before["ActiveState"] != "active":
            return False
        return bool(before["InvocationID"] and after["InvocationID"] and
                    before["InvocationID"] != after["InvocationID"])
    except (OSError, subprocess.SubprocessError):
        return None


def main(arguments=None):
    started = time.monotonic()
    receipt = {"ok": False, "position": None, "before": None,
               "dispatch_in_gateway": None, "routine_enabled": None,
               "gateway_restarted": None, "mutationPerformed": False,
               "firstMissingSignal": "none"}
    request = None
    try:
        try:
            request = _envelope.read(known_fields=("position",), max_input_bytes=65536)
        except _envelope.EnvelopeError:
            raise Refusal("hermes-kanban-position-invalid") from None
        position = request.payload.get("position")
        if position is not None and (not isinstance(position, str) or position not in ("ours", "theirs", "none")):
            raise Refusal("hermes-kanban-position-invalid")
        user = os.environ.get("CADUCEUS_HERMES_USER", "hermes")
        home = Path(os.environ.get("CADUCEUS_HERMES_HOME", "/home/hermes/.hermes"))
        cli = Path(os.environ.get("CADUCEUS_HERMES_CLI", "/home/hermes/.local/bin/hermes"))
        if not home.is_dir() or not cli.is_file() or not os.access(cli, os.X_OK) or not ((home / "config.yaml").is_file() or (home / "kanban.db").is_file()):
            raise Refusal("hermes-kanban-hermes-absent")
        _observe(receipt, user, home, cli)
        if position is not None:
            receipt["before"] = receipt["position"]
            receipt["gateway_restarted"] = False
            desired = position == "theirs"
            if receipt["dispatch_in_gateway"] != desired:
                result = _run_cli(user, home, cli, "config", "set", KEY, str(desired).lower())
                if result.returncode != 0:
                    raise Refusal("hermes-kanban-config-write-failed")
                receipt["mutationPerformed"] = True
                restarted = _restart(user)
                if restarted is None:
                    raise Refusal("hermes-kanban-gateway-restart-failed")
                receipt["gateway_restarted"] = restarted
            _observe(receipt, user, home, cli)
        receipt["ok"] = True
    except Refusal as error:
        receipt["firstMissingSignal"] = str(error)
    except (OSError, KeyError, ValueError):
        receipt["firstMissingSignal"] = "hermes-kanban-config-read-failed"
    if receipt["mutationPerformed"]:
        send("sbin", "hermes-kanban-manager", receipt["ok"], target="hermes-gateway",
             duration_ms=int((time.monotonic() - started) * 1000),
             signal=receipt["firstMissingSignal"])
    if request is not None:
        receipt = _envelope.attach(receipt, request)
    return emit(receipt)

"""Run one memory-maintenance pass as the account that owns the store."""
from __future__ import annotations

import argparse
import io
import json
import os
import pwd
import subprocess
import sys
import time
from pathlib import Path

from agathodaimon import _envelope

HERE = Path(__file__).resolve().parent


def resolve_paths(settings, profile, home):
    python = home / settings.get("python_by_profile", {}).get(profile, settings["python"])
    return python, home / settings["config"]


def dispatch(request=None, *, dry_run=False, user_id=None):
    if request is not None:
        requested_dry = request.payload.get("dry_run", False)
        if not isinstance(requested_dry, bool):
            return {"ok": False, "firstMissingSignal": "nap-arguments-invalid"}
        dry_run = dry_run or requested_dry
        user_id = request.payload.get("user_id", user_id)
    started = time.monotonic()
    log_fd = None
    value = {"ok": False, "firstMissingSignal": "nap-account-pass-unavailable", "judged": 0, "folded": 0, "stale": 0, "gist": 0}
    try:
        settings = json.loads((HERE.parent.parent / "defconfigs" / "local-ai-nap" / "profiles.json").read_text(encoding="utf-8"))
        profile = json.loads(_envelope.appliance_runtime_path("profile").read_text(encoding="utf-8"))["profile"]
        account = settings["accounts"][profile]
        identity = pwd.getpwnam(account)
        home = Path(identity.pw_dir)
        python, config = resolve_paths(settings, profile, home)
        if not python.is_file() or not config.is_file():
            raise ValueError("account-runtime-unavailable")
        if not isinstance(dry_run, bool) or (user_id is not None and (not isinstance(user_id, str) or not user_id.strip())):
            raise ValueError("nap-arguments-invalid")
        gist_every = settings.get("gist_every", 0)
        if type(gist_every) is not int or gist_every < 0:
            raise ValueError("nap-arguments-invalid")
        command = [str(python), str(HERE / "pass.py"), str(config), str(settings["similarity_floor"]), user_id or "", "dry" if dry_run else "write", str(gist_every)]
        if os.geteuid() != identity.pw_uid:
            if os.geteuid() != 0:
                raise ValueError("account-switch-requires-root")
            command = ["/usr/sbin/runuser", "-u", account, "--", *command]
        log_fd = os.open("/var/log/appliance/appliance.log", os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
        env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "MEM0_TELEMETRY": "false", "NO_PROXY": "*", "no_proxy": "*", "PYTHONDONTWRITEBYTECODE": "1"}
        result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, check=False)
        reply = json.loads(result.stdout)
        if not isinstance(reply, dict) or result.returncode and reply.get("ok") is not False:
            raise ValueError("account-pass-failed")
        value = reply
    except (OSError, ValueError, KeyError, TypeError):
        pass
    if log_fd is not None:
        try:
            if not dry_run and (value.get("ok") is not True or any(value.get(k, 0) for k in ("judged", "folded", "stale", "gist"))):
                deed = {"who": "agathodaimon", "verb": "nap", "target": "memory", "outcome": "ok" if value.get("ok") else "failed", "duration_ms": int((time.monotonic() - started) * 1000), "signal": value.get("firstMissingSignal", "none")}
                line = (json.dumps(deed, separators=(",", ":")) + "\n").encode()
                if len(line) >= 1024 or os.write(log_fd, line) != len(line):
                    raise OSError("deed-write-failed")
        except OSError:
            value["ok"] = False
            value["firstMissingSignal"] = "nap-deed-log-unavailable"
        finally:
            os.close(log_fd)
    return _envelope.attach(value, request) if request is not None else value


def main(args=None):
    parser = argparse.ArgumentParser(prog="local-ai nap")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--user-id")
    options = parser.parse_args(args or [])
    request = None
    if not sys.stdin.isatty():
        raw = sys.stdin.read()
        if raw.strip():
            original = sys.stdin
            try:
                sys.stdin = io.StringIO(raw)
                request = _envelope.read(known_fields=("dry_run", "user_id"))
            except (ValueError, OSError):
                print(json.dumps({"ok": False, "firstMissingSignal": "nap-envelope-invalid"}))
                return 2
            finally:
                sys.stdin = original
    value = dispatch(request, dry_run=options.dry_run, user_id=options.user_id)
    print(json.dumps(value, separators=(",", ":")))
    return 0 if value.get("ok") else 1

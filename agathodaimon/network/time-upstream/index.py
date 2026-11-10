"""Choose the WAN time source and write chrony's runtime sources."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
from importlib import import_module

from agathodaimon._envelope import EnvelopeError, attach, read

household = import_module("agathodaimon.settings.datetime.household-time._household")
POOLS = "".join(f"pool {number}.debian.pool.ntp.org iburst\n" for number in range(4))


def _run(argv, timeout):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, timeout=timeout, check=False)


def _gateway():
    deadline = time.monotonic() + 90
    signal = "agathodaimon-time-upstream-gateway-missing"
    while (remaining := deadline - time.monotonic()) > 0:
        started = time.monotonic()
        try:
            result = _run(["ip", "-4", "route", "show", "default", "dev", "wan0"], min(2, remaining))
            if result.returncode:
                signal = "agathodaimon-time-upstream-wan-route-unavailable"
            else:
                signal = "agathodaimon-time-upstream-gateway-missing"
                for line in result.stdout.splitlines():
                    fields = line.split()
                    if "via" in fields:
                        index = fields.index("via")
                        if index + 1 < len(fields):
                            return str(ipaddress.IPv4Address(fields[index + 1])), "none"
        except (OSError, ValueError, subprocess.SubprocessError):
            signal = "agathodaimon-time-upstream-wan-route-unavailable"
        delay = min(1 - (time.monotonic() - started), deadline - time.monotonic())
        if delay > 0:
            time.sleep(delay)
    return None, signal


def _write_sources(content):
    directory = Path(os.environ.get("AGATHODAIMON_TIME_UPSTREAM_DIR", "/run/chrony-dhcp"))
    directory.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".upstream.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
        os.replace(name, directory / "upstream.sources")
    finally:
        Path(name).unlink(missing_ok=True)


def _reload_if_running():
    try:
        if _run(["pgrep", "-x", "chronyd"], 1).returncode == 0:
            _run(["chronyc", "reload", "sources"], 2)
    except (OSError, subprocess.SubprocessError):
        pass


def upstream():
    gateway, signal = _gateway()
    answered = False
    if gateway:
        try:
            answered = _run(["chronyd", "-Q", "-t", "8", f"server {gateway} iburst"], 10).returncode == 0
            if not answered:
                signal = "agathodaimon-time-upstream-gateway-no-answer"
        except (OSError, subprocess.SubprocessError):
            signal = "agathodaimon-time-upstream-gateway-probe-failed"
    mode = "gateway" if answered else "pools"
    content = f"server {gateway} iburst\n" if answered else POOLS
    try:
        _write_sources(content)
    except OSError:
        return household.receipt("upstream", ok=False, changed=False, gateway=gateway,
                                 answered=answered, mode=None,
                                 first_missing_signal="agathodaimon-time-upstream-write-failed")
    _reload_if_running()
    return household.receipt("upstream", ok=True, changed=True, gateway=gateway,
                             answered=answered, mode=mode, first_missing_signal=signal)


def main(argv=None):
    del argv
    try:
        request = read()
    except EnvelopeError as error:
        value = household.receipt("invalid", ok=False, changed=False, first_missing_signal=str(error))
        print(json.dumps(value, sort_keys=True))
        return 1
    value = attach(upstream(), request)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1

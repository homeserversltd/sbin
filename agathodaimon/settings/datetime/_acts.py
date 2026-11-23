"""Date & Time's staff observations and mutations."""
from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import sys
from datetime import UTC, datetime
from http.client import HTTPConnection, HTTPException
from importlib import import_module
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_HOUSE_FETCH_SECONDS = 2.0

# Only the private reader owns this timer. Use kernel termination, not a
# Python handler that could wait on DNS, and don't inherit a blocked alarm.
if __name__ == "__main__":
    if sys.argv[1:] != ["--read-house-state"]:
        sys.exit(2)
    signal.signal(signal.SIGALRM, signal.SIG_DFL)
    signal.setitimer(signal.ITIMER_REAL, _HOUSE_FETCH_SECONDS)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from agathodaimon._envelope import appliance_runtime_path
from agathodaimon._nidus.write import WriteError
from agathodaimon.settings import _shared
from agathodaimon.settings.datetime import _bar_clock, _zone_mode

_household = import_module("agathodaimon.settings.datetime.household-time._household")
_LOCAL_TIME = "%Y-%m-%d %H:%M"
_AUTOMATIC_TIME_ON = "unsupported:automatic-time-on"
_HOUSE_BODY_MAX = 65536


def _properties(*args):
    ok, text, _ = _shared.command([_household.timedatectl(), *args])
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line) if ok else {}


def _clock():
    properties = _properties("show", "-p", "Timezone", "-p", "NTP", "-p", "NTPSynchronized")
    zone = properties.get("Timezone")
    if not zone or any(properties.get(key) not in ("yes", "no") for key in ("NTP", "NTPSynchronized")):
        raise ValueError("datetime-clock-read-failed")
    return {"timezone": zone, "ntp_enabled": properties["NTP"] == "yes",
            "ntp_synchronized": properties["NTPSynchronized"] == "yes"}


def _last_sync():
    root = Path(os.environ.get("CADUCEUS_ROOT") or appliance_runtime_path("profile").parents[2])
    try:
        stamp = (root / "run/systemd/timesync/synchronized").stat().st_mtime
        return datetime.fromtimestamp(stamp, UTC).isoformat().replace("+00:00", "Z")
    except (OSError, ValueError, OverflowError):
        return None


def _observe_values():
    clock = _clock()
    server = _properties("show-timesync", "-p", "ServerName").get("ServerName") if clock["ntp_enabled"] else None
    home = _shared.home()
    included = _bar_clock.includes_override(home)
    values = {**clock, "automatic_timezone": _zone_mode.read_mode() == "follow",
              "time_format": _bar_clock.read_format(home, included=included),
              "time_server": server or None, "last_sync": _last_sync()}
    return values, included


def read_values():
    return _observe_values()[0]


def read_settings():
    values, included = _observe_values()
    readonly = {} if included else {"time_format": _bar_clock.ABSENT}
    try:
        house_server = _zone_mode.keeps_house_time()
    except ValueError:
        # A missing profile must not suppress the existing clock observation.
        house_server = False
    if house_server:
        protected = ["timezone", "local_time"]
        # A switch that is off can still be turned on on a HomeServer.
        protected.extend(field for field in ("ntp_enabled", "automatic_timezone") if values[field])
        readonly.update(dict.fromkeys(protected, _zone_mode.HOUSE_TIME_REFUSAL))
    return values, readonly


def _read_house_state() -> bytes:
    """Read only in the supervised child, never under the zone-mode lock."""
    connection = HTTPConnection("home.arpa", 3014)
    try:
        connection.request("GET", "/api/v1/time/state", headers={"Accept": "application/json"})
        with connection.getresponse() as response:
            if response.status != 200:
                return b""
            body = response.read(_HOUSE_BODY_MAX + 1)
            return body if len(body) <= _HOUSE_BODY_MAX else b""
    finally:
        connection.close()


def _fresh_house_zone() -> tuple[str, datetime] | None:
    # One timeout covers DNS, connect, headers and the body. run() kills
    # and reaps the direct child even if name resolution never returns.
    argv = [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--read-house-state"]
    try:
        body = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=_HOUSE_FETCH_SECONDS, check=True).stdout
        if not body:
            return None
        document = json.loads(body)
        if not isinstance(document, dict) or document.get("ok") is False:
            return None
        state = document.get("state", document)
        if not isinstance(state, dict):
            return None
        until = _household.parse_stamp(state.get("valid_until"))
        if until is None or until.tzinfo is None or until <= datetime.now(UTC):
            return None
        return _household.validated_timezone(state.get("timezone")), until
    except (OSError, subprocess.SubprocessError, ValueError, RecursionError):
        return None


def _zoneinfo(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_+.-]*(?:/[A-Za-z0-9_+.-]+)*", value):
        raise ValueError("invalid:timezone")
    try:
        return ZoneInfo(value)
    except (ValueError, ZoneInfoNotFoundError) as error:
        raise ValueError("invalid:timezone") from error


def _wall_time(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}", value):
        raise ValueError("invalid:local_time:expected-YYYY-MM-DD-HH:MM")
    try:
        return datetime.strptime(value, _LOCAL_TIME)
    except ValueError as error:
        raise ValueError("invalid:local_time:calendar") from error


def _utc_instant(wall, zone):
    try:
        instants = {wall.replace(tzinfo=zone, fold=fold).astimezone(UTC) for fold in (0, 1)}
        instants = {value for value in instants if value.astimezone(zone).replace(tzinfo=None) == wall}
    except (OverflowError, ValueError) as error:
        raise ValueError("invalid:local_time:calendar") from error
    if len(instants) != 1:
        raise ValueError("invalid:local_time:" + ("ambiguous" if instants else "nonexistent"))
    return instants.pop()


def _prepare(changes):
    protected = ("timezone" in changes or "local_time" in changes
                 or changes.get("ntp_enabled") is False or changes.get("automatic_timezone") is False)
    follow = changes.get("automatic_timezone") is True
    house_server = (protected or follow) and _zone_mode.keeps_house_time()
    if protected and house_server:
        raise ValueError(_zone_mode.HOUSE_TIME_REFUSAL)
    for field in ("ntp_enabled", "automatic_timezone"):
        if field in changes:
            _shared.boolean(changes[field], field)
    if "timezone" in changes:
        _zoneinfo(changes["timezone"])
        if follow:
            raise ValueError("invalid:timezone:conflicts-with-follow")
    if "time_format" in changes:
        name = changes["time_format"]
        if not isinstance(name, str) or name not in _bar_clock.FORMATS:
            raise ValueError("invalid:time_format")
        if not _bar_clock.includes_override(_shared.home()):
            raise ValueError(_bar_clock.ABSENT)
    return house_server


def _record(receipt, result):
    receipt.commands.append({"argv": result.args, "returncode": result.returncode})
    if result.returncode == 0:
        receipt.changed = True


def _timedate(receipt, field, verb, value):
    argv = [_household.timedatectl(), verb, value]
    ok, _, result = _shared.command(argv)
    _record(receipt, result)
    if not ok:
        raise ValueError("privilege:" + field)


def _apply(changes, receipt, readback, prepared):
    clock, house_server, house_zone, wall, wall_zone, instant = prepared
    if "timezone" in changes or "automatic_timezone" in changes:
        zone = changes.get("timezone")
        if zone is not None and zone != clock["timezone"]:
            _timedate(receipt, "timezone", "set-timezone", zone)
            if _clock()["timezone"] != zone:
                raise ValueError("datetime-timezone-readback-failed")
        mode = "follow" if changes.get("automatic_timezone") is True else "manual"
        receipt.changed |= _zone_mode.set_mode_locked(mode)
        readback["automatic_timezone"] = _zone_mode.read_mode() == "follow"
        if readback["automatic_timezone"] != (mode == "follow"):
            raise ValueError("datetime-zone-mode-readback-failed")
        if zone is not None:
            readback["timezone"] = zone
        if mode == "follow":
            if house_server:
                readback["household_zone"] = {"status": "not-applicable"}
            elif house_zone is None:
                readback["household_zone"] = {"status": "deferred"}
            else:
                readback["household_zone"] = {"status": "failed", "timezone": house_zone}
                applied = _household.set_timezone(house_zone, immediate=True,
                                                  observe_set=lambda result: _record(receipt, result))
                if not applied["ok"]:
                    raise ValueError(applied["firstMissingSignal"])
                readback["household_zone"]["status"] = "applied"
                readback["timezone"] = house_zone

    if "ntp_enabled" in changes:
        enabled = changes["ntp_enabled"]
        if clock["ntp_enabled"] != enabled:
            _timedate(receipt, "ntp_enabled", "set-ntp", "yes" if enabled else "no")
        readback["ntp_enabled"] = _clock()["ntp_enabled"]
        if readback["ntp_enabled"] != enabled:
            raise ValueError("datetime-ntp-readback-failed")
    if wall is not None:
        # Do not assume that disabling NTP or applying a zone succeeded.
        observed = _clock()
        if observed["ntp_enabled"]:
            raise ValueError(_AUTOMATIC_TIME_ON)
        if observed["timezone"] != wall_zone.key:
            raise ValueError("datetime-timezone-readback-failed")
        # Send an unambiguous instant even if the staff process inherited TZ.
        _timedate(receipt, "local_time", "set-time", instant.isoformat(sep=" ", timespec="seconds").replace("+00:00", " UTC"))
        actual = datetime.now(wall_zone).replace(second=0, microsecond=0)
        readback["local_time"] = actual.isoformat(sep=" ", timespec="minutes")[:16]
        if actual.astimezone(UTC) != instant:
            raise ValueError("datetime-local-time-readback-failed")
    if "time_format" in changes:
        bar = _bar_clock.set_format(_shared.home(), changes["time_format"])
        receipt.changed |= bar["changed"]
        receipt.commands.extend(bar["commands"])
        readback.update(time_format=bar["time_format"], waybar_reload=bar["waybar_reload"])


def _signal(error):
    return str(error) if isinstance(error, ValueError) else "datetime-system-operation-failed"


def set_values(changes):
    readback = {}
    receipt = None
    try:
        house_server = _prepare(changes)
        house_fact = _fresh_house_zone() if changes.get("automatic_timezone") is True and not house_server else None
        with _zone_mode.locked():
            clock = _clock() if changes.keys() & {"timezone", "ntp_enabled", "local_time"} else {}
            wall = None
            if "local_time" in changes:
                if changes.get("ntp_enabled", clock["ntp_enabled"]):
                    raise ValueError(_AUTOMATIC_TIME_ON)
                wall = _wall_time(changes["local_time"])
            if "timezone" in changes or "automatic_timezone" in changes:
                _zone_mode.read_mode()  # A broken config must not leave a hand-set zone half applied.
            # The fact can expire while a local writer holds the lock.
            house_zone = house_fact[0] if house_fact and house_fact[1] > datetime.now(UTC) else None
            wall_zone = _zoneinfo(changes.get("timezone") or house_zone or clock["timezone"]) if wall is not None else None
            instant = _utc_instant(wall, wall_zone) if wall is not None else None
            receipt = _shared.Receipt("datetime", list(changes))
            try:
                prepared = (clock, house_server, house_zone, wall, wall_zone, instant)
                _apply(changes, receipt, readback, prepared)
                result = receipt.finish(True, receipt.changed)
            except (OSError, ValueError, subprocess.SubprocessError, WriteError, RecursionError) as error:
                result = receipt.finish(False, receipt.changed, _signal(error))
            result.update(changed=receipt.changed, mutationPerformed=receipt.changed, readback=readback)
            return result
    except (OSError, ValueError, RecursionError) as error:
        changed = receipt is not None and receipt.changed
        return {"ok": False, "firstMissingSignal": _signal(error), "changed": changed,
                "mutationPerformed": changed, "readback": readback}


if __name__ == "__main__":
    try:
        sys.stdout.buffer.write(_read_house_state())
    except (OSError, HTTPException):
        sys.exit(1)

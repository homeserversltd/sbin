"""Read Linux power hardware and describe the Lenovo charge-limit write."""
from __future__ import annotations

import re
import shlex
from pathlib import Path


CHARGE_LIMIT_DROP_IN = "tmpfiles.d/60-appliance-charge-limit.conf"
SYSTEM_FIELDS = ("battery_level", "battery_state", "lid_action")


def _text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError):
        return None


def battery_values() -> dict[str, int | str | None]:
    for supply in sorted(Path("/sys/class/power_supply").glob("*")):
        if (_text(supply / "type") != "Battery" or _text(supply / "scope") == "Device"
                or _text(supply / "present") == "0"):
            continue
        level = _text(supply / "capacity") or ""
        return {
            "battery_level": int(level) if re.fullmatch(r"[0-9]{1,3}", level) and int(level) <= 100 else None,
            "battery_state": _text(supply / "status") or None,
        }
    return {}


def conservation_mode() -> Path | None:
    # The driver link survives PCI path changes. Do not guess which device to
    # write if two conservation_mode nodes are exposed by this driver.
    driver = Path("/sys/bus/platform/drivers/ideapad_acpi")
    paths = [path for path in driver.glob("VPC2004:*/conservation_mode")
             if re.fullmatch(r"VPC2004:[0-9A-Fa-f]{2}", path.parent.name) and path.is_file()]
    return paths[0] if len(paths) == 1 else None


def charge_limit(path: Path) -> bool | None:
    return {"0": False, "1": True}.get(_text(path) or "")


def write_charge_limit(path: Path, enabled: bool) -> None:
    try:
        # A sysfs attribute must already exist; never replace or create it.
        with path.open("r+b", buffering=0) as target:
            if target.write(b"1" if enabled else b"0") != 1:
                raise ValueError("charge-limit-write-failed")
    except OSError as error:
        raise ValueError("charge-limit-write-failed") from error
    if charge_limit(path) is not enabled:
        raise ValueError("charge-limit-readback-mismatch")


def _is_dpms_off(command: str) -> bool:
    try:
        words = shlex.split(command, comments=True)
    except ValueError:
        return False
    if len(words) < 3 or Path(words[0]).name != "hyprctl" or words[1] != "dispatch":
        return False
    return words[2:] == ["dpms", "off"] or (len(words) == 3 and re.fullmatch(
        r'''hl\.dsp\.dpms\(\s*\{\s*action\s*=\s*(["'])disable\1\s*\}\s*\)''', words[2]) is not None)


def hypridle_screen_off(home: Path) -> int | None:
    """Read configured display blanking only; do not run a listener command."""
    timers = []
    listener: dict[str, str] | None = None
    for line in (_text(home / ".config/hypr/hypridle.conf") or "").splitlines():
        stripped = line.split("#", 1)[0].strip()
        if re.fullmatch(r"listener\s*\{", stripped):
            listener = {}
        elif listener is not None:
            if stripped == "}":
                timeout = listener.get("timeout", "")
                if _is_dpms_off(listener.get("on-timeout", "")) and re.fullmatch(r"[0-9]{1,10}", timeout):
                    timers.append(int(timeout))
                listener = None
            else:
                key, separator, value = line.partition("=")
                key = key.strip()
                if separator and key in {"timeout", "on-timeout"}:
                    listener[key] = (value if key == "on-timeout" else value.split("#", 1)[0]).strip()
    return min(timers) if timers else None

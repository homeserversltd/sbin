"""Keep HomeServer's system clock on UTC on every timezone setter."""
import json
import os
from pathlib import Path


def require_timezone_change_allowed():
    root = os.environ.get("CADUCEUS_ROOT")
    if root is None:
        from agathodaimon.settings.display.policy import _read_profile_name
        profile = _read_profile_name()
    else:
        try:
            value = json.loads((Path(root) / "etc/appliance/profile.json").read_text(encoding="utf-8"))
            profile = value.get("profile") if isinstance(value, dict) else None
        except (OSError, UnicodeError, ValueError):
            profile = None
    if not isinstance(profile, str) or not profile:
        raise ValueError("agathodaimon-household-time-profile-unavailable")
    if profile == "homeserver":
        raise ValueError("agathodaimon-household-time-homeserver-utc-only")

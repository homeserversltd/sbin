"""Keep HomeServer's system clock on UTC on every timezone setter."""


def require_timezone_change_allowed():
    from agathodaimon.settings.display.policy import _read_profile_name

    profile = _read_profile_name()
    if not isinstance(profile, str) or not profile:
        raise ValueError("agathodaimon-household-time-profile-unavailable")
    if profile == "homeserver":
        raise ValueError("agathodaimon-household-time-homeserver-utc-only")

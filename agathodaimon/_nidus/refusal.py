import re


_SIGNAL_TOKEN = re.compile(r"[a-z0-9._:-]+")


class Refusal(RuntimeError):
    """A bounded actuation refusal."""


class BadRequest(ValueError):
    """A bounded refusal of the request itself."""


def named_signal(exc: Exception, stop: str) -> str:
    """Keep an explicit signal token, then a whole message token, never prose."""
    signal = getattr(exc, "signal", None)
    if isinstance(signal, str) and _SIGNAL_TOKEN.fullmatch(signal):
        return signal
    message = str(exc)
    if _SIGNAL_TOKEN.fullmatch(message):
        return message
    return f"{stop}-failed:{type(exc).__name__}"

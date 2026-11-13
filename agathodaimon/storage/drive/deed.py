"""The closed deed vocabulary for opened data drives."""
from agathodaimon._deed import send


def record(verb, ok, duration_ms, signal=None):
    if verb not in {"drive-open", "drive-eject"}:
        raise ValueError("invalid drive deed verb")
    return send("sbin", verb, ok, target="drive", duration_ms=duration_ms, signal=signal)

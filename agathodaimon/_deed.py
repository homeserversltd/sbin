"""Send bounded staff deeds to the local Caduceus hyalos door."""
from __future__ import annotations

from datetime import datetime, timezone
import json
import sys
from urllib.parse import urlsplit
from urllib.request import Request, ProxyHandler, HTTPRedirectHandler, build_opener

from agathodaimon._envelope import appliance_runtime_path


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send(organ: str, verb: str, ok: bool, *, target: str = "", duration_ms: int = 0,
         signal: str = "operation-failed") -> bool:
    """Send fixed deed metadata; callers must never supply secret material."""
    try:
        if not all(isinstance(x, str) and x and len(x) <= 48 and
                   all(c.isascii() and (c.isalnum() or c in "-_.") for c in x)
                   for x in (organ, verb)):
            raise ValueError("invalid deed identity")
        if not isinstance(target, str) or len(target) > 48 or any(
            not (c.isascii() and (c.isalnum() or c in "-_.")) for c in target
        ):
            raise ValueError("invalid deed target")
        config = json.loads(appliance_runtime_path("config").read_text(encoding="utf-8"))
        bind = config["caduceus"]["bind"]
        parsed = urlsplit(bind if "://" in bind else "http://" + bind)
        if parsed.username is not None or parsed.password is not None or parsed.port is None:
            raise ValueError("invalid caduceus bind")
        try:
            profile = json.loads(appliance_runtime_path("profile").read_text(encoding="utf-8"))
            body_id = profile.get("body_id") or profile.get("bodyId") or profile.get("profile") or "unknown-body"
            world = profile.get("world") or ("monad" if profile.get("profile") == "homeserver" else "appliance")
            if not isinstance(body_id, str):
                body_id = "unknown-body"
            if world not in ("appliance", "monad"):
                world = "appliance"
        except (OSError, ValueError, AttributeError):
            body_id, world = "unknown-body", "appliance"
        if not isinstance(signal, str) or len(signal) > 40 or not all(
            c.isascii() and (c.isalnum() or c in "-_.") for c in signal
        ):
            signal = "operation-failed"
        event = {
            "schema": "hyalos.channel.event.v2",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "body_id": body_id, "world": world, "organ": organ,
            "kind": organ + "." + verb, "level": "info" if ok else "error",
            "ok": bool(ok), "message": "deed recorded",
            "attributes_redacted": {"who": organ, "verb": verb, "target": target,
                                    "outcome": "ok" if ok else "failed",
                                    "signal": "none" if ok else signal,
                                    "first_missing_field": None if ok else verb,
                                    "duration_ms": max(0, int(duration_ms))},
        }
        data = json.dumps(event, separators=(",", ":"), ensure_ascii=True).encode()
        if len(data) >= 1024:
            raise ValueError("deed too large")
        request = Request(f"http://127.0.0.1:{parsed.port}/api/v1/log/write", data=data,
                          headers={"Content-Type": "application/json"}, method="POST")
        with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=2) as response:
            if not 200 <= response.status < 300:
                raise OSError("door rejected deed")
        return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print("caduceus-deed-post-failed", file=sys.stderr)
        return False

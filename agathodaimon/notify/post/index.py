"""Post one complete notification through the local Caduceus door."""
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from agathodaimon._load_trace import _caduceus_base_url

SCHEMA = "caduceus.staff.notify-post.v1"


def _emit(value):
    value["schema"] = SCHEMA
    print(json.dumps(value))
    return 0 if value.get("ok") is True else 1


def _failure(signal):
    return _emit({"ok": False, "firstMissingSignal": signal})


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _post(url, body):
    request = Request(url, data=json.dumps(body).encode(), method="POST", headers={"Accept": "application/json", "Content-Type": "application/json"})
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    with opener.open(request, timeout=10) as response:
        return json.load(response)


def main(argv=None):
    try:
        value = json.load(sys.stdin)
        if isinstance(value, dict) and value.get("schema") == "caduceus.staff.v1":
            value = value.get("payload")
        row = value.get("notification", value) if isinstance(value, dict) else None
        if not isinstance(row, dict) or not all(isinstance(row.get(k), str) and row[k].strip() for k in ("id", "kind", "title")) or row.get("color") not in ("red", "amber", "blue", "none"):
            return _failure("notify-row-invalid")
    except (OSError, UnicodeError, ValueError):
        return _failure("notify-row-invalid")
    try:
        root = Path(os.environ.get("CADUCEUS_ROOT", "/"))
        previous = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
        try:
            if root != Path("/"):
                os.environ["AGATHODAIMON_SCRATCH_ROOT"] = str(root)
            else:
                os.environ.pop("AGATHODAIMON_SCRATCH_ROOT", None)
            base = _caduceus_base_url()
        finally:
            if previous is None:
                os.environ.pop("AGATHODAIMON_SCRATCH_ROOT", None)
            else:
                os.environ["AGATHODAIMON_SCRATCH_ROOT"] = previous
        try:
            result = _post(base + "/api/v1/notifications", {"schema": "caduceus.notifications.v1", "notification": row})
        except HTTPError as error:
            if error.code in (404, 405, 501):
                return _failure("notify-door-absent")
            try:
                result = json.load(error)
            except (ValueError, OSError, UnicodeError):
                return _failure("notify-door-unavailable")
            if not isinstance(result, dict) or result.get("ok") is not False:
                return _failure("notify-door-unavailable")
        if not isinstance(result, dict):
            return _failure("notify-door-unavailable")
        return _emit(result)
    except (OSError, KeyError, TypeError, ValueError, URLError):
        return _failure("notify-post-unavailable")

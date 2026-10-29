"""Post one complete notification through the local Caduceus door."""
import json
import os
import sys
import uuid
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


def _post(url, body, headers=None):
    request = Request(url, data=json.dumps(body).encode(), method="POST", headers={"Content-Type": "application/json", **(headers or {})})
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
        config = json.loads((root / "etc/appliance/config.json").read_text(encoding="utf-8"))
        pin = config["global"]["admin"]["pin"]
        if not isinstance(pin, str) or not pin:
            return _failure("notify-pin-unavailable")
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
        document = "staff-notify-" + uuid.uuid4().hex
        opened = _post(base + "/api/v1/exousia/open", {"documentId": document, "documentIncarnation": uuid.uuid4().hex, "pin": pin})
        pin = None
        if not isinstance(opened, dict) or opened.get("ok") is not True or not isinstance(opened.get("attendance"), str) or not opened["attendance"]:
            return _failure("notify-attendance-unavailable")
        headers = {"x-caduceus-document": document, "x-caduceus-attendance": opened["attendance"]}
        try:
            result = _post(base + "/api/v1/notifications", {"schema": "caduceus.notifications.v1", "notification": row}, headers)
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

#!/usr/bin/env python3
"""Publish the immutable sbin release flag to Forgejo."""
from __future__ import annotations

import datetime
import json
import os
import re
import secrets
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

API = "https://git.home.arpa/api/v1"
WEB = "https://git.home.arpa"
OWNER_REPO = "HOMESERVERSLTD/sbin"
FLAG_NAME = "release.flag"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
UNIX_TIMESTAMP = re.compile(r"^[0-9]+$")


class ReleaseError(RuntimeError):
    """A failure that is safe to expose in the CI receipt."""


def fail(message: str) -> None:
    raise ReleaseError(message)


def ssl_context() -> ssl.SSLContext:
    cafile = os.environ.get("SSL_CERT_FILE")
    return ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()


def request_url(path_or_url: str) -> str:
    """Allow only the fixed Forgejo HTTPS host for every request and redirect."""
    parsed = urllib.parse.urlsplit(path_or_url)
    if parsed.scheme:
        if (
            parsed.scheme != "https"
            or parsed.hostname != "git.home.arpa"
            or parsed.netloc != "git.home.arpa"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port not in (None, 443)
        ):
            fail("refusing URL outside the fixed Forgejo HTTPS host")
        return path_or_url
    if not path_or_url.startswith("/"):
        fail("Forgejo API path must be absolute")
    return API + path_or_url


class FixedHostRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        request_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request(
    method: str,
    path_or_url: str,
    token: str,
    *,
    body: bytes | None = None,
    content_type: str | None = None,
    accept: str = "application/json",
) -> tuple[int, bytes]:
    headers = {"Authorization": f"token {token}", "Accept": accept}
    if content_type:
        headers["Content-Type"] = content_type
    url = request_url(path_or_url)
    opener = urllib.request.build_opener(
        FixedHostRedirects,
        urllib.request.HTTPSHandler(context=ssl_context()),
    )
    try:
        with opener.open(
            urllib.request.Request(url, data=body, headers=headers, method=method),
            timeout=120,
        ) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        exc.read()
        return exc.code, b""
    except (urllib.error.URLError, OSError) as exc:
        detail = exc.reason if isinstance(exc, urllib.error.URLError) else type(exc).__name__
        fail(f"transport failure for {method} {path_or_url}: {detail}")
    raise AssertionError("unreachable")


def decode_json(raw: bytes, description: str) -> Any:
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"{description} returned invalid JSON")
        raise AssertionError("unreachable") from exc


def flagged_at() -> str:
    raw = os.environ.get("CI_COMMIT_TIMESTAMP", "")
    if not UNIX_TIMESTAMP.fullmatch(raw):
        fail("CI_COMMIT_TIMESTAMP must be a required UNIX timestamp")
    try:
        value = datetime.datetime.fromtimestamp(int(raw), datetime.timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        fail(f"CI_COMMIT_TIMESTAMP is out of range: {exc}")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def flag_bytes(source_sha: str, pipeline_url: str) -> bytes:
    if not FULL_SHA.fullmatch(source_sha):
        fail("CI_COMMIT_SHA must be exactly 40 lowercase hexadecimal characters")
    if not pipeline_url:
        fail("CI_PIPELINE_URL is required")
    payload = {
        "schema": "estate.release-flag.v1",
        "component": "sbin",
        "source_sha": source_sha,
        "flagged_at": flagged_at(),
        "pipeline_url": pipeline_url,
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def release_tag_url(source_sha: str) -> str:
    return f"/repos/{OWNER_REPO}/releases/tags/{urllib.parse.quote(source_sha, safe='')}"


def release_page_url(source_sha: str) -> str:
    return f"{WEB}/{OWNER_REPO}/releases/tag/{urllib.parse.quote(source_sha, safe='')}"


def read_release(source_sha: str, token: str) -> dict[str, Any] | None:
    status, raw = request("GET", release_tag_url(source_sha), token)
    if status == 404:
        return None
    if status != 200:
        fail(f"release lookup returned HTTP {status}")
    value = decode_json(raw, "release lookup")
    if not isinstance(value, dict):
        fail("release lookup returned a non-object")
    return value


def validate_identity(release: dict[str, Any], source_sha: str) -> int:
    if (
        release.get("tag_name") != source_sha
        or release.get("name") != f"sbin {source_sha[:8]}"
        or release.get("target_commitish") != source_sha
    ):
        fail("release identity conflicts with CI_COMMIT_SHA")
    release_id = release.get("id")
    if not isinstance(release_id, int) or isinstance(release_id, bool):
        fail("release response omitted its numeric id")
    return release_id


def validate_assets(release: dict[str, Any], expected_names: set[str]) -> dict[str, dict[str, Any]]:
    assets = release.get("assets")
    if not isinstance(assets, list):
        fail("release response has no asset list")
    by_name: dict[str, dict[str, Any]] = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            fail("release contains a malformed asset")
        name = asset["name"]
        if name in by_name:
            fail("release contains duplicate asset names")
        by_name[name] = asset
    if set(by_name) != expected_names:
        fail("release assets do not exactly match the release.flag contract")
    return by_name


def download_asset(asset: dict[str, Any], token: str) -> bytes:
    asset_id = asset.get("id")
    if not isinstance(asset_id, int) or isinstance(asset_id, bool):
        fail("release.flag asset response omitted its numeric id")
    status, raw = request(
        "GET",
        f"/repos/{OWNER_REPO}/releases/assets/{asset_id}",
        token,
        accept="application/octet-stream",
    )
    if status != 200:
        fail(f"release.flag download returned HTTP {status}")
    return raw


def validate_existing(release: dict[str, Any], source_sha: str, token: str, expected: bytes) -> None:
    validate_identity(release, source_sha)
    assets = validate_assets(release, {FLAG_NAME})
    if download_asset(assets[FLAG_NAME], token) != expected:
        fail("immutable release.flag conflict; refusing overwrite")


def multipart_flag(content: bytes) -> tuple[bytes, str]:
    boundary = "sbin-release-" + secrets.token_hex(16)
    header = (
        f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; '
        f'filename="{FLAG_NAME}"\r\nContent-Type: application/json; charset=utf-8\r\n\r\n'
    ).encode("ascii")
    trailer = f"\r\n--{boundary}--\r\n".encode("ascii")
    return header + content + trailer, f"multipart/form-data; boundary={boundary}"


def create_release(source_sha: str, token: str) -> tuple[dict[str, Any], bool]:
    payload = json.dumps(
        {
            "tag_name": source_sha,
            "target_commitish": source_sha,
            "name": f"sbin {source_sha[:8]}",
            "body": "",
            "draft": False,
            "prerelease": False,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    status, raw = request(
        "POST",
        f"/repos/{OWNER_REPO}/releases",
        token,
        body=payload,
        content_type="application/json",
    )
    if status == 409:
        raced = read_release(source_sha, token)
        if raced is None:
            fail("release create race did not produce a readable release")
        return raced, True
    if status != 201:
        fail(f"release creation returned HTTP {status}")
    value = decode_json(raw, "release creation")
    if not isinstance(value, dict):
        fail("release creation returned a non-object")
    validate_identity(value, source_sha)
    validate_assets(value, set())
    return value, False


def publish(source_sha: str, token: str, expected: bytes) -> tuple[str, str]:
    existing = read_release(source_sha, token)
    if existing is not None:
        validate_existing(existing, source_sha, token, expected)
        return "no-op", release_page_url(source_sha)

    release, raced = create_release(source_sha, token)
    if raced:
        validate_existing(release, source_sha, token, expected)
        return "no-op", release_page_url(source_sha)
    release_id = validate_identity(release, source_sha)
    if release.get("assets") != []:
        validate_assets(release, set())

    body, content_type = multipart_flag(expected)
    status, _ = request(
        "POST",
        f"/repos/{OWNER_REPO}/releases/{release_id}/assets?"
        + urllib.parse.urlencode({"name": FLAG_NAME}),
        token,
        body=body,
        content_type=content_type,
    )
    if status != 201:
        fail(f"release.flag upload returned HTTP {status}")

    reread = read_release(source_sha, token)
    if reread is None:
        fail("release reread returned HTTP 404")
    validate_existing(reread, source_sha, token, expected)
    return "published", release_page_url(source_sha)


def main() -> int:
    token = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not token:
        print(json.dumps({"status": "error", "error": "FORGEJO_TOKEN is required"}, separators=(",", ":")))
        return 1
    source_sha = os.environ.get("CI_COMMIT_SHA", "")
    try:
        expected = flag_bytes(source_sha, os.environ.get("CI_PIPELINE_URL", ""))
        status, url = publish(source_sha, token, expected)
    except ReleaseError as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, separators=(",", ":")))
        return 1
    print(
        json.dumps(
            {
                "status": status,
                "tag": source_sha,
                "name": f"sbin {source_sha[:8]}",
                "assets": [FLAG_NAME],
                "release_url": url,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

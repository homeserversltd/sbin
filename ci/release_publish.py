#!/usr/bin/env python3
"""Publish the sbin shipped payload to its native Forgejo release.

The release version and tag are derived deterministically as VERSION, the
literal ``-g``, and the full lowercase 40-hex HEAD. This makes each admitted
main head uniquely addressable even when VERSION is unchanged. HEAD is
validated before it is used. The payload is tracked repository content
excluding CI-only files (.woodpecker.yml and ci/); tar member order and
metadata are normalized.

Emit one JSON receipt. An existing release with matching verified assets is a
no-op. A new release is created, both assets uploaded, downloaded, and checked.
"""
from __future__ import annotations
import hashlib, json, os, re, subprocess, sys, tarfile, tempfile
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

API = "https://git.home.arpa/api/v1"
WEB = "https://git.home.arpa"
OWNER = "HOMESERVERSLTD"
REPO = "sbin"
SCHEMA = "sbin.release_publish.v1"
OPERATION = "release.publish"
SAFE = re.compile(r"^[A-Za-z0-9._-]+$")
HEAD = re.compile(r"^[0-9a-f]{40}$")

class ReleaseError(RuntimeError):
    """A failure suitable for the JSON receipt."""

def request(method: str, path: str, token: str, *, body: Any = None,
            data: bytes | None = None, query: dict[str, str] | None = None,
            raw: bool = False) -> tuple[int, Any]:
    url = API.rstrip("/") + path
    if query:
        url += "?" + urlencode(query)
    headers = {"Accept": "application/octet-stream" if raw else "application/json",
               "Authorization": f"token {token}"}
    if body is not None:
        data = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        headers["Content-Type"] = "application/octet-stream"
    try:
        with urlopen(Request(url, data=data, headers=headers, method=method), timeout=30) as response:
            payload = response.read()
            if raw:
                return response.status, payload
            if not payload:
                return response.status, None
            try:
                return response.status, json.loads(payload)
            except json.JSONDecodeError as exc:
                raise ReleaseError("non-json-forgejo-response") from exc
    except HTTPError as exc:
        return exc.code, None
    except (OSError, URLError) as exc:
        raise ReleaseError(type(exc).__name__) from exc

def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                            text=True, check=False)
    if result.returncode:
        raise ReleaseError(f"git-{args[0]}-failed")
    return result.stdout.strip()

def payload(root: Path) -> list[str]:
    names = [p for p in git(root, "ls-files", "-z").split("\0") if p]
    names = [p for p in names if p != ".woodpecker.yml" and not p.startswith("ci/")]
    if not names:
        raise ReleaseError("empty-shipped-payload")
    return sorted(names)

def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    info.mtime = 0
    info.pax_headers = {}
    return info

def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def make_tar(root: Path, names: list[str], destination: Path) -> None:
    with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as archive:
        for name in names:
            archive.add(root / name, arcname=name, recursive=False, filter=normalize)

def assets(token: str, release_id: int) -> list[dict[str, Any]]:
    base = f"/repos/{OWNER}/{REPO}/releases/{release_id}/assets"
    status, value = request("GET", base, token)
    if status != 200 or not isinstance(value, list):
        raise ReleaseError("release-assets-read-failed")
    return [v for v in value if isinstance(v, dict)]

def verify(token: str, values: list[dict[str, Any]], artifact: str,
           sidecar: str, expected: str) -> None:
    by_name = {v.get("name"): v for v in values}
    if {artifact, sidecar} - set(by_name):
        raise ReleaseError("release-assets-incomplete")
    for name, sidecar_bytes in ((artifact, None),
                                (sidecar, f"{expected}  {artifact}\n".encode())):
        asset_id = by_name[name].get("id")
        if not isinstance(asset_id, int):
            raise ReleaseError("release-asset-id-missing")
        status, downloaded = request("GET", f"/repos/{OWNER}/{REPO}/releases/assets/{asset_id}",
                                     token, raw=True)
        if status != 200 or not isinstance(downloaded, bytes):
            raise ReleaseError("release-asset-download-failed")
        if name == artifact and hashlib.sha256(downloaded).hexdigest() != expected:
            raise ReleaseError("release-artifact-digest-mismatch")
        if name == sidecar and downloaded != sidecar_bytes:
            raise ReleaseError("release-sidecar-mismatch")

def publish(root: Path) -> dict[str, Any]:
    token = os.environ.get("FORGEJO_TOKEN", "").strip()
    if not token:
        raise ReleaseError("forgejo-token-missing")
    base_version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SAFE.fullmatch(base_version):
        raise ReleaseError("invalid-version")
    head = git(root, "rev-parse", "HEAD")
    if not HEAD.fullmatch(head):
        raise ReleaseError("invalid-source-head")
    version = f"{base_version}-g{head}"
    names = payload(root)
    artifact = f"{REPO}-{version}.tar"
    sidecar = f"{artifact}.sha256"
    base = f"/repos/{OWNER}/{REPO}"
    release_url = f"{WEB}/{OWNER}/{REPO}/releases/tag/{quote(version, safe='')}"
    with tempfile.TemporaryDirectory(prefix="sbin-release-") as temp:
        archive = Path(temp) / artifact
        make_tar(root, names, archive)
        expected = digest(archive)
        sidecar_bytes = f"{expected}  {artifact}\n".encode("ascii")
        tag_path = f"{base}/tags/{quote(version, safe='')}"
        tag_status, tag = request("GET", tag_path, token)
        if tag_status not in (200, 404):
            raise ReleaseError("release-tag-read-failed")
        if tag_status == 200 and isinstance(tag, dict):
            commit = tag.get("commit")
            tag_head = commit.get("id") if isinstance(commit, dict) else None
            if tag_head and tag_head != head:
                raise ReleaseError("release-tag-conflicts-with-head")
        release_path = f"{base}/releases/tags/{quote(version, safe='')}"
        release_status, release = request("GET", release_path, token)
        if release_status not in (200, 404):
            raise ReleaseError("release-read-failed")
        if release_status == 200:
            if not isinstance(release, dict) or not isinstance(release.get("id"), int):
                raise ReleaseError("release-id-missing")
            verify(token, assets(token, release["id"]), artifact, sidecar, expected)
            return {"schema":SCHEMA, "operation":OPERATION,
                    "repository":f"forgejo:{OWNER}/{REPO}",
                    "artifact":artifact, "sidecar":sidecar,
                    "release_url":release_url, "source_head":head,
                    "outcome":"verified-no-op", "status":"no-op",
                    "ok":True, "changed":False, "version":version,
                    "tag":version, "sha256":expected, "payload_files":len(names)}
        status, created = request("POST", f"{base}/releases", token, body={
            "tag_name":version, "target_commitish":head, "name":version,
            "body":f"sbin shipped payload {version}", "draft":False, "prerelease":False})
        if status not in (200, 201) or not isinstance(created, dict):
            raise ReleaseError("release-create-failed")
        release_id = created.get("id")
        if not isinstance(release_id, int):
            raise ReleaseError("release-id-missing")
        upload = f"{base}/releases/{release_id}/assets"
        for name, data in ((artifact, archive.read_bytes()), (sidecar, sidecar_bytes)):
            status, _ = request("POST", upload, token, data=data, query={"name":name})
            if status not in (200, 201):
                raise ReleaseError("release-asset-upload-failed")
        verify(token, assets(token, release_id), artifact, sidecar, expected)
        return {"schema":SCHEMA, "operation":OPERATION,
                "repository":f"forgejo:{OWNER}/{REPO}",
                "artifact":artifact, "sidecar":sidecar,
                "release_url":release_url, "source_head":head,
                "outcome":"published", "status":"published",
                "ok":True, "changed":True, "version":version,
                "tag":version, "sha256":expected, "payload_files":len(names)}

def main() -> int:
    try:
        receipt = publish(Path(__file__).resolve().parents[1])
    except (OSError, ReleaseError) as exc:
        receipt = {"status":"error", "ok":False, "changed":False, "error":str(exc)}
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0 if receipt["ok"] else 1

if __name__ == "__main__":
    sys.exit(main())

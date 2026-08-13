"""Narrow appliance source-map splice actuator.

Fulcrum alone composes a catalog and overlay.  This actuator accepts only the
already-finished Harmonia-managed map, validates the bytes at its privileged
boundary, and replaces only the top-level ``sources`` value in the fixed device
certificate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit

SCHEMA = "homeserver.device-profile.v1"
CERTIFICATE_PATH = "/etc/appliance/profile.json"
SOURCE_MAP_PATH = "/etc/caduceus/source-map.json"
COMPONENT = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
CREDENTIAL_MARKERS = ("password", "passwd", "secret", "token", "private-key", "private_key")
SECRET_PREFIXES = ("ghp_", "github_pat_", "glpat-", "xox", "akia")


class SourceMapError(ValueError):
    pass


def _root() -> Path:
    return Path(os.environ.get("CADUCEUS_ROOT", "/"))


def _path(absolute: str) -> Path:
    return _root() / absolute.lstrip("/")


def certificate_path() -> Path:
    return _path(CERTIFICATE_PATH)


def source_map_path() -> Path:
    return _path(SOURCE_MAP_PATH)


def _reject_credentials(value: Any, *, field: str = "sources") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise SourceMapError("source-map-key-invalid")
            lowered = key.lower()
            if any(marker in lowered for marker in CREDENTIAL_MARKERS):
                if key != "credential_selector":
                    raise SourceMapError("source-map-credential-material-forbidden")
            _reject_credentials(child, field=key)
    elif isinstance(value, list):
        for child in value:
            _reject_credentials(child, field=field)
    elif isinstance(value, str):
        lowered = value.lower()
        if any(marker in lowered for marker in CREDENTIAL_MARKERS) or lowered.startswith(SECRET_PREFIXES):
            raise SourceMapError("source-map-credential-material-forbidden")


def _git_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SourceMapError("source-map-git-url-required")
    url = value.strip()
    if url.startswith("git@"):
        host_path = url[4:]
        if ":" not in host_path or any(part in {"", ".", ".."} for part in host_path.split(":", 1)):
            raise SourceMapError("source-map-git-url-invalid")
        return url
    parsed = urlsplit(url)
    permitted_username = parsed.scheme == "ssh" and parsed.username == "git"
    if (
        parsed.scheme not in {"http", "https", "ssh"}
        or not parsed.netloc
        or (parsed.username and not permitted_username)
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise SourceMapError("source-map-git-url-invalid")
    return url


def _local_path(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
        raise SourceMapError("source-map-local-checkout-path-invalid")
    path = Path(value)
    if ".." in path.parts:
        raise SourceMapError("source-map-local-checkout-path-invalid")
    return value


def validate_source_map(value: Any) -> dict[str, Any]:
    """Validate a completed map without merging, augmenting, or composing it."""
    _reject_credentials(value)
    if not isinstance(value, dict) or not value:
        raise SourceMapError("source-map-required")
    result: dict[str, Any] = {}
    for component, entry in value.items():
        if not isinstance(component, str) or not COMPONENT.fullmatch(component):
            raise SourceMapError("source-map-component-invalid")
        if not isinstance(entry, dict) or set(entry) != {"ref", "candidates"}:
            raise SourceMapError("source-map-entry-invalid")
        ref = entry.get("ref")
        candidates = entry.get("candidates")
        if not isinstance(ref, str) or not ref.strip():
            raise SourceMapError("source-map-ref-required")
        if not isinstance(candidates, list) or not candidates:
            raise SourceMapError("source-map-candidates-required")
        rendered_candidates: list[dict[str, str]] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                raise SourceMapError("source-map-candidate-invalid")
            kind = candidate.get("kind")
            if kind == "git":
                if set(candidate) not in ({"kind", "url"}, {"kind", "url", "credential_selector"}):
                    raise SourceMapError("source-map-candidate-invalid")
                rendered: dict[str, str] = {"kind": "git", "url": _git_url(candidate.get("url"))}
                selector = candidate.get("credential_selector")
                if selector is not None:
                    if not isinstance(selector, str) or not selector.strip():
                        raise SourceMapError("source-map-selector-required")
                    rendered["credential_selector"] = selector
                rendered_candidates.append(rendered)
            elif kind == "local-checkout":
                if set(candidate) != {"kind", "path"}:
                    raise SourceMapError("source-map-candidate-invalid")
                rendered_candidates.append({"kind": "local-checkout", "path": _local_path(candidate.get("path"))})
            else:
                raise SourceMapError("source-map-candidate-kind-invalid")
        result[component] = {"ref": ref, "candidates": rendered_candidates}
    return dict(sorted(result.items()))


def _source_span(raw: str) -> tuple[int, int] | None:
    try:
        certificate = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SourceMapError("certificate-json-invalid") from exc
    if not isinstance(certificate, dict):
        raise SourceMapError("certificate-must-be-object")
    if certificate.get("schema") != SCHEMA:
        raise SourceMapError("certificate-schema-invalid")
    decoder = json.JSONDecoder()
    position, length = 0, len(raw)

    def skip_ws(index: int) -> int:
        while index < length and raw[index].isspace():
            index += 1
        return index

    position = skip_ws(position)
    if position >= length or raw[position] != "{":
        raise SourceMapError("certificate-must-be-object")
    position += 1
    found: tuple[int, int] | None = None
    while True:
        position = skip_ws(position)
        if position >= length:
            raise SourceMapError("certificate-json-invalid")
        if raw[position] == "}":
            break
        try:
            key, key_end = decoder.raw_decode(raw, position)
        except json.JSONDecodeError as exc:
            raise SourceMapError("certificate-json-invalid") from exc
        if not isinstance(key, str):
            raise SourceMapError("certificate-key-invalid")
        position = skip_ws(key_end)
        if position >= length or raw[position] != ":":
            raise SourceMapError("certificate-json-invalid")
        value_start = skip_ws(position + 1)
        try:
            _, value_end = decoder.raw_decode(raw, value_start)
        except json.JSONDecodeError as exc:
            raise SourceMapError("certificate-json-invalid") from exc
        if key == "sources":
            if found is not None:
                raise SourceMapError("certificate-sources-duplicate")
            found = (value_start, value_end)
        position = skip_ws(value_end)
        if position >= length:
            raise SourceMapError("certificate-json-invalid")
        if raw[position] == "}":
            break
        if raw[position] != ",":
            raise SourceMapError("certificate-json-invalid")
        position += 1
    return found


def non_sources_bytes(raw: str) -> bytes:
    """The byte comparison seam used by fixture proof; never exposed in receipts."""
    span = _source_span(raw)
    if span is None:
        return raw.encode("utf-8")
    start, end = span
    return (raw[:start] + raw[end:]).encode("utf-8")


def splice_sources(raw: str, sources: dict[str, Any]) -> tuple[str, bool, bool]:
    span = _source_span(raw)
    rendered = json.dumps(sources, indent=2, sort_keys=True)
    if span is not None:
        start, end = span
        updated = raw[:start] + rendered + raw[end:]
        return updated, updated != raw, True

    # The scanner above has already established that this is one JSON object.
    # Insert a new member without reserializing any existing member bytes.
    close = raw.rfind("}")
    if close < 0:
        raise SourceMapError("certificate-json-invalid")
    before_close = raw[:close]
    inner = before_close[before_close.find("{") + 1 :]
    if not inner.strip():
        insertion = f'\n  "sources": {rendered}\n'
    else:
        separator = ",\n  " if "\n" in inner else ", "
        insertion = f'{separator}"sources": {rendered}'
    updated = raw[:close] + insertion + raw[close:]
    return updated, True, False


def _receipt(*, ok: bool, changed: bool, signal: str, **fields: Any) -> dict[str, Any]:
    return {
        "schema": "caduceus.profile.sources.reseed.v1",
        "ok": ok,
        "changed": changed,
        "certificatePath": CERTIFICATE_PATH,
        "sourceMapPath": SOURCE_MAP_PATH,
        "writer": "caduceus_staff.source_map",
        "firstMissingSignal": signal,
        **fields,
    }


def reseed() -> dict[str, Any]:
    certificate = certificate_path()
    source_map = source_map_path()
    try:
        raw_map = source_map.read_text(encoding="utf-8")
        sources = validate_source_map(json.loads(raw_map))
        raw_certificate = certificate.read_text(encoding="utf-8")
        updated, changed, sources_were_present = splice_sources(raw_certificate, sources)
    except (OSError, json.JSONDecodeError, SourceMapError) as exc:
        return _receipt(ok=False, changed=False, signal=f"caduceus-source-map-reseed-{exc}")

    before_sha256 = hashlib.sha256(raw_certificate.encode("utf-8")).hexdigest()
    after_sha256 = hashlib.sha256(updated.encode("utf-8")).hexdigest()
    common = {
        "components": sorted(sources),
        "sourcesWerePresent": sources_were_present,
        "preservedNonSourcesBytes": True,
        "beforeSha256": before_sha256,
        "afterSha256": after_sha256,
        "mode": "0444",
        "owner": "root:root" if os.geteuid() == 0 else "unprivileged-test",
    }
    if not changed:
        return _receipt(ok=True, changed=False, signal="none", **common)

    temporary: str | None = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".profile.json.", dir=certificate.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(updated)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o444)
        if os.geteuid() == 0:
            os.chown(temporary, 0, 0)
        os.replace(temporary, certificate)
        directory_fd = os.open(certificate.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        return _receipt(ok=False, changed=False, signal=f"caduceus-source-map-reseed-write-failed: {exc}", **common)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
    return _receipt(ok=True, changed=True, signal="none", **common)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-profile-sources-reseed")
    parser.add_argument("command", choices=["reseed"])
    args = parser.parse_args(argv)
    value = reseed() if args.command == "reseed" else _receipt(ok=False, changed=False, signal="caduceus-source-map-command-invalid")
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Privileged Hestia Anchor household certificate primitives.

The nine public primitives are deliberately independently callable.  This module
is the sole Python writer of its disposable-root certificate, proxy and state
surfaces; ``state_commit`` is the sole durable-state writer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "caduceus.household.tls.v1"
PLATFORMS = {"windows", "android", "chromeos", "linux", "macos"}
CSR_MAX_BYTES = 64 * 1024
BUNDLE_METADATA = {
    platform: {
        "filename": f"homeserver-house-ca-{platform}{'.cer' if platform == 'windows' else '.crt'}",
        "mime_type": "application/x-x509-ca-cert",
        "encoding": "der" if platform == "windows" else "pem",
    }
    for platform in PLATFORMS
}


def _root() -> Path:
    return Path(os.environ.get("CADUCEUS_ROOT", "/"))


def _path(env: str, absolute: str) -> Path:
    override = os.environ.get(env)
    return Path(override) if override else _root() / absolute.lstrip("/")


def cert_dir() -> Path:
    return _path("CADUCEUS_CERT_DIR", "/var/lib/caduceus/certs")


def state_path() -> Path:
    return _path("CADUCEUS_STATE_PATH", "/var/lib/caduceus/state.json")


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True)


def _fingerprint(path: Path, encoding: str = "pem") -> str:
    command = ["openssl", "x509"]
    if encoding == "der":
        command.extend(["-inform", "DER"])
    command.extend(["-in", str(path), "-noout", "-fingerprint", "-sha256"])
    return _run(command).stdout.strip().split("=", 1)[-1]


def _not_after(path: Path) -> str:
    return _run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"]).stdout.strip().removeprefix("notAfter=")


def _profile() -> str:
    path = _path("CADUCEUS_PROFILE_PATH", "/etc/caduceus/profile.yaml")
    if path.is_file():
        for line in path.read_text().splitlines():
            if line.startswith("profile:"):
                return line.split(":", 1)[1].strip()
    return os.environ.get("CADUCEUS_PROFILE", "homeserver")


def _csr_identity() -> tuple[str, list[str]]:
    """Read this body's CSR claim from its appliance declaration."""
    profile: dict[str, Any] = {}
    path = _path("CADUCEUS_APPLIANCE_PROFILE_PATH", "/etc/appliance/profile.json")
    if path.is_file():
        try:
            value = json.loads(path.read_text())
            if isinstance(value, dict):
                profile = value
        except (OSError, json.JSONDecodeError):
            pass

    identity = next(
        (
            value.strip()
            for key in ("fqdn", "hostname")
            if isinstance(value := profile.get(key), str) and value.strip()
        ),
        "",
    )
    if not identity:
        hostname = _path("CADUCEUS_HOSTNAME_PATH", "/etc/hostname")
        if hostname.is_file():
            identity = hostname.read_text().strip()
    if not identity:
        identity = socket.getfqdn().strip()

    ip = next(
        (
            value.strip()
            for key in ("ip", "ip_address", "lan_ip")
            if isinstance(value := profile.get(key), str) and value.strip()
        ),
        "",
    )
    return identity, [ip] if ip else []


def _generation() -> int:
    path = state_path()
    if not path.is_file():
        return 0
    try:
        return int(json.loads(path.read_text()).get(SCHEMA, {}).get("generation", 0))
    except (json.JSONDecodeError, ValueError, TypeError):
        return 0


def _receipt(primitive: str, *, changed: bool, dry_run: bool = False, ok: bool = True, **fields: Any) -> dict[str, Any]:
    return {
        "schema": f"caduceus.staff.house_ca.{primitive}.v1",
        "ok": ok,
        "primitive": primitive,
        "role": _profile(),
        "changed": changed,
        "dry_run": dry_run,
        "state_generation": fields.pop("state_generation", _generation()),
        "client_reinstall_required": False,
        "firstMissingSignal": "none" if ok else fields.pop("firstMissingSignal", "agathodaimon-house-ca-refused"),
        **fields,
    }


def _refusal(primitive: str, signal: str, **fields: Any) -> dict[str, Any]:
    return _receipt(primitive, changed=False, ok=False, firstMissingSignal=signal, **fields)


def _root_valid(ca: Path, key: Path) -> bool:
    try:
        _run(["openssl", "x509", "-in", str(ca), "-noout"])
        _run(["openssl", "pkey", "-in", str(key), "-noout"])
        ca_pub = _run(["openssl", "x509", "-in", str(ca), "-pubkey", "-noout"]).stdout
        key_pub = _run(["openssl", "pkey", "-in", str(key), "-pubout"]).stdout
        basic = _run(["openssl", "x509", "-in", str(ca), "-noout", "-text"]).stdout
        return ca_pub == key_pub and "CA:TRUE" in basic
    except subprocess.CalledProcessError:
        return False


def _make_root(directory: Path, ca: Path, key: Path) -> None:
    with tempfile.NamedTemporaryFile("w", dir=directory, delete=False) as stream:
        stream.write("[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n[dn]\nO=HomeServer\nCN=HomeServer House CA\n[ca]\nbasicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n")
        config = Path(stream.name)
    temporary_key = directory / ".ca.key.pem.new"
    temporary_ca = directory / ".ca.pem.new"
    try:
        _run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(temporary_key), "-out", str(temporary_ca), "-days", "3650", "-sha256", "-config", str(config)])
        temporary_key.chmod(0o600)
        temporary_ca.chmod(0o644)
        os.replace(temporary_key, key)
        os.replace(temporary_ca, ca)
    finally:
        config.unlink(missing_ok=True)
        temporary_key.unlink(missing_ok=True)
        temporary_ca.unlink(missing_ok=True)


def ensure_root(*, dry_run: bool = False, renewal_authority: str | None = None) -> dict[str, Any]:
    """Converge a valid stable root; replacement needs explicit renewal authority."""
    directory = cert_dir()
    ca = directory / "ca.pem"
    key = directory / "ca.key.pem"
    exists = ca.exists() or key.exists()
    valid = ca.is_file() and key.is_file() and _root_valid(ca, key)
    if valid:
        return _receipt("ensure_root", changed=False, dry_run=dry_run, ca_fingerprint=_fingerprint(ca), ca_not_after=_not_after(ca), proof="existing-valid-ring")
    if exists and not renewal_authority:
        raise RuntimeError("agathodaimon-house-ca-ring-replacement-refused")
    if dry_run:
        plan = ["renew-house-root"] if exists else ["create-house-root"]
        return _receipt("ensure_root", changed=False, dry_run=True, renewal_authority=bool(renewal_authority), plan=plan)
    directory.mkdir(parents=True, exist_ok=True)
    _make_root(directory, ca, key)
    return _receipt("ensure_root", changed=True, renewed=exists, ca_fingerprint=_fingerprint(ca), ca_not_after=_not_after(ca), proof="root-readback")


def rotate_ca(understood: bool) -> dict[str, Any]:
    """Preserve the sbin-only explicit CA rotation capability."""
    if not understood:
        return _refusal("rotate_ca", "agathodaimon-house-ca-rotate-confirmation-required", message="Pass --i-understand-clients-reinstall to rotate the house CA.")
    directory = cert_dir()
    directory.mkdir(parents=True, exist_ok=True)
    ca, key = directory / "ca.pem", directory / "ca.key.pem"
    before = _fingerprint(ca) if ca.is_file() else None
    old_ca, old_key = directory / ".ca.pem.previous", directory / ".ca.key.pem.previous"
    old_ca.unlink(missing_ok=True); old_key.unlink(missing_ok=True)
    if ca.exists(): os.replace(ca, old_ca)
    if key.exists(): os.replace(key, old_key)
    try:
        _make_root(directory, ca, key)
        leaf = issue_leaf()
    except Exception:
        ca.unlink(missing_ok=True); key.unlink(missing_ok=True)
        if old_ca.exists(): os.replace(old_ca, ca)
        if old_key.exists(): os.replace(old_key, key)
        raise
    old_ca.unlink(missing_ok=True); old_key.unlink(missing_ok=True)
    receipt = _receipt("rotate_ca", changed=True, ca_fingerprint_before=before, ca_fingerprint=_fingerprint(ca), leaf_fingerprint=leaf["leaf_fingerprint"], proof="root-and-leaf-readback")
    receipt["client_reinstall_required"] = True
    return receipt


def _split_sans(values: Sequence[str]) -> tuple[list[str], list[str]]:
    dns, ips = [], []
    for value in values:
        value = value.strip()
        if not value:
            continue
        try:
            ips.append(str(ipaddress.ip_address(value)))
        except ValueError:
            if any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-*._" for char in value):
                raise ValueError("agathodaimon-cert-san-invalid")
            dns.append(value.lower())
    return list(dict.fromkeys(dns)), list(dict.fromkeys(ips))


def _bundle_fingerprint_if_present() -> str | None:
    bundle = _bundle_path("linux")
    if not bundle.is_file():
        return None
    return _fingerprint(bundle)


def issue_leaf(identity: str = "home.arpa", dns_names: Sequence[str] = (), ip_addresses: Sequence[str] = (), *, dry_run: bool = False) -> dict[str, Any]:
    root = ensure_root(dry_run=dry_run)
    dns, ips = _split_sans([identity, *dns_names, *ip_addresses])
    bundle_before = _bundle_fingerprint_if_present()
    if dry_run:
        return _receipt("issue_leaf", changed=False, dry_run=True, identity=identity, sans=dns + ips, ca_fingerprint=root.get("ca_fingerprint"), bundle_fingerprint=bundle_before, plan=["ensure_root", "issue-leaf"])
    directory = cert_dir()
    safe = identity.replace("*", "wildcard").replace("/", "_")
    leaf = directory / f"{safe}.pem"
    key = directory / f"{safe}.key.pem"
    csr = directory / f"{safe}.csr.pem"
    alt = [*(f"DNS.{index}={value}" for index, value in enumerate(dns, 1)), *(f"IP.{index}={value}" for index, value in enumerate(ips, 1))]
    config = directory / f".{safe}.cnf"
    config.write_text("[req]\nprompt=no\ndistinguished_name=dn\nreq_extensions=ext\n[dn]\nO=HomeServer\nCN=" + identity + "\n[ext]\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=@alt\n[alt]\n" + "\n".join(alt) + "\n")
    try:
        _run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-config", str(config)])
        _run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(directory / "ca.pem"), "-CAkey", str(directory / "ca.key.pem"), "-CAcreateserial", "-out", str(leaf), "-days", "824", "-sha256", "-extfile", str(config), "-extensions", "ext"])
        _run(["openssl", "verify", "-CAfile", str(directory / "ca.pem"), str(leaf)])
    finally:
        csr.unlink(missing_ok=True)
        config.unlink(missing_ok=True)
    key.chmod(0o600)
    leaf.chmod(0o644)
    bundle_after = _bundle_fingerprint_if_present()
    if bundle_before != bundle_after:
        raise RuntimeError("agathodaimon-cert-bundle-changed-by-leaf")
    return _receipt("issue_leaf", changed=True, identity=identity, sans=dns + ips, ca_fingerprint=_fingerprint(directory / "ca.pem"), leaf_fingerprint=_fingerprint(leaf), leaf_not_after=_not_after(leaf), bundle_fingerprint=bundle_after, bundle_preserved=True, proof="leaf-chain-verified")


def _csr_sans(text: str) -> list[str]:
    marker = "X509v3 Subject Alternative Name:"
    try:
        start = text.splitlines().index(next(line for line in text.splitlines() if marker in line)) + 1
    except (StopIteration, ValueError):
        raise ValueError("agathodaimon-cert-csr-san-missing") from None
    sans: list[str] = []
    for line in text.splitlines()[start:]:
        line = line.strip()
        if not line or line.startswith("Signature Algorithm"):
            break
        if line.startswith("DNS:") or line.startswith("IP Address:"):
            sans.extend(item.strip().lower() for item in line.split(","))
    if not sans:
        raise ValueError("agathodaimon-cert-csr-san-missing")
    return sans


def sign_csr(csr_pem: Any) -> dict[str, Any]:
    """Auxiliary CSR signer; household private material remains in staff custody."""
    if not isinstance(csr_pem, str) or len(csr_pem.encode()) > CSR_MAX_BYTES:
        raise ValueError("agathodaimon-cert-csr-too-large")
    if "PRIVATE KEY" in csr_pem or any(ord(char) < 32 and char not in "\n\t" for char in csr_pem):
        raise ValueError("agathodaimon-cert-csr-private-key-or-control")
    identity, declared_ips = _csr_identity()
    dns, ips = _split_sans([identity, *declared_ips])
    requested = [*(f"dns:{name}" for name in dns), *(f"ip address:{ip}" for ip in ips)]
    directory = cert_dir()
    if not (directory / "ca.pem").is_file() or not (directory / "ca.key.pem").is_file():
        raise RuntimeError("agathodaimon-house-ca-unavailable")
    with tempfile.TemporaryDirectory(dir=directory) as temporary:
        csr, leaf, config = Path(temporary) / "request.pem", Path(temporary) / "leaf.pem", Path(temporary) / "sign.cnf"
        csr.write_text(csr_pem)
        try:
            verified = _run(["openssl", "req", "-in", str(csr), "-noout", "-verify", "-subject", "-text", "-nameopt", "RFC2253"]).stdout
        except subprocess.CalledProcessError as error:
            raise ValueError("agathodaimon-cert-csr-invalid") from error
        subject = next((line.split("subject=", 1)[1] for line in verified.splitlines() if line.startswith("subject=")), "")
        if subject.lower() != f"cn={identity}":
            raise ValueError("agathodaimon-cert-csr-identity-mismatch")
        actual = _csr_sans(verified)
        if actual != requested or len(set(actual)) != len(actual):
            raise ValueError("agathodaimon-cert-csr-san-mismatch")
        config.write_text("[ext]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=" + ",".join(item.replace("dns:", "DNS:").replace("ip address:", "IP:") for item in requested) + "\n")
        _run(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(directory / "ca.pem"), "-CAkey", str(directory / "ca.key.pem"), "-CAcreateserial", "-out", str(leaf), "-days", "824", "-sha256", "-extfile", str(config), "-extensions", "ext"])
        _run(["openssl", "verify", "-CAfile", str(directory / "ca.pem"), str(leaf)])
        return _receipt("csr_sign", changed=True, identity=identity, sans=dns + ips, leaf_pem=leaf.read_text(), ca_pem=(directory / "ca.pem").read_text(), ca_fingerprint=_fingerprint(directory / "ca.pem"), leaf_fingerprint=_fingerprint(leaf), leaf_expiry=_not_after(leaf), proof="csr-chain-verified")


def _bundle_metadata(platform: str) -> dict[str, str]:
    try:
        return BUNDLE_METADATA[platform]
    except (KeyError, TypeError):
        raise ValueError("agathodaimon-cert-platform-invalid") from None


def _bundle_path(platform: str) -> Path:
    return _path("CADUCEUS_CERT_BUNDLE_DIR", "/var/lib/caduceus/certs/bundles") / _bundle_metadata(platform)["filename"]


def _assert_ca_only(path: Path, encoding: str = "pem") -> str:
    content = path.read_bytes()
    if b"PRIVATE KEY" in content:
        raise RuntimeError("agathodaimon-cert-private-key-leaked")
    command = ["openssl", "x509"]
    if encoding == "der":
        command.extend(["-inform", "DER"])
    command.extend(["-in", str(path), "-noout", "-text"])
    text = _run(command).stdout
    if "CA:TRUE" not in text:
        raise ValueError("agathodaimon-cert-bundle-not-ca")
    return _fingerprint(path, encoding)


def bundle_export(platform: str = "linux", *, dry_run: bool = False) -> dict[str, Any]:
    metadata = _bundle_metadata(platform)
    root = ensure_root(dry_run=dry_run)
    out = _bundle_path(platform)
    if dry_run:
        return _receipt("bundle_export", changed=False, dry_run=True, platform=platform, ca_fingerprint=root.get("ca_fingerprint"), plan=["verify-root-ca", "export-ca-only"])
    source = cert_dir() / "ca.pem"
    fingerprint = _assert_ca_only(source)
    out.parent.mkdir(parents=True, exist_ok=True)
    if metadata["encoding"] == "der":
        _run(["openssl", "x509", "-in", str(source), "-outform", "DER", "-out", str(out)])
    else:
        shutil.copyfile(source, out)
    exported = _assert_ca_only(out, metadata["encoding"])
    if exported != fingerprint:
        raise RuntimeError("agathodaimon-cert-bundle-fingerprint-mismatch")
    out.chmod(0o644)
    return _receipt("bundle_export", changed=True, platform=platform, path=str(out), ca_fingerprint=fingerprint, bundle_fingerprint=exported, ca_only=True, proof="openssl-ca-readback")


def bundle_read(platform: str) -> dict[str, Any]:
    """Auxiliary public bundle reader."""
    metadata = _bundle_metadata(platform)
    bundle = _bundle_path(platform)
    if not bundle.is_file():
        raise ValueError("agathodaimon-cert-bundle-missing")
    fingerprint = _assert_ca_only(bundle, metadata["encoding"])
    return _receipt("bundle_read", changed=False, platform=platform, filename=metadata["filename"], mime_type=metadata["mime_type"], fingerprint=fingerprint, content_base64=base64.b64encode(bundle.read_bytes()).decode("ascii"), proof="ca-only-readback")


def _expected_root_fingerprint() -> str:
    ca = cert_dir() / "ca.pem"
    if ca.is_file():
        return _assert_ca_only(ca)
    path = state_path()
    if path.is_file():
        value = json.loads(path.read_text()).get(SCHEMA, {}).get("root_fingerprint")
        if isinstance(value, str) and value:
            return value
    raise RuntimeError("agathodaimon-house-ca-root-fingerprint-missing")


def trust_install(bundle: str, platform: str = "linux", *, dry_run: bool = False) -> dict[str, Any]:
    metadata = _bundle_metadata(platform)
    source = Path(bundle)
    if not source.is_file():
        raise ValueError("agathodaimon-cert-bundle-missing")
    supplied = _assert_ca_only(source, metadata["encoding"])
    expected = _expected_root_fingerprint()
    if supplied != expected:
        raise ValueError("agathodaimon-cert-bundle-fingerprint-mismatch")
    store = _path("CADUCEUS_TRUST_STORE", "/usr/local/share/ca-certificates")
    target = store / "homeserver-house-ca.crt"
    already = target.is_file() and _assert_ca_only(target) == expected
    if dry_run:
        return _receipt("trust_install", changed=False, dry_run=True, platform=platform, ca_fingerprint=expected, bundle_installed=already, plan=["verify-bundle-structure", "verify-root-fingerprint", "trust-store-readback"])
    if not already:
        store.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".new")
        shutil.copyfile(source, temporary)
        temporary.chmod(0o644)
        os.replace(temporary, target)
    installed = target.is_file() and _assert_ca_only(target) == expected
    if not installed:
        raise RuntimeError("agathodaimon-cert-trust-store-readback-failed")
    committed = state_commit({"root_fingerprint": expected, "bundle_installed": True})
    return _receipt("trust_install", changed=not already, platform=platform, ca_fingerprint=expected, bundle_installed=True, state_generation=committed["state_generation"], state_commit=committed, proof="trust-store-readback")


def apply_nginx(portal: str, upstream: str, certificate: str, key_path: str, *, dry_run: bool = False) -> dict[str, Any]:
    if not portal or not upstream.startswith(("http://", "https://")):
        raise ValueError("agathodaimon-nginx-input-invalid")
    directory = _path("CADUCEUS_NGINX_DIR", "/etc/nginx/conf.d")
    target = directory / f"agathodaimon-{portal.replace('.', '-')}.conf"
    body = f"server {{ listen 443 ssl; server_name {portal}; ssl_certificate {certificate}; ssl_certificate_key {key_path}; location / {{ proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_pass {upstream}; }} }}\n"
    same = target.is_file() and target.read_text() == body
    if dry_run:
        return _receipt("apply_nginx", changed=False, dry_run=True, portal=portal, plan=["stage-nginx", "validate-nginx", "activate-nginx"])
    if not same:
        directory.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(body)
        os.replace(temporary, target)
    return _receipt("apply_nginx", changed=not same, portal=portal, proof="nginx-config-readback")


def constituent_lock(portal: str, lan_ip: str, *, dry_run: bool = False) -> dict[str, Any]:
    ip = str(ipaddress.ip_address(lan_ip))
    if not portal:
        raise ValueError("agathodaimon-constituent-portal-invalid")
    # V1 declares the adapter plan but does not pretend DHCP/DNS mutation occurred.
    return _receipt("constituent_lock", changed=False, dry_run=dry_run, portal=portal, lan_ip=ip, dhcp_dns_applied=False, plan=["reserve-dhcp", "bind-dns"], proof="declared-constituent-plan")


def _validated_state(transition: dict[str, Any], old: dict[str, Any]) -> dict[str, Any]:
    profile = _profile()
    portals = transition.get("portals", old.get("portals", []))
    constituents = transition.get("constituents", old.get("constituents", []))
    if profile != "homeserver" and (portals or constituents):
        raise ValueError("agathodaimon-state-role-inventory-refused")
    if not isinstance(portals, list) or not isinstance(constituents, list):
        raise ValueError("agathodaimon-state-shape-invalid")
    return {
        "profile": profile,
        "root_fingerprint": transition.get("root_fingerprint", old.get("root_fingerprint")),
        "bundle_installed": bool(transition.get("bundle_installed", old.get("bundle_installed", False))),
        "portals": portals if profile == "homeserver" else [],
        "constituents": constituents if profile == "homeserver" else [],
        "generation": int(old.get("generation", 0)) + 1,
    }


def state_commit(transition: dict[str, Any], *, dry_run: bool = False) -> dict[str, Any]:
    if not isinstance(transition, dict):
        raise ValueError("agathodaimon-state-transition-invalid")
    path = state_path()
    existing: dict[str, Any] = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text())
        except json.JSONDecodeError as error:
            raise ValueError("agathodaimon-state-invalid") from error
    old = existing.get(SCHEMA, {})
    value = _validated_state(transition, old)
    if dry_run:
        return _receipt("state_commit", changed=False, dry_run=True, state_generation=old.get("generation", 0), next_generation=value["generation"], plan=["atomic-state-replace"])
    existing[SCHEMA] = value
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".state.")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(existing, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)
    return _receipt("state_commit", changed=True, state_generation=value["generation"], proof="atomic-state-readback")


def portal_admit(portal: str, lan_ip: str, upstream: str, aliases: Sequence[str] = (), *, dry_run: bool = False) -> dict[str, Any]:
    if _profile() != "homeserver":
        return _refusal("portal_admit", "agathodaimon-portal-admit-profile-refused", portal=portal, failed_child="profile-gate")
    children: list[dict[str, Any]] = []
    try:
        locked = constituent_lock(portal, lan_ip, dry_run=dry_run)
        children.append(locked)
        leaf = issue_leaf(portal, aliases, [lan_ip], dry_run=dry_run)
        children.append(leaf)
        applied = apply_nginx(portal, upstream, str(cert_dir() / f"{portal}.pem"), str(cert_dir() / f"{portal}.key.pem"), dry_run=dry_run)
        children.append(applied)
        transition = {"root_fingerprint": leaf.get("ca_fingerprint"), "portals": [{"fqdn": portal, "lan_ip": lan_ip, "upstream": upstream}], "constituents": [{"identity": portal, "lan_ip": lan_ip}]}
        committed = state_commit(transition, dry_run=dry_run)
        children.append(committed)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        failed = ("constituent_lock", "issue_leaf", "apply_nginx", "state_commit")[len(children)] if len(children) < 4 else "state_commit"
        return _refusal("portal_admit", "agathodaimon-portal-child-failed", portal=portal, failed_child=failed, held_generation=_generation(), children=children)
    generation = committed.get("state_generation", _generation())
    return _receipt("portal_admit", changed=not dry_run, dry_run=dry_run, portal=portal, generation=generation, state_generation=generation, children=children, proof="four-child-composition")


def status() -> dict[str, Any]:
    ca, path, role = cert_dir() / "ca.pem", state_path(), _profile()
    value = _receipt("status", changed=False, profile=role, root_present=ca.is_file(), bundle_installed=False, portals=[], constituents=[])
    if ca.is_file():
        value.update(ca_fingerprint=_fingerprint(ca), ca_not_after=_not_after(ca))
    ledger: dict[str, Any] = {}
    if path.is_file():
        ledger = json.loads(path.read_text()).get(SCHEMA, {})
        value.update(bundle_installed=ledger.get("bundle_installed", False), state_generation=ledger.get("generation", 0))
        if not ca.is_file() and isinstance(ledger.get("root_fingerprint"), str):
            value["ca_fingerprint"] = ledger["root_fingerprint"]
        if role == "homeserver":
            value["portals"] = ledger.get("portals", [])
            value["constituents"] = ledger.get("constituents", [])
    if role != "homeserver" and not ledger:
        target = _path("CADUCEUS_TRUST_STORE", "/usr/local/share/ca-certificates") / "homeserver-house-ca.crt"
        try:
            value["bundle_installed"] = target.is_file() and bool(_assert_ca_only(target))
        except (OSError, ValueError, subprocess.CalledProcessError):
            value["bundle_installed"] = False
    return value


def _emit(call) -> int:
    try:
        value = call()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError):
        value = _refusal("error", "agathodaimon-house-ca-refused")
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1


def _json_stdin() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (json.JSONDecodeError, TypeError) as error:
        raise ValueError("agathodaimon-house-ca-request-invalid") from error
    if not isinstance(value, dict):
        raise ValueError("agathodaimon-house-ca-request-invalid")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agathodaimon-house-ca")
    sub = parser.add_subparsers(dest="cmd", required=True)
    root = sub.add_parser("ensure-root"); root.add_argument("--dry-run", action="store_true"); root.add_argument("--renewal-authority")
    sub.add_parser("status")
    issue = sub.add_parser("issue-leaf"); issue.add_argument("identity", nargs="?", default="home.arpa"); issue.add_argument("--sans", default=""); issue.add_argument("--ips", default=""); issue.add_argument("--dry-run", action="store_true")
    rotate = sub.add_parser("rotate-ca"); rotate.add_argument("--i-understand-clients-reinstall", action="store_true")
    sub.add_parser("sign-csr")
    legacy_bundle = sub.add_parser("bundle"); legacy_bundle.add_argument("platform", nargs="?", default="linux", choices=sorted(PLATFORMS))
    bundle = sub.add_parser("bundle-export"); bundle.add_argument("platform", choices=sorted(PLATFORMS)); bundle.add_argument("--dry-run", action="store_true")
    reader = sub.add_parser("bundle-read"); reader.add_argument("platform", choices=sorted(PLATFORMS))
    trust = sub.add_parser("trust-install"); trust.add_argument("bundle"); trust.add_argument("--platform", default="linux", choices=sorted(PLATFORMS)); trust.add_argument("--dry-run", action="store_true")
    apply = sub.add_parser("apply-nginx"); apply.add_argument("portal"); apply.add_argument("upstream"); apply.add_argument("certificate"); apply.add_argument("key_path"); apply.add_argument("--dry-run", action="store_true")
    lock = sub.add_parser("constituent-lock"); lock.add_argument("portal"); lock.add_argument("lan_ip"); lock.add_argument("--dry-run", action="store_true")
    commit = sub.add_parser("state-commit"); commit.add_argument("--dry-run", action="store_true")
    admit = sub.add_parser("portal-admit"); admit.add_argument("portal"); admit.add_argument("lan_ip"); admit.add_argument("upstream"); admit.add_argument("--aliases", default=""); admit.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    if args.cmd == "ensure-root": return _emit(lambda: ensure_root(dry_run=args.dry_run, renewal_authority=args.renewal_authority))
    if args.cmd == "status": return _emit(status)
    if args.cmd == "issue-leaf": return _emit(lambda: issue_leaf(args.identity, args.sans.split(",") if args.sans else (), args.ips.split(",") if args.ips else (), dry_run=args.dry_run))
    if args.cmd == "rotate-ca": return _emit(lambda: rotate_ca(args.i_understand_clients_reinstall))
    if args.cmd == "sign-csr": return _emit(lambda: sign_csr(_json_stdin().get("csrPem")))
    if args.cmd == "bundle": return _emit(lambda: bundle_export(args.platform))
    if args.cmd == "bundle-export": return _emit(lambda: bundle_export(args.platform, dry_run=args.dry_run))
    if args.cmd == "bundle-read": return _emit(lambda: bundle_read(args.platform))
    if args.cmd == "trust-install": return _emit(lambda: trust_install(args.bundle, args.platform, dry_run=args.dry_run))
    if args.cmd == "apply-nginx": return _emit(lambda: apply_nginx(args.portal, args.upstream, args.certificate, args.key_path, dry_run=args.dry_run))
    if args.cmd == "constituent-lock": return _emit(lambda: constituent_lock(args.portal, args.lan_ip, dry_run=args.dry_run))
    if args.cmd == "state-commit": return _emit(lambda: state_commit(_json_stdin(), dry_run=args.dry_run))
    if args.cmd == "portal-admit": return _emit(lambda: portal_admit(args.portal, args.lan_ip, args.upstream, args.aliases.split(",") if args.aliases else (), dry_run=args.dry_run))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

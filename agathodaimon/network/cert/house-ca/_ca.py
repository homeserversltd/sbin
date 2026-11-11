"""Privileged Hestia Anchor household certificate primitives.

The nine public primitives are deliberately independently callable.  This module
is the sole Python writer of its disposable-root certificate, proxy and state
surfaces; ``state_commit`` is the sole durable-state writer.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
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


@contextlib.contextmanager
def house_ca_lock():
    """One house-ca mutation at a time, locked on the state directory itself (no new file)."""
    directory = state_path().parent
    directory.mkdir(parents=True, exist_ok=True)
    fd = os.open(directory, os.O_RDONLY)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("agathodaimon-house-ca-busy") from error
        yield
    finally:
        os.close(fd)


def _run(command: list[str], timeout=None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, capture_output=True, timeout=timeout)


def _fingerprint(path: Path, encoding: str = "pem") -> str:
    command = ["openssl", "x509"]
    if encoding == "der":
        command.extend(["-inform", "DER"])
    command.extend(["-in", str(path), "-noout", "-fingerprint", "-sha256"])
    return _run(command).stdout.strip().split("=", 1)[-1]


def _not_after(path: Path) -> str:
    return _run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"]).stdout.strip().removeprefix("notAfter=")


def _profile() -> str:
    path = _path("CADUCEUS_APPLIANCE_PROFILE_PATH", "/etc/appliance/profile.json")
    try:
        profile = json.loads(path.read_text())
        if isinstance(profile, dict):
            value = profile.get("profile")
            if isinstance(value, str) and value.strip():
                return value.strip()
    except (OSError, UnicodeError, json.JSONDecodeError):
        pass
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
    except (OSError, json.JSONDecodeError, ValueError, TypeError, AttributeError):
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
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
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
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
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


def _assert_trust_install_ca_only(path: Path, encoding: str = "pem") -> str:
    """Validate the whole trust-install PEM, not just OpenSSL's first cert."""
    if encoding == "pem":
        content = path.read_bytes()
        if b"PRIVATE KEY" in content:
            raise RuntimeError("agathodaimon-cert-private-key-leaked")
        stripped = content.strip()
        begin = b"-----BEGIN CERTIFICATE-----"
        end = b"-----END CERTIFICATE-----"
        if (
            stripped.count(begin) != 1
            or stripped.count(end) != 1
            or not stripped.startswith(begin)
            or not stripped.endswith(end)
        ):
            raise ValueError("agathodaimon-cert-bundle-not-single-ca")
        encoded = b"".join(stripped[len(begin):-len(end)].split())
        if not encoded:
            raise ValueError("agathodaimon-cert-bundle-not-single-ca")
        try:
            base64.b64decode(encoded, validate=True)
        except ValueError:
            raise ValueError("agathodaimon-cert-bundle-not-single-ca") from None
    return _assert_ca_only(path, encoding)


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


def _trust_store_layout() -> tuple[bool, Path, Path]:
    """Return rooted platform detection, anchor directory, and system bundle."""
    root = _root()
    arch_anchors = root / "etc/ca-certificates/trust-source/anchors"
    arch = arch_anchors.is_dir()
    override = os.environ.get("CADUCEUS_TRUST_STORE")
    store = Path(override) if override else (
        arch_anchors if arch else root / "usr/local/share/ca-certificates"
    )
    bundle_override = os.environ.get("CADUCEUS_SYSTEM_CA_BUNDLE")
    if bundle_override:
        system_bundle = Path(bundle_override)
    else:
        system_bundle = root / "etc/ssl/certs/ca-certificates.crt"
        arch_extracted = root / "etc/ca-certificates/extracted/tls-ca-bundle.pem"
        if arch and not system_bundle.is_file() and arch_extracted.is_file():
            system_bundle = arch_extracted
    return arch, store, system_bundle


def _browser_bridge(arch: bool) -> tuple[str, Path | None]:
    """Read the NSS module and p11-kit in this body's filesystem."""
    root = _root()
    directories = [root / "usr/lib"] if arch else sorted((root / "usr/lib").glob("*-linux-gnu"))
    for directory in directories:
        module = directory / "libnssckbi.so"
        trust = directory / "pkcs11/p11-kit-trust.so"
        if not trust.is_file():
            continue
        if module.is_symlink():
            link = os.readlink(module)
            destination = root / link.lstrip("/") if link.startswith("/") else module.parent / link
            if destination.resolve() == trust.resolve():
                return "bridged", module
        if module.is_file() and not module.is_symlink():
            return "unbridged", module
        return "unbridged", module
    return "unsupported", None


def _bridge_browser(module: Path) -> tuple[int | None, bool]:
    """Divert only NSS's built-in module, then install the relative bridge."""
    root = _root()
    rooted = root.resolve() != Path("/")
    logical = "/" + str(module.relative_to(root)).lstrip("/") if rooted else str(module)
    executable = shutil.which("dpkg-divert")
    if not executable:
        for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
            candidate = Path(directory) / "dpkg-divert"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                executable = str(candidate)
                break
    if not executable:
        return None, False
    command = [executable]
    if rooted:
        command.extend(["--root", str(root)])
    if module.is_symlink():
        try:
            owner = subprocess.run(
                [*command, "--listpackage", logical],
                check=False, text=True, capture_output=True,
            )
            if owner.returncode != 0 or owner.stdout.strip() != "homeserver-house-trust":
                return owner.returncode or 1, False
            temporary = module.with_name(f".{module.name}.{os.urandom(16).hex()}.new")
            temporary.symlink_to("pkcs11/p11-kit-trust.so")
            try:
                os.replace(temporary, module)
            finally:
                temporary.unlink(missing_ok=True)
            return 0, True
        except OSError:
            return None, False
    command.extend(["--package", "homeserver-house-trust", "--divert", logical + ".distrib", "--rename", logical])
    diverted = False
    try:
        result = subprocess.run(command, check=False, text=True, capture_output=True)
        if result.returncode != 0:
            return result.returncode, False
        diverted = True
        module.symlink_to("pkcs11/p11-kit-trust.so")
        return 0, True
    except OSError:
        return None, diverted


def _trust_refresh_command(arch: bool, store: Path) -> tuple[str, list[str], str | None]:
    """Resolve a safe refresher, preferring PATH shims for rooted witnesses."""
    root = _root()
    rooted = root.resolve() != Path("/").resolve()
    program = "update-ca-trust" if arch else "update-ca-certificates"
    arguments: list[str] = ["extract"] if arch else []
    if not arch:
        if rooted:
            arguments.extend(["--sysroot", str(root)])
        default_store = root / "usr/local/share/ca-certificates"
        if rooted or store != default_store:
            arguments.extend(["--localcertsdir", str(store)])

    executable = shutil.which(program)
    if executable:
        resolved = Path(executable).resolve()
        host_tool_dirs = {Path(path).resolve() for path in ("/usr/bin", "/usr/sbin", "/bin", "/sbin")}
        # Arch's updater has no portable sysroot mode.  A rooted run must use
        # the explicitly supplied PATH stand-in, never the host updater.
        if arch and rooted and resolved.parent in host_tool_dirs:
            executable = None
        else:
            executable = str(resolved)
    if not executable and (not (arch and rooted)):
        for directory in ("/usr/sbin", "/usr/bin", "/sbin", "/bin"):
            candidate = Path(directory) / program
            if candidate.is_file() and os.access(candidate, os.X_OK):
                executable = str(candidate)
                break
    command = [executable or program, *arguments]
    return program, command, executable


def _trust_bundle_readback(system_bundle: Path, anchor: Path) -> bool:
    try:
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", str(system_bundle), str(anchor)],
            check=False,
            text=True,
            capture_output=True,
        )
    except OSError:
        return False
    return result.returncode == 0


def _trust_file_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except OSError:
        return None


def _trust_refusal(signal: str, *, changed: bool = False, **fields: Any) -> dict[str, Any]:
    return _receipt(
        "trust_install", changed=changed, ok=False,
        firstMissingSignal=signal, proof="trust-install-refusal", **fields,
    )


def trust_install(
    bundle: str,
    platform: str = "linux",
    *,
    dry_run: bool = False,
    fingerprint: str | None = None,
    renew_ring: bool = False,
) -> dict[str, Any]:
    """Install a CA-only first-contact bundle into this platform's trust store."""
    metadata = _bundle_metadata(platform)
    source = Path(bundle)
    if not source.is_file():
        return _trust_refusal(
            "agathodaimon-cert-bundle-missing", platform=platform,
            reason="bundle-missing", bundle_installed=False,
        )
    try:
        supplied = _assert_trust_install_ca_only(source, metadata["encoding"])
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        return _trust_refusal(
            str(error) or "agathodaimon-cert-bundle-invalid", platform=platform,
            reason="bundle-invalid", bundle_fingerprint=None, bundle_installed=False,
        )

    # The caller's fingerprint attests to the bundle; it is not authority to
    # replace a root already pinned by this body's ca.pem or durable ledger.
    if fingerprint is not None and fingerprint != supplied:
        return _trust_refusal(
            "agathodaimon-cert-bundle-fingerprint-mismatch", platform=platform,
            reason="caller-fingerprint-mismatch", pin_decision="caller-fingerprint",
            supplied_fingerprint=supplied, caller_fingerprint=fingerprint,
            bundle_installed=False,
        )

    ca = cert_dir() / "ca.pem"
    local_pin: str | None = None
    if ca.is_file():
        try:
            local_pin = _assert_ca_only(ca)
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            return _trust_refusal(
                str(error) or "agathodaimon-house-ca-root-invalid", platform=platform,
                reason="local-root-invalid", pin_decision="local-ca.pem",
                supplied_fingerprint=supplied, bundle_installed=False,
            )

    state = state_path()
    existing: dict[str, Any] = {}
    if state.is_file():
        try:
            loaded = json.loads(state.read_text())
        except (OSError, json.JSONDecodeError) as error:
            return _trust_refusal(
                "agathodaimon-state-invalid", platform=platform,
                reason="ledger-invalid", supplied_fingerprint=supplied,
                bundle_installed=False, detail=str(error),
            )
        if not isinstance(loaded, dict):
            return _trust_refusal(
                "agathodaimon-state-invalid", platform=platform,
                reason="ledger-invalid", supplied_fingerprint=supplied,
                bundle_installed=False,
            )
        existing = loaded
    ledger = existing.get(SCHEMA, {})
    if not isinstance(ledger, dict):
        return _trust_refusal(
            "agathodaimon-state-invalid", platform=platform,
            reason="ledger-invalid", supplied_fingerprint=supplied,
            bundle_installed=False,
        )
    ledger_pin = ledger.get("root_fingerprint")
    if ledger_pin is not None and ledger_pin != "" and not isinstance(ledger_pin, str):
        return _trust_refusal(
            "agathodaimon-state-invalid", platform=platform,
            reason="ledger-invalid", supplied_fingerprint=supplied,
            bundle_installed=False,
        )
    if not ledger_pin:
        ledger_pin = None

    pin_sources = [
        name for name, value in (("local-ca.pem", local_pin), ("state-ledger", ledger_pin))
        if value is not None
    ]
    pin_decision = "+".join(pin_sources) or (
        "caller-fingerprint" if fingerprint is not None else "missing"
    )
    if local_pin is not None and supplied != local_pin:
        return _trust_refusal(
            "agathodaimon-cert-bundle-fingerprint-mismatch", platform=platform,
            reason="local-root-pinned", pin_decision=pin_decision,
            pin_sources=pin_sources, ca_fingerprint=local_pin,
            bundle_fingerprint=supplied, bundle_installed=False,
        )
    if local_pin is None and ledger_pin is None and fingerprint is None:
        return _trust_refusal(
            "agathodaimon-house-ca-root-fingerprint-missing", platform=platform,
            reason="pin-missing", pin_decision="missing", pin_sources=[],
            bundle_fingerprint=supplied, bundle_installed=False,
        )

    ring_changed = ledger_pin is not None and supplied != ledger_pin
    if ring_changed and not renew_ring:
        return _trust_refusal(
            "bundle_refused", platform=platform, reason="ring-changed",
            pin_decision=pin_decision, pin_sources=pin_sources,
            ca_fingerprint=ledger_pin, bundle_fingerprint=supplied,
            bundle_installed=False,
        )

    if local_pin is not None:
        pin_decision = "local-ca.pem" + ("+state-ledger" if ledger_pin else "")
    elif ledger_pin is not None:
        pin_decision = "state-ledger"
    else:
        pin_decision = "caller-fingerprint"
    first_contact = local_pin is None and ledger_pin is None
    reason = "renewed" if ring_changed and renew_ring else (
        "first-contact" if first_contact else "converged"
    )
    root_fingerprint = supplied

    arch, store, system_bundle = _trust_store_layout()
    target = store / "homeserver-house-ca.crt"
    try:
        anchor_fingerprint = _assert_ca_only(target) if target.is_file() else None
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        anchor_fingerprint = None
    anchor_current = anchor_fingerprint == root_fingerprint
    store_current = anchor_current and _trust_bundle_readback(system_bundle, target)
    state_current = (
        ledger_pin == root_fingerprint and ledger.get("bundle_installed") is True
    )
    program, refresh_command, executable = _trust_refresh_command(arch, store)
    refresh_needed = not store_current
    bridge_before, bridge_module = _browser_bridge(arch)
    bridge_enabled = _profile() != "homeserver"
    already_current = state_current and anchor_current and store_current and not ring_changed and (not bridge_enabled or bridge_before == "bridged")
    if already_current:
        reason = "already-current"

    if dry_run:
        return _receipt(
            "trust_install", changed=False, dry_run=True, platform=platform,
            ca_fingerprint=root_fingerprint, bundle_fingerprint=supplied,
            bundle_installed=store_current, reason=reason,
            pin_decision=pin_decision, pin_sources=pin_sources,
            anchor_path=str(target), system_bundle=str(system_bundle),
            refresh_program=program, refresh_command=refresh_command,
            refresh_available=executable is not None,
            would_write_anchor=not anchor_current,
            would_refresh=refresh_needed,
            would_commit_state=not state_current,
            would_bridge=bridge_enabled and bridge_before == "unbridged" and not arch,
            plan=["validate-ca-only-bundle", "resolve-root-pin", "install-platform-anchor", "refresh-system-trust", "verify-system-bundle", "record-root-state", "bridge-browser-trust"],
            proof="trust-install-plan-only",
        )

    try:
        # Validate the prospective state transition before changing the anchor.
        _validated_state(
            {"root_fingerprint": root_fingerprint, "bundle_installed": True},
            ledger,
        )
    except (ValueError, TypeError, RuntimeError) as error:
        return _trust_refusal(
            str(error) or "agathodaimon-state-invalid", platform=platform,
            reason="ledger-transition-refused", pin_decision=pin_decision,
            pin_sources=pin_sources, ca_fingerprint=root_fingerprint,
            bundle_installed=False,
        )

    if refresh_needed and executable is None:
        return _trust_refusal(
            "agathodaimon-cert-trust-store-refresh-failed", platform=platform,
            reason=reason, pin_decision=pin_decision, pin_sources=pin_sources,
            ca_fingerprint=root_fingerprint, bundle_installed=False,
            anchor_path=str(target), system_bundle=str(system_bundle),
            store_refresh={"program": program, "exit": None, "command": refresh_command, "error": "program-not-found"},
        )

    anchor_changed = False
    if not anchor_current:
        store_existed = store.exists()
        try:
            store.mkdir(parents=True, exist_ok=True)
            anchor_changed = not store_existed
            with tempfile.NamedTemporaryFile(dir=store, prefix=".homeserver-house-ca.", suffix=".new", delete=False) as stream:
                temporary = Path(stream.name)
            try:
                if metadata["encoding"] == "der":
                    _run(["openssl", "x509", "-inform", "DER", "-in", str(source), "-out", str(temporary)])
                else:
                    shutil.copyfile(source, temporary)
                temporary.chmod(0o644)
                if _assert_ca_only(temporary) != root_fingerprint:
                    raise RuntimeError("agathodaimon-cert-bundle-fingerprint-mismatch")
                os.replace(temporary, target)
                anchor_changed = True
            finally:
                temporary.unlink(missing_ok=True)
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
            return _trust_refusal(
                str(error) or "agathodaimon-cert-trust-store-write-failed",
                changed=anchor_changed or (not store_existed and store.exists()), platform=platform, reason=reason,
                pin_decision=pin_decision, pin_sources=pin_sources,
                ca_fingerprint=root_fingerprint, bundle_installed=False,
                anchor_path=str(target), system_bundle=str(system_bundle),
            )

    store_refresh: dict[str, Any] = {
        "program": program, "exit": None, "command": refresh_command,
        "attempted": False,
    }
    system_before = _trust_file_bytes(system_bundle)
    if refresh_needed:
        store_refresh["attempted"] = True
        try:
            refreshed = subprocess.run(
                refresh_command, check=False, text=True, capture_output=True,
            )
            store_refresh["exit"] = refreshed.returncode
        except OSError as error:
            store_refresh["error"] = str(error)
        system_bundle = _trust_store_layout()[2]
        system_after = _trust_file_bytes(system_bundle)
        changed = anchor_changed or system_before != system_after
        if store_refresh["exit"] != 0:
            return _trust_refusal(
                "agathodaimon-cert-trust-store-refresh-failed", changed=changed,
                platform=platform, reason=reason, pin_decision=pin_decision,
                pin_sources=pin_sources, ca_fingerprint=root_fingerprint,
                bundle_installed=False, anchor_path=str(target),
                system_bundle=str(system_bundle), store_refresh=store_refresh,
            )
    else:
        system_after = system_before

    try:
        installed_fingerprint = _assert_ca_only(target) if target.is_file() else None
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        installed_fingerprint = None
    verified = (
        installed_fingerprint == root_fingerprint
        and _trust_bundle_readback(system_bundle, target)
    )
    if not verified:
        return _trust_refusal(
            "agathodaimon-cert-trust-store-readback-failed",
            changed=anchor_changed or system_before != system_after,
            platform=platform, reason=reason, pin_decision=pin_decision,
            pin_sources=pin_sources, ca_fingerprint=root_fingerprint,
            bundle_installed=False, anchor_path=str(target),
            system_bundle=str(system_bundle), store_refresh=store_refresh,
        )

    committed: dict[str, Any] | None = None
    if not state_current:
        try:
            committed = state_commit(
                {"root_fingerprint": root_fingerprint, "bundle_installed": True}
            )
        except (OSError, ValueError, RuntimeError, TypeError) as error:
            return _trust_refusal(
                str(error) or "agathodaimon-state-commit-failed",
                changed=anchor_changed or system_before != system_after,
                platform=platform, reason=reason, pin_decision=pin_decision,
                pin_sources=pin_sources, ca_fingerprint=root_fingerprint,
                bundle_installed=True, anchor_path=str(target),
                system_bundle=str(system_bundle), store_refresh=store_refresh,
            )

    changed = anchor_changed or system_before != system_after or committed is not None
    bridge = {"state_before": bridge_before, "attempted": False, "exit": None}
    if bridge_enabled:
        if bridge_before == "unsupported":
            return _trust_refusal(
                "agathodaimon-cert-browser-bridge-unsupported", changed=changed,
                platform=platform, reason=reason, ca_fingerprint=root_fingerprint,
                bundle_fingerprint=supplied, bundle_installed=True,
                browser_trust="unsupported", bridge=bridge, state_commit=committed,
            )
        if bridge_before == "unbridged":
            bridge["attempted"] = not arch and bridge_module is not None
            if not arch and bridge_module is not None:
                bridge["exit"], bridge_changed = _bridge_browser(bridge_module)
                changed = changed or bridge_changed
            if bridge["exit"] != 0 or _browser_bridge(arch)[0] != "bridged":
                return _trust_refusal(
                    "agathodaimon-cert-browser-bridge-failed", changed=changed,
                    platform=platform, reason=reason, ca_fingerprint=root_fingerprint,
                    bundle_fingerprint=supplied, bundle_installed=True,
                    browser_trust=False, bridge=bridge, state_commit=committed,
                )
    return _receipt(
        "trust_install", changed=changed, platform=platform,
        ca_fingerprint=root_fingerprint, bundle_fingerprint=supplied,
        bundle_installed=True, reason=reason, pin_decision=pin_decision,
        pin_sources=pin_sources, anchor_path=str(target),
        system_bundle=str(system_bundle), store_refresh=store_refresh,
        state_generation=(committed["state_generation"] if committed else _generation()),
        state_commit=committed, browser_trust=True if bridge_enabled else None,
        bridge=bridge, proof="anchor-and-system-bundle-readback",
    )


def _nginx_safe(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and not re.search(r'[\s;{}"\'\\]', value)


def _route_options(upstream: Any, tailnet_port: Any, locations: Any, *, primitive: bool = True) -> tuple[int | None, list[dict[str, Any]] | None]:
    if primitive and (not _nginx_safe(upstream) or not upstream.startswith(("http://", "https://"))):
        raise ValueError("agathodaimon-nginx-input-invalid")
    if not primitive and upstream is not None:
        raise ValueError("agathodaimon-nginx-input-invalid")
    if tailnet_port is not None:
        if type(tailnet_port) is int:
            pass
        elif isinstance(tailnet_port, str) and re.fullmatch(r"[0-9]+", tailnet_port):
            tailnet_port = int(tailnet_port)
        else:
            raise ValueError("agathodaimon-nginx-input-invalid")
        if not 1 <= tailnet_port <= 65535:
            raise ValueError("agathodaimon-nginx-input-invalid")
    if locations is not None:
        if not isinstance(locations, list):
            raise ValueError("agathodaimon-nginx-input-invalid")
        paths = {"/"}
        for loc in locations:
            if (not isinstance(loc, dict) or not _nginx_safe(loc.get("path"))
                    or not re.match(r"^(?:=|\^~)?/", loc["path"]) or not _nginx_safe(loc.get("upstream"))
                    or not loc["upstream"].startswith(("http://", "https://"))
                    or type(loc.get("strip_authorization", False)) is not bool
                    or loc["path"] in paths):
                raise ValueError("agathodaimon-nginx-input-invalid")
            paths.add(loc["path"])
    return tailnet_port, locations


def _tailnet_name() -> str:
    try:
        executable = shutil.which("tailscale")
        if not executable:
            raise ValueError()
        result = _run([executable, "status", "--json"], timeout=30)
        name = json.loads(result.stdout)["Self"]["DNSName"]
        if not isinstance(name, str):
            raise ValueError()
        name = name.rstrip(".")
        dns, ips = _split_sans([name])
        if not name or ips or dns != [name.lower()]:
            raise ValueError()
        return dns[0]
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        raise ValueError("agathodaimon-portal-tailnet-name-unavailable") from None


HESTIA_HTTP = """map $http_upgrade $connection_upgrade { default upgrade; '' close; }
"""
HESTIA_TLS = """ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:HestiaSSL:10m;
ssl_session_timeout 10m;
"""
HESTIA_PROXY = """proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection $connection_upgrade;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_hide_header X-Powered-By;
"""


def _policy_options(max_body_size: Any, read_timeout: Any) -> dict[str, Any]:
    if not isinstance(max_body_size, str) or not re.fullmatch(r"[0-9]+[kKmMgG]?", max_body_size):
        raise ValueError("agathodaimon-nginx-input-invalid")

    def decimal(value: Any, lower: int, upper: int) -> int:
        if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
            value = int(value)
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError("agathodaimon-nginx-input-invalid")
        return value

    return {"max_body_size": max_body_size, "read_timeout": decimal(read_timeout, 1, 86400)}


def _nginx_location(path: str, upstream: str, proxy_include: Path, read_timeout: int, strip_authorization: bool = False) -> str:
    strip = ' proxy_set_header Authorization "";' if strip_authorization else ''
    if path.startswith("^~"):
        path = "^~ " + path[2:]
    elif path.startswith("="):
        path = "= " + path[1:]
    return (f'location {path} {{ include "{proxy_include}"; proxy_buffering off; '
            f'proxy_read_timeout {read_timeout}s;{strip} proxy_pass {upstream}; }}')


def _hestia_seat() -> dict[str, Any] | None:
    from agathodaimon._nidus.path import appliance_runtime_path
    seat_id = "hestia.portal.v1"
    try:
        data = json.loads((appliance_runtime_path("seats") / (seat_id + ".json")).read_text())
    except FileNotFoundError:
        return None
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("agathodaimon-hestia-seat-invalid") from error
    if not isinstance(data, dict) or data.get("schema") != seat_id:
        raise ValueError("agathodaimon-hestia-seat-foreign")
    return data


def _hestia_render(row: dict[str, Any], seat: dict[str, Any] | None,
                   files: dict[str, tuple[str, str]], snippets: Path,
                   certificate: str, key_path: str) -> str:
    """Compose one complete route from already-read inputs, with no effects."""
    if not _nginx_safe(certificate) or not _nginx_safe(key_path):
        raise ValueError("agathodaimon-nginx-input-invalid")
    templates = seat.get("templates", {}) if seat else {}
    template = row.get("template")
    if seat is None and template is not None:
        raise ValueError("agathodaimon-hestia-seat-absent")
    if seat is not None:
        template = template or seat.get("fields", {}).get("template", {}).get("default")
        spec = templates.get(template)
        if not isinstance(spec, dict):
            raise ValueError("agathodaimon-hestia-template-hole-unfilled:template")
    else:
        spec = {"primitive": True}
    primitive = bool(spec.get("primitive"))
    port, locations = _route_options(row.get("upstream"), row.get("tailnet_port"), row.get("locations"), primitive=primitive)
    policy = _policy_options(row.get("max_body_size", "1m"), row.get("read_timeout", 60))
    fqdn = row.get("fqdn")
    if not isinstance(fqdn, str):
        raise ValueError("agathodaimon-nginx-input-invalid")
    names, ips = _split_sans([fqdn, *row.get("aliases", [])])
    if ips or not names or names[0] != row.get("fqdn"):
        raise ValueError("agathodaimon-nginx-input-invalid")
    includes = []
    aliases = []
    exact_locations = {loc["path"][1:] for loc in locations or [] if loc["path"].startswith("=")}
    for note, definition in (seat.get("notes", {}) if seat else {}).items():
        field = definition.get("row_field", note.replace("-", "_"))
        value = row.get(field)
        if value is None or value is False or value == []:
            continue
        if definition.get("templates") and template not in definition["templates"]:
            raise ValueError("agathodaimon-hestia-note-refused:" + note)
        if definition.get("kind") == "include":
            key = definition.get("choices", {}).get(value) if definition.get("choices") else definition.get("file")
            if not key or key not in files:
                raise ValueError("agathodaimon-hestia-note-refused:" + note)
            includes.append(f'include "{files[key][0]}";')
        elif definition.get("kind") == "location" and field != "locations":
            if not isinstance(value, list):
                raise ValueError("agathodaimon-nginx-input-invalid")
            for item in value:
                if not isinstance(item, dict):
                    raise ValueError("agathodaimon-nginx-input-invalid")
                path, file = item.get("path"), item.get("file")
                if not _nginx_safe(path) or not path.startswith("/") or not _nginx_safe(file) or not file.startswith("/"):
                    raise ValueError("agathodaimon-nginx-input-invalid")
                if path in exact_locations:
                    raise ValueError("agathodaimon-nginx-input-invalid")
                exact_locations.add(path)
                aliases.append(f'location = {path} {{ alias {file}; add_header Cache-Control no-store; }}')
    locations_text = [_nginx_location(loc["path"], loc["upstream"], snippets / "proxy.conf", policy["read_timeout"], loc.get("strip_authorization", False)) for loc in locations or []]
    if primitive:
        template_body = _nginx_location('/', row["upstream"], snippets / "proxy.conf", policy["read_timeout"])
    else:
        key = spec.get("file")
        if key not in files:
            raise ValueError("agathodaimon-hestia-file-absent:" + str(key))
        template_body = files[key][1]
        for required in spec.get("requires", []):
            if row.get(required) is None or row.get(required) == "":
                raise ValueError("agathodaimon-hestia-template-hole-unfilled:" + required)
        for hole in spec.get("holes", []):
            value = row.get(hole, policy.get(hole))
            if value is None or value == "":
                raise ValueError("agathodaimon-hestia-template-hole-unfilled:" + hole)
            text = str(value)
            if not _nginx_safe(text):
                raise ValueError("agathodaimon-nginx-input-invalid")
            if hole == "root" and not text.startswith("/"):
                raise ValueError("agathodaimon-nginx-input-invalid")
            if hole == "fpm" and not text.startswith("unix:/"):
                match = re.fullmatch(r'(?:[A-Za-z0-9_.-]+|\[[A-Fa-f0-9:.]+\]):([0-9]{1,5})', text)
                if not match or not 1 <= int(match.group(1)) <= 65535:
                    raise ValueError("agathodaimon-nginx-input-invalid")
            template_body = template_body.replace("{{" + hole + "}}", text)
        missing = re.search(r"\{\{([^{}]+)\}\}", template_body)
        if missing:
            raise ValueError("agathodaimon-hestia-template-hole-unfilled:" + missing.group(1))
        template_body = template_body.rstrip()
    rendered = ' '.join([*includes, *aliases, *locations_text, template_body])
    shared = f'include "{snippets / "tls.conf"}"; client_max_body_size {policy["max_body_size"]};'
    common = f'ssl_certificate {certificate}; ssl_certificate_key {key_path}; {shared} {rendered}'
    result = f"server {{ listen 443 ssl; server_name {' '.join(names)}; {common} }}\n"
    if port is not None:
        result += f"server {{ listen *:{port} ssl; {common} }}\n"
    return result


def _hestia_inputs(row: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, tuple[str, str]]]:
    seat = _hestia_seat()
    if seat is None:
        return None, {}
    default = seat.get("fields", {}).get("template", {}).get("default")
    selected = row.get("template") or default
    spec = seat.get("templates", {}).get(selected, {})
    keys = [spec["file"]] if "file" in spec else []
    for name, note in seat.get("notes", {}).items():
        value = row.get(note.get("row_field", name.replace("-", "_")))
        if value is not None and value is not False and value != [] and note.get("templates") and selected not in note["templates"]:
            raise ValueError("agathodaimon-hestia-note-refused:" + name)
        if note.get("kind") == "include" and value is not None and value is not False:
            chosen = note.get("choices", {}).get(value) if note.get("choices") else note.get("file")
            if chosen:
                keys.append(chosen)
    root = seat.get("files_root")
    if not isinstance(root, str) or not _nginx_safe(root) or not root.startswith("/"):
        raise ValueError("agathodaimon-nginx-input-invalid")
    files = {}
    for name in keys:
        if not _nginx_safe(name) or name.startswith("/") or ".." in Path(name).parts:
            raise ValueError("agathodaimon-nginx-input-invalid")
        path = _root() / root.lstrip("/") / name
        try:
            files[name] = (str(path), path.read_text())
        except OSError:
            raise ValueError("agathodaimon-hestia-file-absent:" + str(path)) from None
    return seat, files


def _hestia_row(prior: dict[str, Any], supplied: dict[str, Any], seat: dict[str, Any] | None) -> dict[str, Any]:
    """Carry the whole row and lower seat-declared note values into it."""
    row = dict(prior)
    notes = seat.get("notes", {}) if seat else {}
    if not seat and any(value is not None for value in supplied.values()):
        raise ValueError("agathodaimon-hestia-seat-absent")
    for name, value in supplied.items():
        if value is None:
            continue
        if name == "template":
            row[name] = value
            continue
        spec = notes.get(name)
        if not isinstance(spec, dict):
            raise ValueError("unknown-field:" + name)
        if row.get("template") is None:
            row["template"] = seat.get("fields", {}).get("template", {}).get("default")
        field = spec.get("row_field", name.replace("-", "_"))
        if spec.get("kind") != "location":
            if seat.get("fields", {}).get(field, {}).get("type") == "boolean" and type(value) is not bool:
                raise ValueError("agathodaimon-nginx-input-invalid")
            row[field] = value
            continue
        values = value if isinstance(value, list) else [value]
        previous = list(row.get(field) or []) if field == "locations" else []
        for entry in values:
            if isinstance(entry, dict):
                previous.append(entry)
                continue
            if not isinstance(entry, str):
                raise ValueError("agathodaimon-nginx-input-invalid")
            at = entry.find("=", 1 if entry.startswith("=") else 0)
            if at < 1:
                raise ValueError("agathodaimon-nginx-input-invalid")
            left, right = entry[:at], entry[at + 1:]
            previous.append({"path": left, ("upstream" if field == "locations" else "file"): right})
        row[field] = previous
    return row


def apply_nginx(portal: str, upstream: str | None, certificate: str, key_path: str, aliases: Sequence[str] = (), *, tailnet_port: int | str | None = None, locations: list[dict[str, Any]] | None = None, max_body_size: Any = "1m", read_timeout: Any = 60, dry_run: bool = False, row: dict[str, Any] | None = None) -> dict[str, Any]:
    policy = _policy_options(max_body_size, read_timeout)
    if not portal:
        raise ValueError("agathodaimon-nginx-input-invalid")
    names, ips = _split_sans([portal, *aliases])
    if ips or not names or names[0] != portal:
        raise ValueError("agathodaimon-nginx-input-invalid")
    directory = _path("CADUCEUS_NGINX_DIR", "/etc/nginx/conf.d")
    snippets = _path("CADUCEUS_NGINX_SNIPPETS_DIR", "/etc/nginx/snippets/hestia")
    target = directory / f"agathodaimon-{portal.replace('.', '-')}.conf"
    legacy = directory / f"caduceus-{portal.replace('.', '-')}.conf"
    route_row = {**(row or {}), "fqdn": portal, "aliases": list(aliases), "upstream": upstream,
                 "tailnet_port": tailnet_port, "locations": locations, **policy}
    seat, files = _hestia_inputs(route_row)
    body = _hestia_render(route_row, seat, files, snippets, certificate, key_path)
    known_fields = set(seat.get("fields", {})) if seat else set()
    if seat:
        known_fields.update(note.get("row_field", name.replace("-", "_")) for name, note in seat.get("notes", {}).items())
    skipped_fields = sorted(set(route_row) - known_fields) if seat else []
    body_bytes = body.encode("utf-8")
    same = target.is_file() and target.read_bytes() == body_bytes
    legacy_present = legacy.is_file()
    if dry_run:
        return _receipt(
            "apply_nginx",
            changed=False,
            dry_run=True,
            portal=portal,
            aliases=names[1:],
            server_names=names,
            validated=False,
            reloaded=False,
            legacy_path=str(legacy),
            legacy_present=legacy_present,
            legacy_retired=False,
            legacy_remaining=legacy_present,
            replacement_written=False,
            plan=["stage-nginx", "validate-nginx", "activate-nginx"],
            commands=[["nginx", "-t"], ["systemctl", "reload", "nginx"]],
            hestia_seat="present" if seat else "absent",
            skipped_fields=skipped_fields,
        )

    from agathodaimon._nidus import write as nidus_write

    central = [(directory / "00-hestia-http.conf", HESTIA_HTTP.encode()),
               (snippets / "tls.conf", HESTIA_TLS.encode()),
               (snippets / "proxy.conf", HESTIA_PROXY.encode())]
    desired: list[tuple[Path, bytes | None]] = [*central, (target, body_bytes)]
    if legacy_present:
        desired.append((legacy, None))
    before = {path: path.read_bytes() if path.is_file() else None for path, _ in desired}
    directory.mkdir(parents=True, exist_ok=True)
    snippets.mkdir(parents=True, exist_ok=True)
    state: dict[str, Any] = {"validated": False, "rollback": False, "rollback_reloaded": False,
                             "validation_output": "", "reload_output": ""}

    def validate() -> None:
        try:
            result = _run(["nginx", "-t"], timeout=30)
            state["validation_output"] = (result.stdout + result.stderr).strip()
            state["validated"] = True
        except Exception:
            state["rollback"] = True
            raise

    def activate() -> None:
        rollback = state["rollback"] or not state["validated"]
        if rollback:
            # The shared writer calls reload even when a restore failed. Never
            # reload a mixture: first require every previous file byte back.
            if any((path.read_bytes() if path.is_file() else None) != old for path, old in before.items()):
                raise RuntimeError("agathodaimon-nginx-rollback-incomplete")
            if not state["validated"]:
                return
            _run(["nginx", "-t"], timeout=30)
        try:
            result = _run(["systemctl", "reload", "nginx"], timeout=30)
            if rollback:
                state["rollback_reloaded"] = True
            else:
                state["reload_output"] = (result.stdout + result.stderr).strip()
        except Exception:
            state["rollback"] = True
            raise

    def readback() -> None:
        try:
            if any((path.read_bytes() if path.is_file() else None) != payload for path, payload in desired):
                raise RuntimeError("agathodaimon-nginx-readback-failed")
            # Nidus does not run verify/reload for an unchanged edit.
            if not state["validated"]:
                validate()
                activate()
        except Exception:
            state["rollback"] = True
            raise

    replacement_written = not same
    central_written = [str(path) for path, payload in central if before[path] != payload]
    try:
        nidus_write.write([{"path": path, "candidate": payload} for path, payload in desired],
                          verify=validate, reload=activate, readback=readback)
    except nidus_write.WriteError as error:
        steps = error.parts["attempt"]["steps"]
        failures = [f'{row["path"]}: {row.get("error_type", "error")}' for row in steps
                    if row.get("step") == "restore" and row.get("outcome") == "failed"]
        restored = not failures
        rollback_errors = [str(item) for item in error.restore_errors]
        restore_error = "; ".join([*failures, *rollback_errors]) or None
        failed_phase = error.parts["final_receipt"]["firstMissingSignal"].removesuffix("-failed")
        stage = {"verify": "validate-nginx", "reload": "activate-nginx", "readback": "stage-nginx"}.get(failed_phase, "stage-nginx")
        cause = error.cause
        output = ((cause.stdout or "") + (cause.stderr or "")).strip() if isinstance(cause, subprocess.CalledProcessError) else str(cause)
        return _receipt(
            "apply_nginx", changed=not restored or (state["validated"] and not state["rollback_reloaded"]), ok=False, portal=portal,
            aliases=names[1:], server_names=names, validated=state["validated"],
            reloaded=False, restored=restored, restore_error=restore_error,
            rollback_reloaded=state["rollback_reloaded"],
            failed_step=stage, command_output=output,
            validation_output=state["validation_output"] if state["validated"] else output,
            firstMissingSignal=f"agathodaimon-nginx-{stage}-{'timeout' if isinstance(cause, subprocess.TimeoutExpired) else 'failed'}",
            legacy_path=str(legacy), legacy_present=legacy_present,
            legacy_retired=legacy_present and not legacy.is_file(),
            legacy_remaining=legacy.is_file(), replacement_written=replacement_written,
            central_written=central_written,
            hestia_seat="present" if seat else "absent", skipped_fields=skipped_fields,
            proof="nginx-activation-refused",
        )
    legacy_remaining = legacy.is_file()
    return _receipt(
        "apply_nginx",
        changed=replacement_written or legacy_present or bool(central_written),
        portal=portal,
        aliases=names[1:],
        server_names=names,
        validated=True,
        reloaded=True,
        validation_output=state["validation_output"],
        reload_output=state["reload_output"],
        legacy_path=str(legacy),
        legacy_present=legacy_present,
        legacy_retired=legacy_present and not legacy_remaining,
        legacy_remaining=legacy_remaining,
        replacement_written=replacement_written,
        central_written=central_written,
        hestia_seat="present" if seat else "absent",
        skipped_fields=skipped_fields,
        proof="nginx-validated-and-reloaded",
    )


def constituent_lock(portal: str, lan_ip: str, aliases: Sequence[str] = (), *, dry_run: bool = False) -> dict[str, Any]:
    from agathodaimon.network.dns._manager import DnsManager, create_alias

    ip = str(ipaddress.ip_address(lan_ip))
    names, ips = _split_sans([portal, *aliases])
    if ips or not names or names[0] != portal or not portal.endswith(".home.arpa"):
        raise ValueError("agathodaimon-constituent-portal-invalid")
    manager = DnsManager(
        root_config=_path("CADUCEUS_UNBOUND_CONFIG", "/etc/unbound/unbound.conf"),
        dropin_dir=_path("CADUCEUS_UNBOUND_DROPIN_DIR", "/etc/unbound/unbound.conf.d"),
        include_path=_path("CADUCEUS_UNBOUND_INCLUDE", "/etc/unbound/unbound.conf.d/agathodaimon-local-names.conf"),
    )
    dns_names = [name for name in names if name.endswith(".home.arpa")]
    labels = [name.removesuffix(".home.arpa") for name in dns_names]
    # Admit every label before the first mutation. The DNS adapter owns A-record
    # projection and live readback; never create a device or reverse record.
    for label in labels:
        manager._alias_name(label)
    results: list[dict[str, Any]] = []
    names_bound: list[str] = []
    failure: dict[str, Any] = {}
    if not dry_run:
        for name, label in zip(dns_names, labels):
            try:
                row = create_alias(label, "home", manager=manager)
            except Exception as error:
                row = {"mutationPerformed": False, "first_failing_boundary": str(error)}
            if not isinstance(row, dict):
                row = {"mutationPerformed": False, "first_failing_boundary": "dns-alias-result-invalid"}
            results.append(row)
            if row.get("state") not in ("applied", "noop"):
                failure = {
                    "ok": False,
                    "firstMissingSignal": "agathodaimon-constituent-dns-alias-failed",
                    "first_failing_boundary": row.get("first_failing_boundary", "dns-alias-result-state-invalid"),
                    "failed_name": name,
                }
                break
            names_bound.append(name)
    return _receipt(
        "constituent_lock", changed=any(row.get("mutationPerformed", False) for row in results),
        dry_run=dry_run, portal=portal, aliases=names[1:], lan_ip=ip,
        dns_target="home.arpa", dns_names=dns_names,
        names_bound=names_bound, dns_aliases=results,
        dhcp_dns_applied=not dry_run and not failure, dhcp_reservation_applied=False,
        dhcp_reservation="declared-only", plan=["reserve-dhcp-declared-only", "bind-dns"],
        proof="declared-constituent-plan" if dry_run else "dns-alias-refused" if failure else "dns-alias-live-readback",
        **failure,
    )


def _merge_inventory(previous: Any, incoming: Any, key: str) -> list[dict[str, Any]]:
    if not isinstance(previous, list) or not isinstance(incoming, list):
        raise ValueError("agathodaimon-state-shape-invalid")
    rows: dict[str, dict[str, Any]] = {}
    for row in [*previous, *incoming]:
        if not isinstance(row, dict) or not isinstance(row.get(key), str) or not row[key]:
            raise ValueError("agathodaimon-state-shape-invalid")
        rows[row[key]] = row
    return list(rows.values())


def _validated_state(transition: dict[str, Any], old: dict[str, Any]) -> dict[str, Any]:
    profile = _profile()
    portals = _merge_inventory(old.get("portals", []), transition.get("portals", []), "fqdn")
    constituents = _merge_inventory(old.get("constituents", []), transition.get("constituents", []), "identity")
    if profile != "homeserver" and (portals or constituents):
        raise ValueError("agathodaimon-state-role-inventory-refused")
    if not isinstance(portals, list) or not isinstance(constituents, list):
        raise ValueError("agathodaimon-state-shape-invalid")
    return {
        **old,
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
    _write_state(existing)
    return _receipt("state_commit", changed=True, state_generation=value["generation"], proof="atomic-state-readback")


def _write_state(existing: dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".state.")
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(existing, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def _portal_route_preflight(portal: str, upstream: str | None, tailnet_port: Any, locations: Any, max_body_size: Any = None, read_timeout: Any = None, notes: dict[str, Any] | None = None, aliases: Sequence[str] | None = None, require_tailnet_name: bool = True) -> tuple[dict[str, Any], str | None]:
    existing = json.loads(state_path().read_text()).get(SCHEMA, {}) if state_path().is_file() else {}
    prior = next((row for row in existing.get("portals", []) if row.get("fqdn") == portal), {})
    row = dict(prior)
    row["fqdn"] = portal
    row["upstream"] = upstream if upstream is not None else prior.get("upstream")
    row["aliases"] = aliases if aliases is not None else prior.get("aliases", [])
    row["tailnet_port"] = tailnet_port if tailnet_port is not None else prior.get("tailnet_port")
    row["locations"] = locations if locations is not None else prior.get("locations")
    supplied = {"max_body_size": max_body_size, "read_timeout": read_timeout}
    defaults = {"max_body_size": "1m", "read_timeout": 60}
    selected = {key: value if value is not None else prior.get(key, defaults[key]) for key, value in supplied.items()}
    row.update(_policy_options(**selected))
    seat = _hestia_seat()
    row = _hestia_row(row, notes or {}, seat)
    seat, files = _hestia_inputs(row)
    snippets = _path("CADUCEUS_NGINX_SNIPPETS_DIR", "/etc/nginx/snippets/hestia")
    _hestia_render(row, seat, files, snippets, str(cert_dir() / f"{portal}.pem"), str(cert_dir() / f"{portal}.key.pem"))
    if isinstance(row.get("tailnet_port"), str):
        row["tailnet_port"] = int(row["tailnet_port"])
    return row, _tailnet_name() if require_tailnet_name and row.get("tailnet_port") is not None else None


def portal_admit(portal: str, lan_ip: str, upstream: str | None, aliases: Sequence[str] | None = None, *, owner_mac: str | None = None, origin: str | None = None, claim_tiles: Sequence[str] = (), tailnet_port: Any = None, locations: Any = None, max_body_size: Any = None, read_timeout: Any = None, dry_run: bool = False, notes: dict[str, Any] | None = None) -> dict[str, Any]:
    if _profile() != "homeserver":
        return _refusal("portal_admit", "agathodaimon-portal-admit-profile-refused", portal=portal, failed_child="profile-gate")
    if owner_mac is not None and (not isinstance(owner_mac, str) or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", owner_mac)):
        raise ValueError("agathodaimon-portal-owner-invalid")
    if origin is not None and origin not in ("face", "tile"):
        raise ValueError("agathodaimon-portal-origin-invalid")
    existing = json.loads(state_path().read_text()).get(SCHEMA, {}) if state_path().is_file() else {}
    rows = existing.get("portals", [])
    prior = next((row for row in rows if row.get("fqdn") == portal), {})
    if owner_mac and prior.get("owner_mac") and prior["owner_mac"] != owner_mac:
        return _refusal("portal_admit", "agathodaimon-portal-owner-conflict", portal=portal)
    claim_requested = origin == "face" and bool(owner_mac)
    aliases = prior.get("aliases", []) if aliases is None else aliases
    if owner_mac is None:
        owner_mac = prior.get("owner_mac")
    if origin is None:
        origin = prior.get("origin")
    try:
        row, tailnet_name = _portal_route_preflight(portal, upstream, tailnet_port, locations, max_body_size, read_timeout, notes, aliases)
    except ValueError as error:
        return _refusal("portal_admit", str(error), portal=portal)
    children: list[dict[str, Any]] = []
    failed = "constituent_lock"
    try:
        locked = constituent_lock(portal, lan_ip, aliases, dry_run=dry_run)
        children.append(locked)
        if not locked.get("ok"):
            raise RuntimeError(locked["firstMissingSignal"])
        failed = "issue_leaf"
        leaf = issue_leaf(portal, [*aliases, *([tailnet_name] if tailnet_name else [])], [lan_ip], dry_run=dry_run)
        children.append(leaf)
        if not leaf.get("ok"):
            raise RuntimeError(leaf["firstMissingSignal"])
        failed = "apply_nginx"
        applied = apply_nginx(portal, row.get("upstream"), str(cert_dir() / f"{portal}.pem"), str(cert_dir() / f"{portal}.key.pem"), aliases, tailnet_port=row.get("tailnet_port"), locations=row.get("locations"), dry_run=dry_run, max_body_size=row["max_body_size"], read_timeout=row["read_timeout"], row=row)
        children.append(applied)
        if not applied.get("ok"):
            raise RuntimeError(applied["firstMissingSignal"])
        failed = "state_commit"
        row.update({"fqdn": portal, "aliases": applied["aliases"], "lan_ip": lan_ip})
        if row.get("upstream") is None:
            row.pop("upstream", None)
        if row.get("tailnet_port") is None:
            row.pop("tailnet_port", None)
        if row.get("locations") is None:
            row.pop("locations", None)
        if owner_mac is not None:
            row["owner_mac"] = owner_mac
        if origin is not None:
            row["origin"] = origin
        claims = []
        if claim_requested:
            for old in rows:
                if old.get("fqdn") != portal and old.get("lan_ip") == lan_ip and not old.get("owner_mac"):
                    claimed = {**old, "owner_mac": owner_mac}
                    if old.get("fqdn") in claim_tiles:
                        claimed["origin"] = "tile"
                    claims.append(claimed)
        transition = {"root_fingerprint": leaf.get("ca_fingerprint"), "portals": [*claims, row], "constituents": [{"identity": portal, "lan_ip": lan_ip}]}
        committed = state_commit(transition, dry_run=dry_run)
        children.append(committed)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        return _receipt("portal_admit", changed=any(child.get("changed", False) for child in children), dry_run=dry_run, ok=False, firstMissingSignal="agathodaimon-portal-child-failed", portal=portal, failed_child=failed, child_signal=str(error), held_generation=_generation(), children=children)
    generation = committed.get("state_generation", _generation())
    return _receipt("portal_admit", changed=not dry_run, dry_run=dry_run, portal=portal, generation=generation, state_generation=generation, children=children, hestia_seat=applied.get("hestia_seat"), skipped_fields=applied.get("skipped_fields", []), proof="four-child-composition")


def portal_retire(portal: str, owner_mac: str, *, dry_run: bool = False) -> dict[str, Any]:
    from agathodaimon.network.dns._manager import DnsManager

    if _profile() != "homeserver":
        return _refusal("portal_retire", "agathodaimon-portal-retire-refused", portal=portal, failed_child="profile-gate")
    existing = json.loads(state_path().read_text()) if state_path().is_file() else {}
    old = existing.get(SCHEMA, {})
    row = next((item for item in old.get("portals", []) if item.get("fqdn") == portal), None)
    if not row or not row.get("owner_mac") or not owner_mac or row["owner_mac"] != owner_mac or row.get("origin") != "tile":
        return _refusal("portal_retire", "agathodaimon-portal-retire-refused", portal=portal)
    names, ips = _split_sans([portal, *row.get("aliases", [])])
    if ips or not names or names[0] != portal or not portal.endswith(".home.arpa"):
        return _refusal("portal_retire", "agathodaimon-portal-retire-refused", portal=portal)
    manager = DnsManager(
        root_config=_path("CADUCEUS_UNBOUND_CONFIG", "/etc/unbound/unbound.conf"),
        dropin_dir=_path("CADUCEUS_UNBOUND_DROPIN_DIR", "/etc/unbound/unbound.conf.d"),
        include_path=_path("CADUCEUS_UNBOUND_INCLUDE", "/etc/unbound/unbound.conf.d/agathodaimon-local-names.conf"),
    )
    labels = [name.removesuffix(".home.arpa") for name in names if name.endswith(".home.arpa")]
    for label in labels:
        manager._alias_name(label)
    plan = ["nginx_withdraw", "dns_withdraw", "leaf_delete", "state_retire"]
    if dry_run:
        return _receipt("portal_retire", changed=False, dry_run=True, portal=portal, plan=plan)
    directory = _path("CADUCEUS_NGINX_DIR", "/etc/nginx/conf.d")
    vhost = directory / f"agathodaimon-{portal.replace('.', '-')}.conf"
    aside = directory / f".agathodaimon-{portal.replace('.', '-')}.retiring"
    leaves = [cert_dir() / f"{portal}.pem", cert_dir() / f"{portal}.key.pem"]
    children = []
    removed_labels = []
    leaf_preimages = {}
    vhost_preimage = None
    failed = "nginx_withdraw"
    try:
        if aside.exists():
            raise RuntimeError("agathodaimon-portal-retire-staging-exists")
        if vhost.exists():
            vhost_preimage = (vhost.read_bytes(), vhost.stat().st_mode & 0o777)
            os.replace(vhost, aside)
        _run(["nginx", "-t"], timeout=30)
        _run(["systemctl", "reload", "nginx"], timeout=30)
        children.append({"child": failed, "ok": True})
        failed = "dns_withdraw"
        for label in labels:
            # The shared DNS adapter also migrates gateway records and
            # reprojects other aliases.  Do not let retirement change either.
            records = manager._owned_records()
            migrated = manager._migrate_gateway_records(records)
            parts = manager._record_parts
            if list(map(parts, records)) != list(map(parts, migrated)):
                raise RuntimeError("agathodaimon-portal-dns-migration-required")
            _, gateway_before, gateway_after = manager._gateway_file_candidate()
            if gateway_before != gateway_after:
                raise RuntimeError("agathodaimon-portal-dns-migration-required")
            alias = manager._alias_name(label)
            canonical = manager.canonical_name("home")
            was_bound = manager._alias_bindings(records).get(alias) == canonical
            retained = [line for line in records if not (was_bound and parts(line)[0] == alias)]
            previous_targets = {parts(line)[0] for line in records if parts(line)[1] == "A" and parts(line)[3] is None} | manager._alias_bindings(records).keys()
            current_targets = {parts(line)[0] for line in retained if parts(line)[1] == "A" and parts(line)[3] is None} | manager._alias_bindings(retained).keys()
            projected = manager._project_aliases(retained, removed_targets=previous_targets - current_targets)
            if manager._render_owned(projected) != manager._render_owned(retained):
                raise RuntimeError("agathodaimon-portal-dns-reprojection-required")
            result = manager.remove_alias(label, "home")
            if result.get("state") not in ("applied", "noop"):
                raise RuntimeError("agathodaimon-portal-dns-withdraw-failed")
            if was_bound:
                removed_labels.append(label)
        children.append({"child": failed, "ok": True})
        failed = "leaf_delete"
        for path in leaves:
            if path.exists():
                leaf_preimages[path] = (path.read_bytes(), path.stat().st_mode & 0o777)
                path.unlink()
        children.append({"child": failed, "ok": True})
        failed = "state_retire"
        if vhost_preimage is not None:
            aside.unlink()
        value = {**old, "portals": [r for r in old.get("portals", []) if r.get("fqdn") != portal], "constituents": [r for r in old.get("constituents", []) if r.get("identity") != portal], "generation": int(old.get("generation", 0)) + 1}
        existing[SCHEMA] = value
        _write_state(existing)
        children.append({"child": failed, "ok": True})
    except Exception as error:
        rollback_errors = []
        for path, (payload, mode) in leaf_preimages.items():
            try:
                path.write_bytes(payload)
                path.chmod(mode)
            except OSError as rollback:
                rollback_errors.append(str(rollback))
        for label in reversed(removed_labels):
            try:
                result = manager.create_alias(label, "home")
                if result.get("state") not in ("applied", "noop"):
                    raise RuntimeError("agathodaimon-portal-dns-restore-failed")
            except Exception as rollback:
                rollback_errors.append(str(rollback))
        if vhost_preimage is not None:
            try:
                if aside.exists():
                    os.replace(aside, vhost)
                else:
                    vhost.write_bytes(vhost_preimage[0])
                    vhost.chmod(vhost_preimage[1])
                _run(["nginx", "-t"], timeout=30)
                _run(["systemctl", "reload", "nginx"], timeout=30)
            except Exception as rollback:
                rollback_errors.append(str(rollback))
        return _receipt("portal_retire", changed=bool(rollback_errors), ok=False, firstMissingSignal="agathodaimon-portal-retire-child-failed", portal=portal, failed_child=failed, child_signal=str(error), rollback_errors=rollback_errors, children=children)
    return _receipt("portal_retire", changed=True, portal=portal, state_generation=value["generation"], children=children, proof="retirement-committed")


def status() -> dict[str, Any]:
    ca, path, role = cert_dir() / "ca.pem", state_path(), _profile()
    value = _receipt("status", changed=False, profile=role, root_present=ca.is_file(), bundle_installed=False, portals=[], constituents=[])
    if role != "homeserver":
        bridge_state, _ = _browser_bridge(_trust_store_layout()[0])
        value["browser_trust"] = "unsupported" if bridge_state == "unsupported" else bridge_state == "bridged"
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
        _, store, _ = _trust_store_layout()
        target = store / "homeserver-house-ca.crt"
        try:
            value["bundle_installed"] = target.is_file() and bool(_assert_ca_only(target))
        except (OSError, ValueError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            value["bundle_installed"] = False
    return value


def _emit(call) -> int:
    try:
        value = call()
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
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



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
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
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
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
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
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError):
        anchor_fingerprint = None
    anchor_current = anchor_fingerprint == root_fingerprint
    store_current = anchor_current and _trust_bundle_readback(system_bundle, target)
    state_current = (
        ledger_pin == root_fingerprint and ledger.get("bundle_installed") is True
    )
    program, refresh_command, executable = _trust_refresh_command(arch, store)
    refresh_needed = not store_current
    already_current = state_current and anchor_current and store_current and not ring_changed
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
            plan=["validate-ca-only-bundle", "resolve-root-pin", "install-platform-anchor", "refresh-system-trust", "verify-system-bundle", "record-root-state"],
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
        except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
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
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError):
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
    return _receipt(
        "trust_install", changed=changed, platform=platform,
        ca_fingerprint=root_fingerprint, bundle_fingerprint=supplied,
        bundle_installed=True, reason=reason, pin_decision=pin_decision,
        pin_sources=pin_sources, anchor_path=str(target),
        system_bundle=str(system_bundle), store_refresh=store_refresh,
        state_generation=(committed["state_generation"] if committed else _generation()),
        state_commit=committed, proof="anchor-and-system-bundle-readback",
    )


def apply_nginx(portal: str, upstream: str, certificate: str, key_path: str, *, dry_run: bool = False) -> dict[str, Any]:
    if not portal or not upstream.startswith(("http://", "https://")):
        raise ValueError("agathodaimon-nginx-input-invalid")
    directory = _path("CADUCEUS_NGINX_DIR", "/etc/nginx/conf.d")
    target = directory / f"agathodaimon-{portal.replace('.', '-')}.conf"
    legacy = directory / f"caduceus-{portal.replace('.', '-')}.conf"
    body = f"server {{ listen 443 ssl; server_name {portal}; ssl_certificate {certificate}; ssl_certificate_key {key_path}; location / {{ proxy_buffering off; proxy_http_version 1.1; proxy_read_timeout 60s; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; proxy_set_header X-Forwarded-Host $host; proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; proxy_pass {upstream}; }} }}\n"
    body_bytes = body.encode("utf-8")
    same = target.is_file() and target.read_bytes() == body_bytes
    legacy_present = legacy.is_file()
    if dry_run:
        return _receipt(
            "apply_nginx",
            changed=False,
            dry_run=True,
            portal=portal,
            legacy_path=str(legacy),
            legacy_present=legacy_present,
            legacy_retired=False,
            legacy_remaining=legacy_present,
            replacement_written=False,
            plan=["stage-nginx", "validate-nginx", "activate-nginx"],
        )
    replacement_written = False
    if not same:
        directory.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".tmp")
        try:
            temporary.write_bytes(body_bytes)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        installed = target.is_file() and target.read_bytes() == body_bytes
        if not installed:
            raise RuntimeError("agathodaimon-nginx-readback-failed")
        replacement_written = True
    legacy_retired = False
    if legacy.is_file():
        legacy.unlink()
        legacy_retired = True
    legacy_remaining = legacy.is_file()
    return _receipt(
        "apply_nginx",
        changed=replacement_written or legacy_retired,
        portal=portal,
        legacy_path=str(legacy),
        legacy_present=legacy_present,
        legacy_retired=legacy_retired,
        legacy_remaining=legacy_remaining,
        replacement_written=replacement_written,
        proof="nginx-config-readback",
    )


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
        _, store, _ = _trust_store_layout()
        target = store / "homeserver-house-ca.crt"
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
    trust = sub.add_parser("trust-install"); trust.add_argument("bundle"); trust.add_argument("--platform", default="linux", choices=sorted(PLATFORMS)); trust.add_argument("--dry-run", action="store_true"); trust.add_argument("--fingerprint"); trust.add_argument("--renew-ring", action="store_true")
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
    if args.cmd == "trust-install": return _emit(lambda: trust_install(args.bundle, args.platform, dry_run=args.dry_run, fingerprint=args.fingerprint, renew_ring=args.renew_ring))
    if args.cmd == "apply-nginx": return _emit(lambda: apply_nginx(args.portal, args.upstream, args.certificate, args.key_path, dry_run=args.dry_run))
    if args.cmd == "constituent-lock": return _emit(lambda: constituent_lock(args.portal, args.lan_ip, dry_run=args.dry_run))
    if args.cmd == "state-commit": return _emit(lambda: state_commit(_json_stdin(), dry_run=args.dry_run))
    if args.cmd == "portal-admit": return _emit(lambda: portal_admit(args.portal, args.lan_ip, args.upstream, args.aliases.split(",") if args.aliases else (), dry_run=args.dry_run))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

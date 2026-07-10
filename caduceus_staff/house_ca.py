"""Caduceus staff house CA — stable trust anchor + renewable leaf.

Snake 2 (Python) of Caduceus dual actuators. Paths default under
/var/lib/caduceus/certs. Never edits legacy sslKey.sh / createCertBundle.sh.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Sequence


def cert_dir() -> Path:
    return Path(os.environ.get("CADUCEUS_CERT_DIR", "/var/lib/caduceus/certs"))


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, check=check, text=True, capture_output=True)


def _fp(path: Path) -> str:
    out = _run(["openssl", "x509", "-in", str(path), "-noout", "-fingerprint", "-sha256"])
    line = out.stdout.strip()
    return line.split("=", 1)[-1] if "=" in line else line


def _not_after(path: Path) -> str:
    out = _run(["openssl", "x509", "-in", str(path), "-noout", "-enddate"])
    return out.stdout.strip().removeprefix("notAfter=")


def _emit(obj: dict) -> int:
    print(json.dumps(obj, indent=2, sort_keys=True))
    return 0 if obj.get("ok", False) else 1


def _write_ca_config(path: Path) -> None:
    path.write_text(
        """[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
x509_extensions = v3_ca

[dn]
C = US
O = HomeServer
OU = House CA
CN = HomeServer House CA

[v3_ca]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""
    )


def _write_leaf_config(path: Path, sans: list[str]) -> None:
    alt = "\n".join(f"DNS.{i} = {name}" for i, name in enumerate(sans, start=1))
    path.write_text(
        f"""[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C = US
O = HomeServer
OU = HTTPS
CN = home.arpa

[v3_req]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[v3_leaf]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
{alt}
"""
    )


def ensure_ca(*, rotate: bool = False) -> dict:
    d = cert_dir()
    d.mkdir(parents=True, exist_ok=True)
    ca_pem = d / "ca.pem"
    ca_key = d / "ca.key.pem"
    reinstall = False
    if rotate or not ca_pem.is_file() or not ca_key.is_file():
        reinstall = ca_pem.is_file() or rotate
        conf = d / "openssl-ca.conf"
        _write_ca_config(conf)
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:4096",
                "-nodes",
                "-keyout",
                str(ca_key),
                "-out",
                str(ca_pem),
                "-days",
                "3650",
                "-config",
                str(conf),
            ]
        )
        ca_key.chmod(0o600)
        ca_pem.chmod(0o644)
        conf.unlink(missing_ok=True)
        (d / "ca.srl").unlink(missing_ok=True)
    return {
        "ca_pem": str(ca_pem),
        "ca_key": str(ca_key),
        "ca_fingerprint": _fp(ca_pem),
        "ca_not_after": _not_after(ca_pem),
        "client_reinstall_required": bool(reinstall and rotate),
        "ok": True,
    }


def default_sans(extra: Sequence[str] | None = None) -> list[str]:
    base = ["home.arpa", "*.home.arpa"]
    for item in extra or []:
        item = item.strip()
        if item and item not in base:
            base.append(item)
    return base


def issue_leaf(sans: Sequence[str] | None = None) -> dict:
    d = cert_dir()
    ca = ensure_ca(rotate=False)
    names = default_sans(sans)
    leaf_pem = d / "leaf.pem"
    leaf_key = d / "leaf.key.pem"
    conf = d / "openssl-leaf.conf"
    csr = d / "leaf.csr.pem"
    _write_leaf_config(conf, names)
    _run(
        [
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:4096",
            "-nodes",
            "-keyout",
            str(leaf_key),
            "-out",
            str(csr),
            "-config",
            str(conf),
        ]
    )
    _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(csr),
            "-CA",
            str(d / "ca.pem"),
            "-CAkey",
            str(d / "ca.key.pem"),
            "-CAcreateserial",
            "-out",
            str(leaf_pem),
            "-days",
            "824",
            "-extfile",
            str(conf),
            "-extensions",
            "v3_leaf",
        ]
    )
    leaf_key.chmod(0o640)
    leaf_pem.chmod(0o644)
    csr.unlink(missing_ok=True)
    conf.unlink(missing_ok=True)
    # verify
    _run(["openssl", "verify", "-CAfile", str(d / "ca.pem"), str(leaf_pem)])
    return {
        "schema": "caduceus.staff.house_ca.issue_leaf.v1",
        "ok": True,
        "ca_fingerprint": ca["ca_fingerprint"],
        "leaf_fingerprint": _fp(leaf_pem),
        "leaf_not_after": _not_after(leaf_pem),
        "sans": names,
        "client_reinstall_required": False,
        "paths": {"ca_pem": str(d / "ca.pem"), "leaf_pem": str(leaf_pem), "leaf_key": str(leaf_key)},
        "firstMissingSignal": "none",
    }


def rotate_ca(understood: bool) -> dict:
    if not understood:
        return {
            "schema": "caduceus.staff.house_ca.rotate_ca.v1",
            "ok": False,
            "client_reinstall_required": False,
            "firstMissingSignal": "caduceus-house-ca-rotate-confirmation-required",
            "message": "Pass --i-understand-clients-reinstall to rotate the house CA.",
        }
    before = None
    ca_pem = cert_dir() / "ca.pem"
    if ca_pem.is_file():
        before = _fp(ca_pem)
    ca = ensure_ca(rotate=True)
    leaf = issue_leaf()
    return {
        "schema": "caduceus.staff.house_ca.rotate_ca.v1",
        "ok": True,
        "ca_fingerprint_before": before,
        "ca_fingerprint": ca["ca_fingerprint"],
        "leaf_fingerprint": leaf["leaf_fingerprint"],
        "client_reinstall_required": True,
        "firstMissingSignal": "none",
    }


def status() -> dict:
    d = cert_dir()
    ca_pem = d / "ca.pem"
    leaf_pem = d / "leaf.pem"
    if not ca_pem.is_file():
        return {
            "schema": "caduceus.staff.house_ca.status.v1",
            "ok": False,
            "client_reinstall_required": False,
            "firstMissingSignal": "caduceus-house-ca-missing",
        }
    out: dict = {
        "schema": "caduceus.staff.house_ca.status.v1",
        "ok": True,
        "ca_fingerprint": _fp(ca_pem),
        "ca_not_after": _not_after(ca_pem),
        "client_reinstall_required": False,
        "cert_dir": str(d),
        "firstMissingSignal": "none",
    }
    if leaf_pem.is_file():
        out["leaf_fingerprint"] = _fp(leaf_pem)
        out["leaf_not_after"] = _not_after(leaf_pem)
        # SANs
        text = _run(["openssl", "x509", "-in", str(leaf_pem), "-noout", "-ext", "subjectAltName"]).stdout
        out["sans_raw"] = text.strip()
    return out


def bundle_create(platform: str = "linux") -> dict:
    d = cert_dir()
    ca_pem = d / "ca.pem"
    if not ca_pem.is_file():
        return {
            "schema": "caduceus.staff.house_ca.bundle.v1",
            "ok": False,
            "firstMissingSignal": "caduceus-house-ca-missing",
            "message": "Run issue-leaf or ensure CA first.",
        }
    out_dir = Path(os.environ.get("CADUCEUS_CERT_BUNDLE_DIR", str(d / "bundles")))
    out_dir.mkdir(parents=True, exist_ok=True)
    platform = platform.lower()
    if platform == "windows":
        out = out_dir / "homeserver_ca.cer"
        _run(["openssl", "x509", "-in", str(ca_pem), "-outform", "DER", "-out", str(out)])
    elif platform in ("android", "chromeos"):
        out = out_dir / "homeserver_ca.crt"
        shutil.copy(ca_pem, out)
    else:
        # linux/macos — CA-only p12 (no private key)
        out = out_dir / "homeserver_ca.p12"
        _run(
            [
                "openssl",
                "pkcs12",
                "-export",
                "-nokeys",
                "-in",
                str(ca_pem),
                "-out",
                str(out),
                "-name",
                "HomeServer House CA",
                "-passout",
                "pass:homeserver",
            ]
        )
    out.chmod(0o644)
    # prove no private key material in pem export path
    raw = out.read_bytes()
    if b"PRIVATE KEY" in raw:
        return {"schema": "caduceus.staff.house_ca.bundle.v1", "ok": False, "firstMissingSignal": "private-key-leaked"}
    return {
        "schema": "caduceus.staff.house_ca.bundle.v1",
        "ok": True,
        "platform": platform,
        "path": str(out),
        "ca_fingerprint": _fp(ca_pem),
        "client_reinstall_required": False,
        "firstMissingSignal": "none",
    }


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="caduceus-house-ca", description="Caduceus staff house CA (Python snake)")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    il = sub.add_parser("issue-leaf")
    il.add_argument("--sans", default="", help="comma-separated extra DNS SANs")
    rc = sub.add_parser("rotate-ca")
    rc.add_argument("--i-understand-clients-reinstall", action="store_true")
    bu = sub.add_parser("bundle")
    bu.add_argument("platform", nargs="?", default="linux", choices=["windows", "android", "chromeos", "linux", "macos"])
    args = p.parse_args(argv)
    if args.cmd == "status":
        return _emit(status())
    if args.cmd == "issue-leaf":
        extra = [x for x in args.sans.split(",") if x.strip()]
        return _emit(issue_leaf(extra))
    if args.cmd == "rotate-ca":
        return _emit(rotate_ca(args.i_understand_clients_reinstall))
    if args.cmd == "bundle":
        return _emit(bundle_create(args.platform))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

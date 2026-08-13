"""Root-only Keyman command membrane for Caduceus SacredCredential.

The credential is owned, encrypted, and rewritten only by Keyman's one admitted
implementation, ``/vault/keyman/keyman-crypto``.  This module never interprets
Keyman's ciphertext, derivation parameters, cipher mode, skeleton passphrase
quirks, or Keyman file format.  It asks Keyman for a brief decrypted caduceus record in a
private temporary directory, parses that bounded record, and securely removes it.

Caduceus identity is always lowercase SHA-256 of the raw skeleton file bytes.
That identity is public metadata; the operator PIN and Keyman plaintext remain
inside the bounded Keyman command/read/cleanup window.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

_RECORD = re.compile(rb'^username="([^"\r\n]+)"\r?\npassword="([^"\r\n]*)"\r?\n?$', re.DOTALL)


class CaduceusAccessRefused(RuntimeError):
    """A redacted refusal for missing, malformed, or mismatched Keyman data."""


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CaduceusAccessRefused("agathodaimon-staff-root-required")


def _pin_bytes(pin: str) -> bytearray:
    value = bytearray(pin.encode("utf-8"))
    if not value or b'"' in value or b"\r" in value or b"\n" in value:
        _wipe(value)
        raise CaduceusAccessRefused("agathodaimon-pin-invalid")
    return value


def _runtime_paths(key_dir: Path | None, vault_dir: Path | None) -> tuple[Path, Path]:
    """Production defaults with scratch fake-root coordinates for proof."""
    return (
        key_dir or Path(os.environ.get("CADUCEUS_KEYMAN_KEY_DIR", "/root/key")),
        vault_dir or Path(os.environ.get("CADUCEUS_KEYMAN_VAULT_DIR", "/vault/.keys")),
    )


def _keyman_binary() -> Path:
    return Path(os.environ.get("CADUCEUS_KEYMAN_CRYPTO", "/vault/keyman/keyman-crypto"))


def _keyman_temp_dir() -> Path:
    return Path(os.environ.get("CADUCEUS_KEYMAN_TEMP_DIR", "/dev/shm"))


def _raw_identity(key_dir: Path) -> str:
    try:
        raw = bytearray((key_dir / "skeleton.key").read_bytes())
    except OSError as exc:
        raise CaduceusAccessRefused("agathodaimon-skeleton-unavailable") from exc
    try:
        if not raw:
            raise CaduceusAccessRefused("agathodaimon-skeleton-malformed")
        return hashlib.sha256(bytes(raw)).hexdigest()
    finally:
        _wipe(raw)


def _remove_private_tree(path: Path) -> None:
    try:
        for child in path.iterdir():
            if child.is_file() or child.is_symlink():
                try:
                    size = child.stat().st_size
                    with child.open("r+b", buffering=0) as handle:
                        handle.write(b"\x00" * size)
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError:
                    pass
                child.unlink(missing_ok=True)
        path.rmdir()
    except OSError:
        shutil.rmtree(path, ignore_errors=True)


def _keyman(operation: str, payload: bytearray, *, read_output: bool = False) -> bytearray:
    """Invoke exactly Keyman's binary; PIN/plaintext are never command arguments."""
    binary = _keyman_binary()
    temporary_root: Path | None = None
    input_path: Path | None = None
    output_path: Path | None = None
    output = bytearray()
    try:
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise CaduceusAccessRefused("agathodaimon-keyman-unavailable")
        temporary_root = Path(tempfile.mkdtemp(prefix="agathodaimon-keyman-", dir=_keyman_temp_dir()))
        os.chmod(temporary_root, 0o700)
        input_path = temporary_root / "input"
        with input_path.open("xb", buffering=0) as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        command = [str(binary), operation, str(input_path)]
        if read_output:
            output_path = temporary_root / "output"
            command.append(str(output_path))
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        if result.returncode != 0:
            raise CaduceusAccessRefused("agathodaimon-keyman-command-refused")
        if read_output:
            try:
                if output_path is None:
                    raise CaduceusAccessRefused("agathodaimon-keyman-output-unavailable")
                output = bytearray(output_path.read_bytes())
            except OSError as exc:
                raise CaduceusAccessRefused("agathodaimon-keyman-output-unavailable") from exc
        return output
    except (OSError, subprocess.SubprocessError) as exc:
        raise CaduceusAccessRefused("agathodaimon-keyman-command-refused") from exc
    finally:
        _wipe(payload)
        if temporary_root is not None:
            _remove_private_tree(temporary_root)


def _credential() -> tuple[bytearray, bytearray]:
    plaintext = _keyman("decrypt", bytearray(b"service=caduceus\n"), read_output=True)
    try:
        match = _RECORD.fullmatch(bytes(plaintext))
        if match is None:
            raise CaduceusAccessRefused("agathodaimon-key-malformed")
        return bytearray(match.group(1)), bytearray(match.group(2))
    finally:
        _wipe(plaintext)


VAULT_SERVICE = "homeconsole-vault"

def seated_service_record_present(service: str, *, vault_dir: Path | None = None) -> bool:
    if service != VAULT_SERVICE: raise CaduceusAccessRefused("agathodaimon-keyman-service-refused")
    _, root = _runtime_paths(None, vault_dir)
    return (root / f"{service}.key").is_file()

def read_seated_service_password(service: str, *, vault_dir: Path | None = None) -> bytearray:
    _require_root()
    if not seated_service_record_present(service, vault_dir=vault_dir): raise CaduceusAccessRefused("agathodaimon-keyman-record-unavailable")
    plaintext = _keyman("decrypt", bytearray(f"service={service}\n".encode("ascii")), read_output=True)
    username = bytearray()
    try:
        match = _RECORD.fullmatch(bytes(plaintext))
        if match is None: raise CaduceusAccessRefused("agathodaimon-keyman-record-malformed")
        username = bytearray(match.group(1)); return bytearray(match.group(2))
    finally:
        _wipe(username); _wipe(plaintext)

def _require_current_credential(key_dir: Path) -> tuple[str, bytearray]:
    identity = _raw_identity(key_dir)
    username = bytearray()
    stored_pin = bytearray()
    try:
        username, stored_pin = _credential()
        if not hmac.compare_digest(bytes(username), identity.encode("ascii")):
            raise CaduceusAccessRefused("agathodaimon-identity-mismatch")
        return identity, bytearray(stored_pin)
    finally:
        _wipe(username)
        _wipe(stored_pin)


@dataclass
class DerivedCaduceusSigner:
    """Private in-memory signer with a public-only verifier projection."""

    _seed: bytearray = field(repr=False)
    identity_sha256: str
    _public_key_hex: str = ""

    def __post_init__(self) -> None:
        public = self.private_key().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self._public_key_hex = public.hex()

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    @property
    def signer_epoch(self) -> str:
        return hashlib.sha256(bytes.fromhex(self._public_key_hex)).hexdigest()

    @property
    def epoch(self) -> str:
        return self.signer_epoch

    def private_key(self) -> Ed25519PrivateKey:
        if not self._seed:
            raise CaduceusAccessRefused("agathodaimon-derived-signer-closed")
        return Ed25519PrivateKey.from_private_bytes(bytes(self._seed))

    def close(self) -> None:
        _wipe(self._seed)
        self._seed.clear()

    def __enter__(self) -> "DerivedCaduceusSigner":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def verify_and_derive_caduceus(pin: str, *, key_dir: Path | None = None, vault_dir: Path | None = None) -> DerivedCaduceusSigner:
    """Verify one PIN through Keyman and derive the tablet-defined signer."""
    _require_root()
    key_dir, vault_dir = _runtime_paths(key_dir, vault_dir)
    if not (vault_dir / "caduceus.key").is_file():
        raise CaduceusAccessRefused("agathodaimon-key-unavailable")
    presented = _pin_bytes(pin)
    stored = bytearray()
    try:
        identity, stored = _require_current_credential(key_dir)
        if not hmac.compare_digest(bytes(stored), bytes(presented)):
            raise CaduceusAccessRefused("agathodaimon-pin-refused")
        seed = bytearray(hashlib.sha256(identity.encode("ascii") + b"\x00" + bytes(presented)).digest())
        return DerivedCaduceusSigner(seed, identity)
    finally:
        _wipe(presented)
        _wipe(stored)


def bind_derived_caduceus(*, key_dir: Path | None = None, vault_dir: Path | None = None) -> DerivedCaduceusSigner:
    """Read fixed Keyman custody and derive a signer from the seated PIN."""
    _require_root()
    key_dir, vault_dir = _runtime_paths(key_dir, vault_dir)
    if not (vault_dir / "caduceus.key").is_file():
        raise CaduceusAccessRefused("agathodaimon-key-unavailable")
    stored = bytearray()
    try:
        identity, stored = _require_current_credential(key_dir)
        seed = bytearray(hashlib.sha256(identity.encode("ascii") + b"\x00" + bytes(stored)).digest())
        return DerivedCaduceusSigner(seed, identity)
    finally:
        _wipe(stored)


def reset_caduceus_pin_to_provisioned_default(*, key_dir: Path | None = None, vault_dir: Path | None = None) -> dict[str, object]:
    """Restore Keyman-held Caduceus PIN from the root-provisioned default file."""
    _require_root()
    default_path = Path(os.environ.get("CADUCEUS_PROVISIONED_DEFAULT_PIN_FILE", "/etc/caduceus/provisioned-default-pin"))
    try:
        default = bytearray(default_path.read_bytes())
    except OSError as exc:
        raise CaduceusAccessRefused("agathodaimon-pin-default-not-provisioned") from exc
    try:
        if default.endswith(b"\n"):
            default.pop()
        if not default:
            raise CaduceusAccessRefused("agathodaimon-pin-default-not-provisioned")
        validated = _pin_bytes(default.decode("utf-8"))
        try:
            key_dir, _ = _runtime_paths(key_dir, vault_dir)
            _require_current_credential(key_dir)
            _keyman("reencrypt", bytearray(b"service=caduceus\nnew_password=" + bytes(default) + b"\n"))
            return {"schema": "keyman.caduceus_access.status.v1", "ok": True, "operation": "pin-reset-default", "private_material": "[REDACTED]"}
        finally:
            _wipe(validated)
    except (UnicodeDecodeError, CaduceusAccessRefused):
        raise
    finally:
        _wipe(default)


def provision_caduceus(initial_pin: str, *, key_dir: Path | None = None, vault_dir: Path | None = None) -> dict[str, object]:
    """Create the fixed Caduceus credential exactly once through Keyman."""
    _require_root()
    key_dir, vault_dir = _runtime_paths(key_dir, vault_dir)
    if (vault_dir / "caduceus.key").exists():
        raise CaduceusAccessRefused("agathodaimon-key-exists")
    pin = _pin_bytes(initial_pin)
    try:
        identity = _raw_identity(key_dir)
        _keyman("create", bytearray(b"service=caduceus\nusername=" + identity.encode("ascii") + b"\npassword=" + bytes(pin) + b"\n"))
        return {"schema": "keyman.caduceus_access.status.v1", "ok": True, "operation": "provisioned", "private_material": "[REDACTED]"}
    finally:
        _wipe(pin)


def change_caduceus_pin(old_pin: str, new_pin: str, *, key_dir: Path | None = None, vault_dir: Path | None = None) -> dict[str, object]:
    """Verify old PIN, ask Keyman to reencrypt, then leave rebind to the caller."""
    _require_root()
    key_dir, _ = _runtime_paths(key_dir, vault_dir)
    old = _pin_bytes(old_pin)
    new = _pin_bytes(new_pin)
    stored = bytearray()
    try:
        _, stored = _require_current_credential(key_dir)
        if not hmac.compare_digest(bytes(stored), bytes(old)):
            raise CaduceusAccessRefused("agathodaimon-pin-refused")
        _keyman("reencrypt", bytearray(b"service=caduceus\nnew_password=" + bytes(new) + b"\n"))
        return {"schema": "keyman.caduceus_access.status.v1", "ok": True, "operation": "pin-changed", "private_material": "[REDACTED]"}
    finally:
        for value in (old, new, stored):
            _wipe(value)

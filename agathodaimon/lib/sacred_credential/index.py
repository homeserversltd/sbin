"""Root-only Caduceus household PIN seat and non-PIN Keyman services.

The live PIN is the bounded ``global.admin.pin`` value in appliance config.
Keyman remains only for the unrelated homeconsole-vault service record.
"""
from __future__ import annotations

import fcntl
import grp
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from agathodaimon._envelope import appliance_runtime_path

_RECORD = re.compile(rb'^username="([^"\r\n]+)"\r?\npassword="([^"\r\n]*)"\r?\n?$', re.DOTALL)
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_FACTORY_BYTES = 1024 * 1024
_MAX_SKELETON_BYTES = 64 * 1024
_MAX_PIN_LENGTH = 512


class CaduceusAccessRefused(RuntimeError):
    """A redacted refusal for missing, malformed, or mismatched credentials."""


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _require_root() -> None:
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        raise CaduceusAccessRefused("agathodaimon-staff-root-required")


def _pin_bytes(pin: str) -> bytearray:
    if not isinstance(pin, str) or len(pin) > _MAX_PIN_LENGTH:
        raise CaduceusAccessRefused("agathodaimon-pin-invalid")
    try:
        value = bytearray(pin.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise CaduceusAccessRefused("agathodaimon-pin-invalid") from exc
    if not value:
        _wipe(value)
        raise CaduceusAccessRefused("agathodaimon-pin-invalid")
    return value


def _open_parent(path: Path) -> tuple[int, str]:
    """Open every path component without following symlinks."""
    if not path.is_absolute() or len(path.parts) < 2 or any(part in {".", ".."} for part in path.parts[1:]):
        raise OSError("unsafe runtime path")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open("/", directory_flags)
    try:
        for part in path.parts[1:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        return directory_fd, path.parts[-1]
    except BaseException:
        os.close(directory_fd)
        raise


def _stat_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _read_at(directory_fd: int, name: str, maximum: int) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("runtime file is not bounded regular data")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            block = os.read(file_fd, min(65536, maximum + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
        after = os.fstat(file_fd)
        if total > maximum or _stat_signature(before) != _stat_signature(after):
            raise ValueError("runtime file changed or exceeded its bound")
        return b"".join(chunks), before
    finally:
        os.close(file_fd)


def _read_path(path: Path, maximum: int, *, unavailable: str, unreadable: str, malformed: str) -> bytes:
    directory_fd = None
    try:
        directory_fd, name = _open_parent(path)
        raw, _ = _read_at(directory_fd, name, maximum)
        return raw
    except FileNotFoundError as exc:
        raise CaduceusAccessRefused(unavailable) from exc
    except ValueError as exc:
        raise CaduceusAccessRefused(malformed) from exc
    except OSError as exc:
        raise CaduceusAccessRefused(unreadable) from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(_: str) -> None:
    raise ValueError("invalid JSON constant")


def _parse_document(raw: bytes, *, malformed: str) -> dict[str, object]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise CaduceusAccessRefused(malformed) from exc
    if not isinstance(value, dict):
        raise CaduceusAccessRefused(malformed)
    return value


def _runtime_path(coordinate: str, *, label: str) -> Path:
    try:
        return appliance_runtime_path(coordinate)
    except ValueError as exc:
        raise CaduceusAccessRefused("agathodaimon-scratch-root-invalid") from exc


def _read_document(coordinate: str, *, label: str) -> dict[str, object]:
    path = _runtime_path(coordinate, label=label)
    prefix = "agathodaimon-config-factory" if label == "config-factory" else "agathodaimon-config"
    maximum = _MAX_FACTORY_BYTES if coordinate == "factory" else _MAX_CONFIG_BYTES
    raw = _read_path(
        path,
        maximum,
        unavailable=f"{prefix}-unavailable",
        unreadable=f"{prefix}-unreadable",
        malformed=f"{prefix}-malformed",
    )
    return _parse_document(raw, malformed=f"{prefix}-malformed")


def _pin_from_document(document: dict[str, object], *, label: str) -> str:
    prefix = "agathodaimon-config-factory" if label == "config-factory" else "agathodaimon-config"
    if "global" not in document:
        raise CaduceusAccessRefused(f"{prefix}-pin-absent")
    global_config = document["global"]
    if not isinstance(global_config, dict):
        raise CaduceusAccessRefused(f"{prefix}-pin-malformed")
    if "admin" not in global_config:
        raise CaduceusAccessRefused(f"{prefix}-pin-absent")
    admin_config = global_config["admin"]
    if not isinstance(admin_config, dict):
        raise CaduceusAccessRefused(f"{prefix}-pin-malformed")
    if "pin" not in admin_config:
        raise CaduceusAccessRefused(f"{prefix}-pin-absent")
    pin = admin_config["pin"]
    try:
        checked = _pin_bytes(pin)
    except CaduceusAccessRefused as exc:
        raise CaduceusAccessRefused(f"{prefix}-pin-malformed") from exc
    _wipe(checked)
    return pin


def _runtime_pin() -> str:
    return _pin_from_document(_read_document("config", label="config"), label="config")


def _raw_identity() -> str:
    path = _runtime_path("skeleton", label="skeleton")
    raw = bytearray(
        _read_path(
            path,
            _MAX_SKELETON_BYTES,
            unavailable="agathodaimon-skeleton-unavailable",
            unreadable="agathodaimon-skeleton-unavailable",
            malformed="agathodaimon-skeleton-malformed",
        )
    )
    try:
        if not raw:
            raise CaduceusAccessRefused("agathodaimon-skeleton-malformed")
        return hashlib.sha256(bytes(raw)).hexdigest()
    finally:
        _wipe(raw)


def _require_config_custody(metadata: os.stat_result) -> int:
    try:
        caduceus_gid = grp.getgrnam("caduceus").gr_gid
    except KeyError as exc:
        raise CaduceusAccessRefused("agathodaimon-config-custody-unavailable") from exc
    if (
        metadata.st_uid != 0
        or metadata.st_gid != caduceus_gid
        or stat.S_IMODE(metadata.st_mode) != 0o660
        or metadata.st_nlink != 1
    ):
        raise CaduceusAccessRefused("agathodaimon-config-custody-invalid")
    return caduceus_gid


def _update_config_pin(
    new_pin: str,
    *,
    expected_old_pin: str | None = None,
    require_absent: bool = False,
) -> None:
    """Atomically replace only global.admin.pin under a directory lock and CAS readback."""
    new = bytearray()
    expected: bytearray | None = None
    directory_fd = None
    temporary_name: str | None = None
    try:
        new = _pin_bytes(new_pin)
        expected = _pin_bytes(expected_old_pin) if expected_old_pin is not None else None
        path = _runtime_path("config", label="config")
        directory_fd, name = _open_parent(path)
        fcntl.flock(directory_fd, fcntl.LOCK_EX)
        try:
            original_raw, original_stat = _read_at(directory_fd, name, _MAX_CONFIG_BYTES)
        except FileNotFoundError as exc:
            raise CaduceusAccessRefused("agathodaimon-config-unavailable") from exc
        except ValueError as exc:
            raise CaduceusAccessRefused("agathodaimon-config-malformed") from exc
        except OSError as exc:
            raise CaduceusAccessRefused("agathodaimon-config-unreadable") from exc
        caduceus_gid = _require_config_custody(original_stat)
        document = _parse_document(original_raw, malformed="agathodaimon-config-malformed")
        global_config = document.get("global")
        if not isinstance(global_config, dict):
            signal = "agathodaimon-config-pin-absent" if "global" not in document else "agathodaimon-config-pin-malformed"
            raise CaduceusAccessRefused(signal)
        admin_config = global_config.get("admin")
        if not isinstance(admin_config, dict):
            signal = "agathodaimon-config-pin-absent" if "admin" not in global_config else "agathodaimon-config-pin-malformed"
            raise CaduceusAccessRefused(signal)
        if require_absent and "pin" in admin_config:
            raise CaduceusAccessRefused("agathodaimon-config-pin-already-provisioned")
        if expected is not None:
            current_pin = _pin_from_document(document, label="config")
            current = _pin_bytes(current_pin)
            try:
                if not hmac.compare_digest(bytes(current), bytes(expected)):
                    raise CaduceusAccessRefused("agathodaimon-pin-refused")
            finally:
                _wipe(current)
        admin_config["pin"] = new_pin
        try:
            encoded = json.dumps(document, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError) as exc:
            raise CaduceusAccessRefused("agathodaimon-config-malformed") from exc
        if len(encoded) > _MAX_CONFIG_BYTES:
            raise CaduceusAccessRefused("agathodaimon-config-malformed")

        temporary_name = f".{name}.agathodaimon-{os.urandom(12).hex()}.tmp"
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.fchown(temporary_fd, 0, caduceus_gid)
            os.fchmod(temporary_fd, 0o660)
            view = memoryview(encoded)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError("short config write")
                view = view[written:]
            os.fsync(temporary_fd)
        finally:
            os.close(temporary_fd)

        try:
            current_raw, current_stat = _read_at(directory_fd, name, _MAX_CONFIG_BYTES)
        except (OSError, ValueError) as exc:
            raise CaduceusAccessRefused("agathodaimon-config-concurrent-update") from exc
        if current_raw != original_raw or _stat_signature(current_stat) != _stat_signature(original_stat):
            raise CaduceusAccessRefused("agathodaimon-config-concurrent-update")
        os.replace(temporary_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary_name = None
        os.fsync(directory_fd)
    except CaduceusAccessRefused:
        raise
    except OSError as exc:
        raise CaduceusAccessRefused("agathodaimon-config-write-refused") from exc
    finally:
        if directory_fd is not None:
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except OSError:
                    pass
            os.close(directory_fd)
        if expected is not None:
            _wipe(expected)
        _wipe(new)


def _keyman_binary() -> Path:
    return Path(os.environ.get("CADUCEUS_KEYMAN_CRYPTO", "/vault/keyman/keyman-crypto"))


def _keyman_temp_dir() -> Path:
    return Path(os.environ.get("CADUCEUS_KEYMAN_TEMP_DIR", "/dev/shm"))


def _vault_directory(vault_dir: Path | None) -> Path:
    return vault_dir or Path(os.environ.get("CADUCEUS_KEYMAN_VAULT_DIR", "/vault/.keys"))


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
    """Invoke Keyman only for its separately seated non-PIN services."""
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


def _service_credential(service: str) -> tuple[bytearray, bytearray]:
    plaintext = _keyman("decrypt", bytearray(f"service={service}\n".encode("ascii")), read_output=True)
    try:
        match = _RECORD.fullmatch(bytes(plaintext))
        if match is None:
            raise CaduceusAccessRefused("agathodaimon-keyman-record-malformed")
        return bytearray(match.group(1)), bytearray(match.group(2))
    finally:
        _wipe(plaintext)


VAULT_SERVICE = "homeconsole-vault"


def seated_service_record_present(service: str, *, vault_dir: Path | None = None) -> bool:
    if service != VAULT_SERVICE:
        raise CaduceusAccessRefused("agathodaimon-keyman-service-refused")
    root = _vault_directory(vault_dir)
    return (root / f"{service}.key").is_file()


def read_seated_service_password(service: str, *, vault_dir: Path | None = None) -> bytearray:
    _require_root()
    if not seated_service_record_present(service, vault_dir=vault_dir):
        raise CaduceusAccessRefused("agathodaimon-keyman-record-unavailable")
    username = bytearray()
    password = bytearray()
    try:
        username, password = _service_credential(service)
        return bytearray(password)
    finally:
        _wipe(username)
        _wipe(password)


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


def verify_and_derive_caduceus(pin: str) -> DerivedCaduceusSigner:
    """Verify against config.json and derive the tablet-defined signer."""
    _require_root()
    presented = _pin_bytes(pin)
    stored = bytearray()
    try:
        identity = _raw_identity()
        stored_pin = _runtime_pin()
        stored = _pin_bytes(stored_pin)
        if not hmac.compare_digest(bytes(stored), bytes(presented)):
            raise CaduceusAccessRefused("agathodaimon-pin-refused")
        seed = bytearray(hashlib.sha256(identity.encode("ascii") + b"\x00" + bytes(presented)).digest())
        return DerivedCaduceusSigner(seed, identity)
    finally:
        _wipe(presented)
        _wipe(stored)


def bind_derived_caduceus() -> DerivedCaduceusSigner:
    """Read the current appliance PIN seat and derive a signer in staff memory."""
    _require_root()
    identity = _raw_identity()
    stored = _pin_bytes(_runtime_pin())
    try:
        seed = bytearray(hashlib.sha256(identity.encode("ascii") + b"\x00" + bytes(stored)).digest())
        return DerivedCaduceusSigner(seed, identity)
    finally:
        _wipe(stored)


def reset_caduceus_pin_to_provisioned_default() -> dict[str, object]:
    """Copy only the sealed factory PIN into config.json; ignore caller PIN data."""
    _require_root()
    factory_pin = _pin_from_document(
        _read_document("factory", label="config-factory"),
        label="config-factory",
    )
    _update_config_pin(factory_pin)
    return {
        "schema": "caduceus.staff.sacred-credential.v1",
        "ok": True,
        "operation": "pin-reset-default",
        "private_material": "[REDACTED]",
    }


def provision_caduceus(initial_pin: str) -> dict[str, object]:
    """Seat the initial PIN in config.json exactly once, without Keyman."""
    _require_root()
    _update_config_pin(initial_pin, require_absent=True)
    return {
        "schema": "caduceus.staff.sacred-credential.v1",
        "ok": True,
        "operation": "pin-provisioned",
        "private_material": "[REDACTED]",
    }


def change_caduceus_pin(old_pin: str, new_pin: str) -> dict[str, object]:
    """Compare the current config PIN and atomically change only that value."""
    _require_root()
    _update_config_pin(new_pin, expected_old_pin=old_pin)
    return {
        "schema": "caduceus.staff.sacred-credential.v1",
        "ok": True,
        "operation": "pin-changed",
        "private_material": "[REDACTED]",
    }

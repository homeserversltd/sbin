"""Native refresh for the retained sslKey.sh certificate contract."""
from __future__ import annotations

import copy
import grp
import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
from dataclasses import dataclass, replace
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlsplit

from agathodaimon._envelope import EnvelopeError, Request, appliance_runtime_path, attach, read

SCHEMA = "caduceus.staff.v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 8 * 1024 * 1024
OPENSSL = "/usr/bin/openssl"
UPDATE_CA_CERTIFICATES = "/usr/sbin/update-ca-certificates"
CERT_DIR = Path("/etc/ssl/home.arpa")
TRUST_ANCHORS = Path("/usr/local/share/ca-certificates")
TRUST_CERTS = Path("/etc/ssl/certs")
TRUST_BUNDLE = TRUST_CERTS / "ca-certificates.crt"
TAILNET_LABEL = re.compile(r"^[a-z0-9-]{1,63}$")
FALLBACK_HOSTS = (
    "jellyfin", "git", "vault", "photos", "docs", "transmission",
    "music", "files", "books", "rss",
)
EXECUTABLE_SELECTORS = {"bin", "program", "path", "script", "command"}
SECRET_MARKER = re.compile(r"tskey-", re.IGNORECASE)


class Refusal(ValueError):
    """A named, structured refusal that is safe to report."""

    def __init__(self, signal: str):
        super().__init__(signal)
        self.signal = signal


@dataclass(frozen=True)
class Image:
    existed: bool
    mode: int = 0
    uid: int = 0
    gid: int = 0
    data: bytes | None = None

    @property
    def kind(self) -> str:
        if not self.existed:
            return "absent"
        if stat.S_ISLNK(self.mode):
            return "symlink"
        if stat.S_ISDIR(self.mode):
            return "directory"
        if stat.S_ISREG(self.mode):
            return "file"
        return "other"


def _receipt(ok: bool, signal: str = "none", *, observed: Any = None,
             could_change: Sequence[str] = (), attempt: Any = None, final: Any = None,
             mutation: bool = False, **fields: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "action": "refresh",
        "firstMissingSignal": signal,
        "mutationPerformed": mutation,
        "observed": observed,
        "could-change": list(could_change),
        "attempt": attempt,
        "final": final,
        **fields,
    }


def _read_regular(path: Path, signal: str, limit: int = MAX_CONFIG_BYTES) -> tuple[bytes, os.stat_result]:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as error:
        raise Refusal(signal) from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise Refusal("cert-refresh-config-invalid")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise Refusal("cert-refresh-config-too-large")
            chunks.append(chunk)
        return b"".join(chunks), info
    finally:
        os.close(fd)


def _load_config() -> dict[str, Any]:
    """Read only the declared appliance runtime config; never read a repo copy."""
    path = appliance_runtime_path("config")
    try:
        info = os.lstat(path)
    except OSError as error:
        raise Refusal("cert-refresh-config-unavailable") from error
    if stat.S_ISLNK(info.st_mode):
        raise Refusal("cert-refresh-config-factory-selected")
    factory = appliance_runtime_path("factory")
    try:
        if os.path.samefile(path, factory):
            raise Refusal("cert-refresh-config-factory-selected")
    except FileNotFoundError:
        pass
    except OSError as error:
        raise Refusal("cert-refresh-config-selection-unreadable") from error
    raw, _meta = _read_regular(path, "cert-refresh-config-unreadable")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal("cert-refresh-config-invalid") from error
    if not isinstance(value, dict):
        raise Refusal("cert-refresh-config-invalid")
    return value


def _origins(config: Mapping[str, Any]) -> list[str]:
    global_value = config.get("global")
    cors = global_value.get("cors") if isinstance(global_value, Mapping) else None
    allowed = cors.get("allowed_origins") if isinstance(cors, Mapping) else None
    if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
        raise Refusal("cert-refresh-cors-origins-invalid")
    return allowed


def _tailnet_from_origins(origins: Sequence[str]) -> str:
    for origin in origins:
        if ".ts.net" not in origin.lower():
            continue
        try:
            parsed = urlsplit(origin)
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError as error:
            raise Refusal("cert-refresh-cors-origin-invalid") from error
        labels = host.split(".")
        if len(labels) == 4 and labels[0] == "home" and labels[2:] == ["ts", "net"]:
            if not TAILNET_LABEL.fullmatch(labels[1]):
                raise Refusal("cert-refresh-tailnet-label-invalid")
            if not parsed.scheme or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise Refusal("cert-refresh-cors-origin-invalid")
            return labels[1]
    raise Refusal("cert-refresh-tailnet-origin-missing")


def _portal_hosts(config: Mapping[str, Any]) -> list[str]:
    tabs = config.get("tabs")
    portals_root = tabs.get("portals") if isinstance(tabs, Mapping) else None
    portal_data = portals_root.get("data") if isinstance(portals_root, Mapping) else None
    portals = portal_data.get("portals") if isinstance(portal_data, Mapping) else None
    if portals is None:
        return []
    if not isinstance(portals, list) or any(not isinstance(item, Mapping) for item in portals):
        raise Refusal("cert-refresh-portals-invalid")
    result: list[str] = []
    seen: set[str] = set()
    for portal in portals:
        local_url = portal.get("localURL")
        if local_url is None:
            continue
        if not isinstance(local_url, str):
            raise Refusal("cert-refresh-portal-local-url-invalid")
        try:
            parsed = urlsplit(local_url)
            host = (parsed.hostname or "").lower().rstrip(".")
        except ValueError as error:
            raise Refusal("cert-refresh-portal-local-url-invalid") from error
        if host.endswith(".home.arpa") and host != "home.arpa" and host not in seen:
            seen.add(host)
            result.append(host)
    return result


def _subject_alt_names(config: Mapping[str, Any], tailnet: str | None = None) -> list[str]:
    origins = _origins(config)
    if tailnet is None:
        tailnet = _tailnet_from_origins(origins)
    elif not TAILNET_LABEL.fullmatch(tailnet):
        raise Refusal("cert-refresh-tailnet-label-invalid")
    hosts = _portal_hosts(config)
    if not hosts:
        hosts = [f"{name}.home.arpa" for name in FALLBACK_HOSTS]
    return list(dict.fromkeys(["home.arpa", "*.home.arpa", f"home.{tailnet}.ts.net", *hosts]))


def _image(path: Path) -> Image:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return Image(False)
    except OSError as error:
        raise Refusal("cert-refresh-inventory-read-failed") from error
    if stat.S_ISLNK(info.st_mode):
        return Image(True, info.st_mode, info.st_uid, info.st_gid, os.fsencode(os.readlink(path)))
    if stat.S_ISDIR(info.st_mode):
        return Image(True, info.st_mode, info.st_uid, info.st_gid)
    if not stat.S_ISREG(info.st_mode):
        raise Refusal("cert-refresh-managed-seat-not-regular")
    data, current = _read_regular(path, "cert-refresh-inventory-read-failed", limit=MAX_CONFIG_BYTES * 4)
    return Image(True, current.st_mode, current.st_uid, current.st_gid, data)


def _restore_temp(path: Path) -> Path:
    digest = hashlib.sha256(os.fsencode(path)).hexdigest()[:16]
    return path.with_name(f".{path.name}.cert-refresh-{digest}.restore")


def _walk_tree(root: Path) -> list[Path]:
    result: list[Path] = []
    pending = [root]
    while pending:
        path = pending.pop()
        image = _image(path)
        result.append(path)
        if image.kind != "directory":
            continue
        try:
            children = sorted(path.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise Refusal("cert-refresh-inventory-read-failed") from error
        pending.extend(reversed(children))
    return result


def _trust_available() -> bool:
    try:
        info = os.lstat(TRUST_ANCHORS)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise Refusal("cert-refresh-trust-directory-unreadable") from error
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise Refusal("cert-refresh-trust-directory-refused")
    for directory in reversed(TRUST_ANCHORS.parents):
        if directory == Path("/"):
            continue
        try:
            parent_info = os.lstat(directory)
        except OSError as error:
            raise Refusal("cert-refresh-trust-parent-unavailable") from error
        if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
            raise Refusal("cert-refresh-trust-parent-refused")
    return True


def prospective_mutable_inventory(tailnet: str | None = None) -> dict[str, Any]:
    """Return the exact prospective legacy-cert and bounded trust-updater seats."""
    config = _load_config()
    sans = _subject_alt_names(config, tailnet)
    paths = [
        CERT_DIR,
        CERT_DIR / "key.pem",
        CERT_DIR / "cert.pem",
        CERT_DIR / ".home.arpa-refresh.key.pem.new",
        CERT_DIR / ".home.arpa-refresh.cert.pem.new",
        CERT_DIR / ".home.arpa-refresh.cnf",
    ]
    for target in (CERT_DIR / "key.pem", CERT_DIR / "cert.pem"):
        if _image(target).kind == "file":
            paths.append(_restore_temp(target))
    trees: list[Path] = []
    updater: dict[str, Any] = {"enabled": False, "program": UPDATE_CA_CERTIFICATES}
    if _trust_available():
        try:
            trust_info = os.lstat(TRUST_CERTS)
        except OSError as error:
            raise Refusal("cert-refresh-system-trust-directory-unavailable") from error
        if stat.S_ISLNK(trust_info.st_mode) or not stat.S_ISDIR(trust_info.st_mode):
            raise Refusal("cert-refresh-system-trust-directory-refused")
        for directory in reversed(TRUST_CERTS.parents):
            if directory == Path("/"):
                continue
            try:
                parent_info = os.lstat(directory)
            except OSError as error:
                raise Refusal("cert-refresh-system-trust-parent-unavailable") from error
            if stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode):
                raise Refusal("cert-refresh-system-trust-parent-refused")
        paths.extend((
            TRUST_ANCHORS,
            TRUST_ANCHORS / "home.arpa.crt",
            TRUST_ANCHORS / ".home.arpa.crt.new",
            TRUST_CERTS,
            TRUST_BUNDLE,
            TRUST_CERTS / "ca-certificates.crt.new",
        ))
        trees.append(TRUST_CERTS)
        for path in _walk_tree(TRUST_CERTS):
            if _image(path).kind == "file":
                paths.append(_restore_temp(path))
        anchor = TRUST_ANCHORS / "home.arpa.crt"
        if _image(anchor).kind == "file":
            paths.append(_restore_temp(anchor))
        updater = {
            "enabled": True,
            "program": UPDATE_CA_CERTIFICATES,
            "arguments": [
                "--certsconf", "/etc/ca-certificates.conf",
                "--certsdir", "/usr/share/ca-certificates",
                "--localcertsdir", str(TRUST_ANCHORS),
                "--certbundle", TRUST_BUNDLE.name,
                "--etccertsdir", str(TRUST_CERTS),
                "--hooksdir", "/dev/null",
            ],
            "environment": {"TMPDIR": str(TRUST_CERTS)},
            "mutations": [
                str(TRUST_BUNDLE), str(TRUST_CERTS / "home.arpa.pem"),
                "all changed hash/orphan symlinks and bounded updater temporaries under " + str(TRUST_CERTS),
            ],
        }
    return {
        "subjectAltNames": sans,
        "paths": sorted({str(path) for path in paths}),
        "trees": [str(path) for path in trees],
        "updater": updater,
    }


def _write_new(path: Path, data: bytes, mode: int, uid: int, gid: int, *, owned: set[Path] | None = None) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    if owned is not None:
        owned.add(path)
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short certificate staging write")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_directory(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _safe_target(path: Path) -> Image:
    image = _image(path)
    if image.kind not in {"absent", "file"}:
        raise Refusal("cert-refresh-target-seat-refused")
    return image


def _atomic_replace(
    stage: Path,
    target: Path,
    mode: int,
    uid: int,
    gid: int,
    *,
    on_replace: Callable[[Path], None] | None = None,
    owned_changed_targets: set[Path] | None = None,
) -> None:
    fd = os.open(stage, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(stage, target)
    if owned_changed_targets is not None:
        owned_changed_targets.add(target)
    if on_replace is not None:
        on_replace(target)
    _fsync_directory(target.parent)


def _kill_process_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate()


def _run(argv: Sequence[str], timeout: float, *, env: Mapping[str, str] | None = None) -> subprocess.CompletedProcess[str] | None:
    try:
        process = subprocess.Popen(
            list(argv), text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=None if env is None else dict(env), start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        return None
    except (OSError, subprocess.SubprocessError):
        try:
            _kill_process_group(process)
        except BaseException:
            pass
        return None
    except BaseException:
        try:
            _kill_process_group(process)
        except BaseException:
            pass
        raise
    return subprocess.CompletedProcess(list(argv), process.returncode, stdout, stderr)


def _refresh_restore(
    images: Mapping[Path, Image],
    trees: Sequence[Path],
    transaction_paths: Sequence[Path],
    restore_temps: Mapping[Path, Path],
    owned_temporaries: set[Path],
    owned_directories: set[Path],
    owned_changed_targets: set[Path],
    owned_updater_paths: set[Path],
) -> list[str]:
    failures: list[str] = []
    current_paths: set[Path] = set()
    for tree in trees:
        try:
            if _image(tree).kind == "directory":
                current_paths.update(_walk_tree(tree))
        except Exception:
            failures.append(str(tree))
    all_paths = set(images) | current_paths | set(transaction_paths)
    for path in sorted((p for p in all_paths if images.get(p, Image(False)).kind == "directory"), key=lambda item: (len(item.parts), str(item))):
        original = images[path]
        try:
            current = _image(path)
            if current.kind != "directory":
                if current.kind != "absent":
                    path.unlink()
                path.mkdir(mode=stat.S_IMODE(original.mode))
                os.chown(path, original.uid, original.gid)
                os.chmod(path, stat.S_IMODE(original.mode))
        except Exception:
            failures.append(str(path))
    for path in sorted(all_paths, key=lambda item: (-len(item.parts), str(item))):
        if path in images and images[path].kind == "directory":
            continue
        original = images.get(path, Image(False))
        try:
            current = _image(path)
            if current == original:
                continue
            if not original.existed:
                updater_owned = path in owned_updater_paths
                if path not in owned_changed_targets and path not in owned_temporaries and path not in owned_directories and not updater_owned:
                    failures.append(str(path))
                    continue
                if current.kind == "directory" and not path.is_symlink():
                    path.rmdir()
                else:
                    path.unlink(missing_ok=True)
            elif original.kind == "symlink":
                if path.exists() or path.is_symlink():
                    path.unlink()
                os.symlink(os.fsdecode(original.data or b""), path)
                os.chown(path, original.uid, original.gid, follow_symlinks=False)
                _fsync_directory(path.parent)
            elif original.kind == "file":
                temp = restore_temps.get(path)
                if temp is None:
                    failures.append(str(path))
                    continue
                _write_new(temp, original.data or b"", stat.S_IMODE(original.mode), original.uid, original.gid, owned=owned_temporaries)
                os.replace(temp, path)
                _fsync_directory(path.parent)
        except Exception:
            failures.append(str(path))
    for path in sorted((p for p in all_paths if images.get(p, Image(False)).kind == "directory"), key=lambda item: (-len(item.parts), str(item))):
        try:
            original = images[path]
            if _image(path) != original:
                os.chown(path, original.uid, original.gid)
                os.chmod(path, stat.S_IMODE(original.mode))
        except Exception:
            failures.append(str(path))
    return sorted(set(failures))


def refresh_legacy_certificate(
    *,
    on_trust_update: Callable[[], None] | None = None,
    on_path_change: Callable[[Path], None] | None = None,
) -> dict[str, Any]:
    """Generate and atomically install the legacy self-signed home.arpa pair."""
    if os.geteuid() != 0:
        return _receipt(False, "cert-refresh-root-required", observed={"runtimeConfig": str(appliance_runtime_path("config"))}, attempt="check-root")
    stage_names = [
        CERT_DIR / ".home.arpa-refresh.key.pem.new",
        CERT_DIR / ".home.arpa-refresh.cert.pem.new",
        CERT_DIR / ".home.arpa-refresh.cnf",
    ]
    trust_stage = TRUST_ANCHORS / ".home.arpa.crt.new"
    transaction_paths = [*stage_names, trust_stage]
    targets = [CERT_DIR, CERT_DIR / "key.pem", CERT_DIR / "cert.pem", *stage_names]
    trees: list[Path] = []
    inventory: dict[str, Any] = {}
    images: dict[Path, Image] = {}
    restore_temps: dict[Path, Path] = {}
    owned_temporaries: set[Path] = set()
    owned_directories: set[Path] = set()
    owned_changed_targets: set[Path] = set()
    temporary_files: set[Path] = set()
    owned_updater_paths: set[Path] = set()
    mutation = False
    stage = "preflight"
    attempted: list[str] = []
    changed_paths: list[str] = []
    sans: list[str] = []
    updater = {"enabled": False, "program": UPDATE_CA_CERTIFICATES}

    def record_path_change(path: Path) -> None:
        changed_paths.append(str(path))
        if on_path_change is not None:
            on_path_change(path)

    try:
        config = _load_config()
        sans = _subject_alt_names(config)
        inventory = prospective_mutable_inventory()
        updater = inventory["updater"]
        targets.extend(Path(item) for item in inventory["paths"])
        transaction_paths.extend(
            Path(item) for item in inventory["paths"]
            if Path(item).name.endswith((".new", ".cnf", ".restore"))
        )
        transaction_paths = list(dict.fromkeys(transaction_paths))
        trees = [Path(item) for item in inventory["trees"]]
        for tree in trees:
            targets.extend(_walk_tree(tree))
        images = {path: _image(path) for path in set(targets)}
        for path, image in tuple(images.items()):
            if image.kind != "file":
                continue
            temp = _restore_temp(path)
            if temp == path:
                raise Refusal("cert-refresh-temporary-seat-exists")
            if _image(temp).kind in {"file", "symlink"}:
                temp.unlink()  # a prior killed refresh left this verb's own restore name behind
            elif _image(temp).kind != "absent":
                raise Refusal("cert-refresh-temporary-seat-exists")
            restore_temps[path] = temp
            images[temp] = Image(False)
            transaction_paths.append(temp)
        for path in transaction_paths:
            if _image(path).kind in {"file", "symlink"} and path.name.startswith("."):
                path.unlink()  # this verb's own dot-named staging seat from a killed run
            if _image(path).kind != "absent":
                raise Refusal("cert-refresh-temporary-seat-exists")
            images.setdefault(path, Image(False))
        attempted = sorted(str(path) for path in images)
        cert_directory = _image(CERT_DIR)
        if cert_directory.kind not in {"absent", "directory"}:
            raise Refusal("cert-refresh-certificate-directory-refused")
        try:
            ssl_parent = os.lstat(CERT_DIR.parent)
        except OSError as error:
            raise Refusal("cert-refresh-certificate-parent-unavailable") from error
        if stat.S_ISLNK(ssl_parent.st_mode) or not stat.S_ISDIR(ssl_parent.st_mode):
            raise Refusal("cert-refresh-certificate-parent-refused")
        key_target_before = _safe_target(CERT_DIR / "key.pem")
        cert_target_before = _safe_target(CERT_DIR / "cert.pem")
        if updater.get("enabled"):
            for path in (TRUST_ANCHORS / "home.arpa.crt", trust_stage, TRUST_BUNDLE):
                _safe_target(path)
        try:
            ssl_gid = grp.getgrnam("ssl-cert").gr_gid
        except KeyError as error:
            raise Refusal("cert-refresh-ssl-cert-group-missing") from error
        _run(["/usr/sbin/usermod", "-a", "-G", "ssl-cert", "www-data"], 15)  # legacy sslKey.sh step, best effort
        if cert_directory.kind == "absent":
            stage = "create-certificate-directory"
            os.mkdir(CERT_DIR, 0o755)
            mutation = True
            owned_directories.add(CERT_DIR)
            owned_changed_targets.add(CERT_DIR)
            record_path_change(CERT_DIR)
            os.chown(CERT_DIR, 0, 0)
            os.chmod(CERT_DIR, 0o755)
            _fsync_directory(CERT_DIR.parent)
        config_text = (
            "[req]\nprompt = no\ndistinguished_name = dn\nx509_extensions = ext\n"
            "[dn]\nC = US\nST = State\nL = City\nO = HomeServer\nOU = IT\nCN = home.arpa\n"
            "[ext]\nbasicConstraints = CA:TRUE\n"
            "keyUsage = digitalSignature,keyEncipherment,keyCertSign\n"
            "subjectAltName = @alt_names\n[alt_names]\n"
            + "".join(f"DNS.{index} = {name}\n" for index, name in enumerate(sans, 1))
        ).encode("utf-8")
        stage = "stage-certificate"
        _write_new(stage_names[0], b"", 0o600, 0, 0, owned=owned_temporaries)
        mutation = True
        _write_new(stage_names[1], b"", 0o600, 0, 0, owned=owned_temporaries)
        _write_new(stage_names[2], config_text, 0o600, 0, 0, owned=owned_temporaries)
        generated = _run([
            OPENSSL, "req", "-x509", "-nodes", "-days", "824", "-newkey", "rsa:4096",
            "-keyout", str(stage_names[0]), "-out", str(stage_names[1]),
            "-config", str(stage_names[2]), "-extensions", "ext", "-sha256",
        ], 120)
        if generated is None or generated.returncode != 0:
            raise Refusal("cert-refresh-openssl-generation-failed")
        for path in stage_names[:2]:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        cert_check = _run([OPENSSL, "x509", "-in", str(stage_names[1]), "-noout", "-text"], 15)
        cert_identity = _run([OPENSSL, "x509", "-in", str(stage_names[1]), "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"], 15)
        cert_public = _run([OPENSSL, "x509", "-in", str(stage_names[1]), "-pubkey", "-noout"], 15)
        key_public = _run([OPENSSL, "pkey", "-in", str(stage_names[0]), "-pubout"], 15)
        if cert_check is None or cert_identity is None or cert_public is None or key_public is None:
            raise Refusal("cert-refresh-generated-pair-invalid")
        checks = (cert_check, cert_identity, cert_public, key_public)
        if any(result.returncode != 0 for result in checks):
            raise Refusal("cert-refresh-generated-pair-invalid")
        identity_lines = [line.split("=", 1)[1] for line in cert_identity.stdout.splitlines() if line.startswith(("subject=", "issuer="))]
        required_usage = ("Digital Signature", "Key Encipherment", "Certificate Sign")
        expected_dn = (("CN", "home.arpa"), ("OU", "IT"), ("O", "HomeServer"), ("L", "City"), ("ST", "State"), ("C", "US"))
        decoded_identity = []
        for identity in identity_lines:
            fields = []
            for field in identity.split(","):
                key, separator, value = field.partition("=")
                if not separator:
                    fields = []
                    break
                fields.append((key, value))
            decoded_identity.append(tuple(fields))
        if cert_public.stdout != key_public.stdout or "CA:TRUE" not in cert_check.stdout or decoded_identity != [expected_dn, expected_dn] or any(item not in cert_check.stdout for item in required_usage):
            raise Refusal("cert-refresh-generated-pair-invalid")
        actual_sans = re.findall(r"DNS:([^,\s]+)", cert_check.stdout, re.IGNORECASE)
        if any(name not in actual_sans for name in sans):
            raise Refusal("cert-refresh-san-readback-failed")
        stage = "replace-certificate-pair"
        if key_target_before.kind == "file":
            _safe_target(CERT_DIR / "key.pem")
        if cert_target_before.kind == "file":
            _safe_target(CERT_DIR / "cert.pem")
        _atomic_replace(stage_names[0], CERT_DIR / "key.pem", 0o640, 0, ssl_gid,
                        on_replace=record_path_change, owned_changed_targets=owned_changed_targets)
        _atomic_replace(stage_names[1], CERT_DIR / "cert.pem", 0o644, 0, ssl_gid,
                        on_replace=record_path_change, owned_changed_targets=owned_changed_targets)
        mutation = True
        trust_changes: list[str] = []
        if updater.get("enabled"):
            stage = "install-trust-anchor"
            anchor = TRUST_ANCHORS / "home.arpa.crt"
            anchor_image = _safe_target(anchor)
            certificate_bytes, _certificate_meta = _read_regular(CERT_DIR / "cert.pem", "cert-refresh-certificate-readback-failed")
            _write_new(trust_stage, certificate_bytes, 0o644, 0, 0, owned=owned_temporaries)
            os.replace(trust_stage, anchor)
            mutation = True
            owned_changed_targets.add(anchor)
            record_path_change(anchor)
            _fsync_directory(TRUST_ANCHORS)
            before_tree = {path: _image(path) for path in _walk_tree(TRUST_CERTS)}
            before_tree[TRUST_CERTS] = _image(TRUST_CERTS)
            stage = "update-system-trust"
            command = [UPDATE_CA_CERTIFICATES, *updater["arguments"]]
            env = dict(os.environ)
            env["TMPDIR"] = str(TRUST_CERTS)
            if on_trust_update is not None:
                on_trust_update()
            updated = _run(command, 90, env=env)
            after_paths = set(_walk_tree(TRUST_CERTS))
            after_tree = {path: _image(path) for path in after_paths}
            after_tree[TRUST_CERTS] = _image(TRUST_CERTS)
            all_trust_paths = set(before_tree) | set(after_tree)
            trust_changes = sorted(str(path) for path in all_trust_paths if before_tree.get(path, Image(False)) != after_tree.get(path, Image(False)))
            for path in trust_changes:
                owned_updater_paths.add(Path(path))
                record_path_change(Path(path))
            temporary_files.update(Path(path) for path in trust_changes if Path(path).name.endswith((".tmp", ".new", ".restore")) or ".tmp-" in Path(path).name)
            if updated is None or updated.returncode != 0:
                raise Refusal("cert-refresh-update-ca-certificates-failed")
            bundle = _image(TRUST_BUNDLE)
            if bundle.kind != "file" or _image(anchor).kind != "file":
                raise Refusal("cert-refresh-trust-readback-failed")
        final_pair = {
            "key": _image(CERT_DIR / "key.pem"),
            "cert": _image(CERT_DIR / "cert.pem"),
        }
        if final_pair["key"].kind != "file" or final_pair["cert"].kind != "file":
            raise Refusal("cert-refresh-pair-readback-failed")
        key_mode = stat.S_IMODE(final_pair["key"].mode)
        cert_mode = stat.S_IMODE(final_pair["cert"].mode)
        if (key_mode, final_pair["key"].uid, final_pair["key"].gid) != (0o640, 0, ssl_gid):
            raise Refusal("cert-refresh-key-metadata-readback-failed")
        if (cert_mode, final_pair["cert"].uid, final_pair["cert"].gid) != (0o644, 0, ssl_gid):
            raise Refusal("cert-refresh-certificate-metadata-readback-failed")
        _fsync_directory(CERT_DIR)
        temporary_files.update(owned_temporaries)
        return _receipt(
            True,
            observed={"runtimeConfig": str(appliance_runtime_path("config")), "trustUpdaterEnabled": bool(updater.get("enabled"))},
            could_change=attempted,
            attempt={"stage": "complete", "openssl": "req-x509-rsa4096", "trustUpdater": updater.get("program") if updater.get("enabled") else "not-needed"},
            final={"paths": sorted(set(changed_paths)), "subjectAltNames": sans,
                   "keyMode": f"{key_mode:04o}", "certificateMode": f"{cert_mode:04o}",
                   "keyUid": final_pair["key"].uid, "keyGid": final_pair["key"].gid,
                   "certificateUid": final_pair["cert"].uid, "certificateGid": final_pair["cert"].gid,
                   "owner": f"{final_pair['key'].uid}:{grp.getgrgid(final_pair['key'].gid).gr_name}"},
            mutation=mutation,
            subjectAltNames=sans,
            writtenPaths=sorted(set(changed_paths)),
            trustUpdater=updater,
            temporaryFiles=sorted(str(path) for path in temporary_files | owned_temporaries),
        )
    except Refusal as error:
        restore_failures: list[str] = []
        if mutation and images:
            restore_failures = _refresh_restore(images, trees, transaction_paths, restore_temps,
                                                owned_temporaries, owned_directories, owned_changed_targets, owned_updater_paths)
        final_paths: set[str] = set()
        for path, original in images.items():
            try:
                if _image(path) != original:
                    final_paths.add(str(path))
            except Exception:
                final_paths.add(str(path))
        for tree in trees:
            try:
                final_paths.update(str(path) for path in _walk_tree(tree) if path not in images)
            except Exception:
                final_paths.add(str(tree))
        return _receipt(
            False,
            error.signal if not restore_failures else "cert-refresh-rollback-failed",
            observed={"runtimeConfig": str(appliance_runtime_path("config"))},
            could_change=attempted,
            attempt={"stage": stage, "rollback": "failed" if restore_failures else "restored", "rollbackFailures": restore_failures},
            final={"changedPaths": sorted(final_paths), "subjectAltNames": sans},
            mutation=mutation,
            subjectAltNames=sans,
            writtenPaths=sorted(set(changed_paths)),
            trustUpdater=updater,
            rollbackFailures=restore_failures,
            temporaryFiles=sorted(str(path) for path in temporary_files | owned_temporaries),
        )
    except Exception:
        restore_failures = _refresh_restore(images, trees, transaction_paths, restore_temps,
                                            owned_temporaries, owned_directories, owned_changed_targets, owned_updater_paths) if mutation and images else []
        final_paths: set[str] = set()
        for path, original in images.items():
            try:
                if _image(path) != original:
                    final_paths.add(str(path))
            except Exception:
                final_paths.add(str(path))
        for tree in trees:
            try:
                final_paths.update(str(path) for path in _walk_tree(tree) if path not in images)
            except Exception:
                final_paths.add(str(tree))
        return _receipt(
            False,
            "cert-refresh-operation-failed" if not restore_failures else "cert-refresh-rollback-failed",
            observed={"runtimeConfig": str(appliance_runtime_path("config"))},
            could_change=attempted,
            attempt={"stage": stage, "rollback": "failed" if restore_failures else "restored", "rollbackFailures": restore_failures},
            final={"subjectAltNames": sans, "changedPaths": sorted(final_paths)},
            mutation=mutation,
            subjectAltNames=sans,
            writtenPaths=sorted(set(changed_paths)),
            trustUpdater=updater,
            rollbackFailures=restore_failures,
            temporaryFiles=sorted(str(path) for path in temporary_files | owned_temporaries),
        )
    finally:
        for path in owned_temporaries:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            if CERT_DIR.is_dir() and not CERT_DIR.is_symlink():
                _fsync_directory(CERT_DIR)
        except OSError:
            pass
        if updater.get("enabled"):
            try:
                if TRUST_ANCHORS.is_dir() and not TRUST_ANCHORS.is_symlink():
                    _fsync_directory(TRUST_ANCHORS)
            except OSError:
                pass


def _read_request() -> Request:
    stream = sys.stdin
    try:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    except (OSError, UnicodeError) as error:
        raise EnvelopeError("cert-refresh-request-invalid") from error
    if len(raw.encode("utf-8", "replace")) > MAX_INPUT_BYTES:
        raise EnvelopeError("cert-refresh-request-too-large")
    try:
        sys.stdin = StringIO(raw)
        return read(known_fields=("action", "operation", "state"), declared_flags=())
    finally:
        sys.stdin = stream


def _scrub(value: Any) -> Any:
    if isinstance(value, str):
        return "[REDACTED]" if SECRET_MARKER.search(value) else value
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub(item) for item in value]
    if isinstance(value, dict):
        result: dict[Any, Any] = {}
        for key, child in value.items():
            safe_key = _scrub(key) if isinstance(key, str) else key
            result[safe_key] = _scrub(child)
        return result
    return value


def _safe_request(request: Request) -> Request:
    value = _scrub(copy.deepcopy(request.value))
    payload = _scrub(copy.deepcopy(request.payload))
    raw = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return replace(
        request,
        value=value,
        payload=payload,
        raw_envelope=raw,
        intent_id=_scrub(request.intent_id),
        transition=_scrub(request.transition),
        version=_scrub(request.version),
        timestamp=_scrub(request.timestamp),
    )


def _has_executable_selector(value: Any) -> bool:
    if isinstance(value, Mapping):
        return bool(EXECUTABLE_SELECTORS.intersection(value))
    return False


def _has_nonempty_argv(value: Any) -> bool:
    if isinstance(value, Mapping):
        return "argv" in value and value["argv"] != []
    return False


def main(argv: Sequence[str] | None = None) -> int:
    request: Request | None = None
    try:
        args = list(sys.argv[1:] if argv is None else argv)
        request = _read_request()
        raw_payload = request.value.get("payload") if request.envelope and isinstance(request.value.get("payload"), Mapping) else {}
        carriers = [request.value, raw_payload]
        if args:
            raise Refusal("cert-refresh-arguments-refused")
        if any(_has_executable_selector(carrier) for carrier in carriers):
            raise Refusal("cert-refresh-executable-selector-refused")
        if any(_has_nonempty_argv(carrier) for carrier in carriers):
            raise Refusal("cert-refresh-request-invalid")
        result = refresh_legacy_certificate()
    except EnvelopeError:
        result = _receipt(False, "cert-refresh-request-invalid", observed={"source": "stdin"}, attempt="read-request")
    except Refusal as error:
        result = _receipt(False, error.signal, observed={"requestRead": request is not None}, attempt="validate-request")
    except Exception:
        result = _receipt(False, "cert-refresh-operation-failed", observed={"requestRead": request is not None}, attempt="bounded-operation")
    if request is not None:
        result = attach(result, _safe_request(request))
    result = _scrub(result)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

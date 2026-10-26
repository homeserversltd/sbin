"""NAS-rooted staff operations over the in-tree Linker core."""
from __future__ import annotations

from datetime import datetime, timezone
import copy
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any, Mapping

from agathodaimon.linker import core, link_index
from agathodaimon.linker.logger_utils import MUTATIONS, quiet_mutations, record_deed

SCHEMA = "caduceus.staff.v1"
BACKEND = "linker-staff-core"
KERNEL_KEYS = ("schema", "intent_id", "transition", "version", "timestamp")
MAX_INPUT = 1024 * 1024
REDACTED = "[REDACTED]"
_SECRET_NAMES = {
    "key", "keymaterial", "privatekey", "secretkey", "seed", "seedphrase",
    "token", "credential", "passphrase", "pin",
}


class StaffError(ValueError):
    def __init__(self, signal: str):
        super().__init__(signal)
        self.signal = signal


class RequestError(StaffError):
    pass



def _secret_name(name: object) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", str(name).lower())
    return "password" in normalized or normalized.endswith("pin") or normalized in _SECRET_NAMES


def _collect_secret_values(value: Any, found: set[str]) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _secret_name(key):
                _collect_strings(child, found)
            else:
                _collect_secret_values(child, found)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_secret_values(child, found)


def _collect_strings(value: Any, found: set[str]) -> None:
    if isinstance(value, str) and value:
        found.add(value)
    elif isinstance(value, Mapping):
        for child in value.values():
            _collect_strings(child, found)
    elif isinstance(value, (list, tuple)):
        for child in value:
            _collect_strings(child, found)


def _scrub(value: Any, secrets: set[str]) -> Any:
    if isinstance(value, Mapping):
        safe_mapping: dict[Any, Any] = {}
        for key, child in value.items():
            safe_key = _scrub(key, secrets) if isinstance(key, str) else key
            if safe_key in safe_mapping:
                marker = next(
                    (chr(code) for code in range(0xE000, 0xF8FF)
                     if all(chr(code) not in secret for secret in secrets)),
                    "_",
                )
                while safe_key in safe_mapping:
                    safe_key = f"{safe_key}{marker}"
            safe_mapping[safe_key] = REDACTED if _secret_name(key) else _scrub(child, secrets)
        return safe_mapping
    if isinstance(value, list):
        return [_scrub(child, secrets) for child in value]
    if isinstance(value, tuple):
        return [_scrub(child, secrets) for child in value]
    if isinstance(value, str):
        safe = value
        for secret in sorted(secrets, key=len, reverse=True):
            safe = safe.replace(secret, REDACTED)
        return safe
    return value


def _read_request() -> tuple[dict[str, Any], dict[str, Any], bool]:
    import sys
    try:
        raw = sys.stdin.read(MAX_INPUT + 1)
    except (OSError, UnicodeError):
        raise RequestError("linker-request-unreadable") from None
    if len(raw.encode("utf-8", "replace")) > MAX_INPUT:
        raise RequestError("linker-request-too-large")
    try:
        value = json.loads(raw)
    except (TypeError, json.JSONDecodeError, RecursionError):
        raise RequestError("linker-request-json-invalid") from None
    if not isinstance(value, dict):
        raise RequestError("linker-request-object-required")
    is_envelope = "schema" in value
    if is_envelope:
        if value.get("schema") != SCHEMA:
            raise RequestError("linker-envelope-schema-foreign")
        if any(key not in value for key in KERNEL_KEYS):
            raise RequestError("linker-envelope-kernel-missing")
        source = value.get("payload")
        payload = dict(source) if isinstance(source, Mapping) else {}
    else:
        nested = value.get("payload")
        payload = dict(nested) if isinstance(nested, Mapping) else dict(value)
    return value, payload, is_envelope


def _emit(receipt: dict[str, Any], request: tuple[dict[str, Any], dict[str, Any], bool] | None,
          secrets: set[str]) -> int:
    if request is not None and request[2]:
        value = request[0]
        carried = _scrub(copy.deepcopy(value), secrets)
        prior = carried.get("stamps")
        prior = list(prior) if isinstance(prior, list) else []
        stamp = {
            "verb": receipt.get("operation", "unknown"),
            "outcome": "ok" if receipt.get("ok") is True else "failed",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        if "stamps" not in value or isinstance(value.get("stamps"), list):
            carried["stamps"] = prior + [dict(stamp)]
        receipt.update(
            intent_id=_scrub(value.get("intent_id"), secrets),
            raw_envelope=json.dumps(carried, separators=(",", ":"), ensure_ascii=False),
            envelope=carried,
            stamps=prior + [dict(stamp)],
            staff=dict(stamp),
        )
    safe = _scrub(receipt, secrets)
    print(json.dumps(safe, separators=(",", ":"), ensure_ascii=False))
    return 0 if safe.get("ok") is True else 1


def _receipt(operation: str, ok: bool, signal: str, *, changed: bool | None = False,
             details: Any = None, observed: Any = None, attempt: Any = None,
             final: Any = None, could_change: list[str] | None = None) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "firstMissingSignal": signal,
        "mutationPerformed": changed,
        "backend": BACKEND,
        "operation": operation,
        "planned": False,
        "changed": changed,
        "details": details,
        "observed": observed,
        "could-change": could_change or [],
        "attempt": attempt,
        "final": final,
    }


def _failure(operation: str, signal: str, *, attempt: Any = None,
             observed: Any = None, changed: bool = False, details: Any = None) -> dict[str, Any]:
    return _receipt(operation, False, signal, changed=changed, details=details,
                    observed=observed, attempt=attempt,
                    final={"ok": False, "signal": signal},
                    could_change=[operation] if operation in {"delete", "deploy", "mkdir", "rename"} else [])


def _unknown_mutation(operation: str, signal: str, operation_path: Path,
                      before: list[dict[str, Any]], *, details: Any = None,
                      attempt: Any = None) -> dict[str, Any]:
    return _receipt(operation, False, signal, changed=None, details=details,
                    observed={"path": str(operation_path), "entries": before},
                    attempt=attempt or {"performed": True, "operation": operation},
                    final={"ok": False, "state": "unknown", "signal": signal},
                    could_change=[operation])


def _roots() -> tuple[Path, Path]:
    scratch = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    isolated = scratch is not None
    if isolated:
        if (not scratch or not Path(scratch).is_absolute() or Path(scratch) == Path("/")
                or any(part in {".", ".."} for part in scratch.split("/") if part)):
            raise StaffError("linker-scratch-root-invalid")
        base = Path(scratch)
        nas = base / "mnt" / "nas"
    else:
        nas = Path("/mnt/nas")
    try:
        nas_info = nas.lstat()
        if not stat.S_ISDIR(nas_info.st_mode) or stat.S_ISLNK(nas_info.st_mode):
            raise StaffError("linker-nas-root-unavailable")
        root = nas.resolve(strict=True)
    except StaffError:
        raise
    except OSError:
        raise StaffError("linker-nas-root-unavailable") from None
    return nas, root


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _path(raw: Any, nas: Path, root: Path, *, mutating: bool = False,
          require_exists: bool = False) -> tuple[Path, Path]:
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise RequestError("linker-path-invalid")
    supplied = Path(raw)
    if ".." in supplied.parts:
        raise StaffError("linker-path-outside-root")
    candidate = supplied if supplied.is_absolute() else nas / supplied
    try:
        lexical_relative = candidate.relative_to(nas)
    except ValueError:
        raise StaffError("linker-path-outside-root") from None
    cursor = nas
    for component in lexical_relative.parts:
        cursor = cursor / component
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError:
            raise StaffError("linker-path-unobservable") from None
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = cursor.resolve(strict=True)
            except (OSError, RuntimeError):
                raise StaffError("linker-path-unobservable") from None
            if not _inside(root, target):
                raise StaffError("linker-path-outside-root")
            if mutating:
                raise StaffError("linker-symlink-unsupported")
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        raise StaffError("linker-path-unobservable") from None
    if not _inside(root, resolved):
        raise StaffError("linker-path-outside-root")
    if require_exists and not candidate.exists():
        raise StaffError("linker-path-unavailable")
    return candidate, resolved


def _component(value: Any, field: str) -> str:
    if (not isinstance(value, str) or not value or value in {".", ".."}
            or "\x00" in value or "/" in value or "\\" in value):
        raise RequestError("linker-name-invalid")
    return value


def _require_directory(path: Path, *, signal: str = "linker-directory-unavailable") -> None:
    try:
        metadata = path.stat()
    except OSError:
        raise StaffError(signal) from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise StaffError(signal)


def _require_regular_or_directory(path: Path) -> str:
    try:
        metadata = path.lstat()
    except OSError:
        raise StaffError("linker-path-unavailable") from None
    if stat.S_ISREG(metadata.st_mode):
        return "file"
    if stat.S_ISDIR(metadata.st_mode):
        return "directory"
    raise StaffError("linker-path-type-unsupported")


def _entry_target(path: Path, root: Path) -> os.stat_result:
    try:
        link_meta = path.lstat()
    except OSError:
        raise StaffError("linker-listing-unobservable") from None
    if stat.S_ISLNK(link_meta.st_mode):
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise StaffError("linker-listing-unobservable") from None
        if not _inside(root, resolved):
            raise StaffError("linker-path-outside-root")
        try:
            return path.stat()
        except OSError:
            raise StaffError("linker-listing-unobservable") from None
    return link_meta


def _listing(path: Path, root: Path) -> tuple[list[dict[str, Any]], tuple[Any, ...]]:
    _require_directory(path, signal="linker-listing-unavailable")
    rows: list[dict[str, Any]] = []
    identity: list[tuple[Any, ...]] = []
    try:
        with os.scandir(path) as iterator:
            entries = list(iterator)
    except OSError:
        raise StaffError("linker-listing-unobservable") from None
    for entry in entries:
        child = Path(entry.path)
        metadata = _entry_target(child, root)
        is_dir = stat.S_ISDIR(metadata.st_mode)
        nlink = metadata.st_nlink
        rows.append({
            "name": entry.name,
            "path": str(child),
            "is_dir": is_dir,
            "is_hardlink": nlink > 1 and not is_dir,
            "nlink": nlink,
        })
        identity.append((entry.name, metadata.st_dev, metadata.st_ino, metadata.st_mode,
                         metadata.st_nlink, metadata.st_mtime_ns))
    rows.sort(key=lambda item: item["name"])
    identity.sort(key=lambda item: item[0])
    return rows, tuple(identity)


def _tree(source: Path, root: Path) -> tuple[str, list[Path]]:
    kind = _require_regular_or_directory(source)
    paths = [source]
    if kind == "file":
        return kind, paths
    pending = [source]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = list(iterator)
        except OSError:
            raise StaffError("linker-source-unobservable") from None
        for entry in entries:
            child = Path(entry.path)
            try:
                metadata = child.lstat()
            except OSError:
                raise StaffError("linker-source-unobservable") from None
            if stat.S_ISLNK(metadata.st_mode):
                try:
                    target = child.resolve(strict=True)
                except (OSError, RuntimeError):
                    raise StaffError("linker-source-unobservable") from None
                if not _inside(root, target):
                    raise StaffError("linker-path-outside-root")
                raise StaffError("linker-symlink-unsupported")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(child)
            elif not stat.S_ISREG(metadata.st_mode):
                raise StaffError("linker-source-type-unsupported")
            paths.append(child)
    return kind, paths


def _tree_signature(path: Path, root: Path) -> tuple[Any, ...] | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError:
        raise StaffError("linker-target-unobservable") from None
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = path.resolve(strict=True)
        except (OSError, RuntimeError):
            raise StaffError("linker-target-unobservable") from None
        if not _inside(root, target):
            raise StaffError("linker-path-outside-root")
        raise StaffError("linker-symlink-unsupported")
    kind, paths = _tree(path, root)
    signature = []
    for item in paths:
        try:
            item_info = item.lstat()
        except OSError:
            raise StaffError("linker-target-unobservable") from None
        signature.append((item.relative_to(path).as_posix(), item_info.st_dev,
                          item_info.st_ino, item_info.st_mode, item_info.st_nlink,
                          item_info.st_mtime_ns))
    return (kind, tuple(sorted(signature)))


def _preflight_target(path: Path, nas: Path, root: Path) -> None:
    try:
        relative = path.relative_to(nas)
    except ValueError:
        raise StaffError("linker-path-outside-root") from None
    cursor = nas
    for component in relative.parts:
        cursor = cursor / component
        try:
            metadata = cursor.lstat()
        except FileNotFoundError:
            break
        except OSError:
            raise StaffError("linker-path-unobservable") from None
        if stat.S_ISLNK(metadata.st_mode):
            try:
                target = cursor.resolve(strict=True)
            except (OSError, RuntimeError):
                raise StaffError("linker-path-unobservable") from None
            if not _inside(root, target):
                raise StaffError("linker-path-outside-root")
            raise StaffError("linker-symlink-unsupported")
    try:
        resolved = path.resolve(strict=False)
    except (OSError, RuntimeError):
        raise StaffError("linker-path-unobservable") from None
    if not _inside(root, resolved):
        raise StaffError("linker-path-outside-root")


def _required(payload: Mapping[str, Any], field: str) -> Any:
    if field not in payload or payload[field] is None:
        raise RequestError("linker-field-required")
    return payload[field]


def _read_operation(verb: str, payload: Mapping[str, Any], nas: Path, root: Path) -> dict[str, Any]:
    raw_path = _required(payload, "path")
    _lexical, path = _path(raw_path, nas, root)
    _require_directory(path, signal="linker-directory-unavailable")
    listing, _identity = _listing(path, root)
    details = {"path": str(path), "entries": listing}
    receipt = _receipt(verb, True, "none", changed=False, details=details,
                       observed={"path": str(path)}, attempt={"performed": False},
                       final={"ok": True, "entries": len(listing)}, could_change=[])
    receipt["entries"] = listing
    return receipt


def _hardlink_scan(payload: Mapping[str, Any], nas: Path, root: Path) -> dict[str, Any]:
    _lexical, path = _path(_required(payload, "path"), nas, root)
    _require_directory(path, signal="linker-directory-unavailable")
    listing, _identity = _listing(path, root)
    try:
        found = link_index.scan_hardlinks(path)
    except StaffError:
        raise
    except Exception:
        raise StaffError("linker-hardlink-scan-failed") from None
    if len(found) != len(listing):
        raise StaffError("linker-hardlink-scan-incomplete")
    expected = {entry["name"]: (entry["is_dir"], entry["is_hardlink"], entry["nlink"])
                for entry in listing}
    rows = []
    for entry in found:
        entry_path = Path(entry.path)
        _path(str(entry_path), nas, root)
        observed = (bool(entry.is_dir), bool(entry.is_hardlink), int(entry.nlink))
        if entry_path.name not in expected or expected[entry_path.name] != observed:
            raise StaffError("linker-hardlink-scan-inconsistent")
        rows.append({
            "name": entry_path.name,
            "path": str(entry_path),
            "is_dir": bool(entry.is_dir),
            "is_hardlink": bool(entry.is_hardlink),
            "nlink": int(entry.nlink),
        })
    rows.sort(key=lambda item: item["name"])
    receipt = _receipt("hardlink-scan", True, "none", changed=False,
                       details={"path": str(path), "entries": rows},
                       observed={"path": str(path), "entries": len(listing)},
                       attempt={"performed": False, "backendCall": "scan_hardlinks"},
                       final={"ok": True, "entries": len(rows)}, could_change=[])
    receipt["entries"] = rows
    return receipt


def _parent_path(path: Path, nas: Path, root: Path) -> Path:
    parent = path.parent
    _preflight_target(parent, nas, root)
    _require_directory(parent)
    return parent


def _mutate(verb: str, payload: Mapping[str, Any], nas: Path, root: Path) -> dict[str, Any]:
    parent: Path | None = None
    source: Path | None = None
    new_name: str | None = None
    if verb == "mkdir":
        parent_raw = _required(payload, "path")
        parent_lexical, parent = _path(parent_raw, nas, root, mutating=True, require_exists=True)
        _require_directory(parent)
        new_name = _component(_required(payload, "new_dir_name"), "new_dir_name")
        target = parent / new_name
        _preflight_target(target, nas, root)
        operation_path = parent
    elif verb == "rename":
        source_raw = _required(payload, "path")
        _source_lexical, source = _path(source_raw, nas, root, mutating=True, require_exists=True)
        if source == root:
            raise StaffError("linker-root-mutation-refused")
        if _require_regular_or_directory(source) != "directory":
            raise StaffError("linker-rename-directory-required")
        _tree(source, root)
        new_name = _component(_required(payload, "new_name"), "new_name")
        target = source.parent / new_name
        _preflight_target(target, nas, root)
        operation_path = _parent_path(source, nas, root)
    elif verb == "delete":
        source_raw = _required(payload, "path")
        _source_lexical, source = _path(source_raw, nas, root, mutating=True, require_exists=True)
        if source == root:
            raise StaffError("linker-root-mutation-refused")
        if _require_regular_or_directory(source) == "directory":
            _tree(source, root)
        target = source
        operation_path = _parent_path(source, nas, root)
    elif verb == "deploy":
        raw_sources = _required(payload, "sources")
        raw_destination = _required(payload, "destination")
        strategy = payload.get("conflict_strategy", "rename")
        if not isinstance(raw_sources, list) or not raw_sources:
            raise RequestError("linker-sources-invalid")
        if not isinstance(strategy, str) or strategy not in {"fail", "skip", "overwrite", "rename"}:
            raise RequestError("linker-conflict-strategy-invalid")
        destination_lexical, destination = _path(raw_destination, nas, root,
                                                   mutating=True, require_exists=True)
        _require_directory(destination)
        source_plans: list[tuple[Path, str, list[Path], Path, tuple[Any, ...] | None]] = []
        target_names: set[str] = set()
        for raw_source in raw_sources:
            source_lexical, source = _path(raw_source, nas, root,
                                            mutating=True, require_exists=True)
            if source == root:
                raise StaffError("linker-root-source-refused")
            kind, members = _tree(source, root)
            target = destination / source.name
            if source.name in target_names:
                raise StaffError("linker-deploy-target-collision")
            target_names.add(source.name)
            if kind == "directory":
                if target == source or target in source.parents or source in target.parents:
                    raise StaffError("linker-deploy-source-target-overlap")
            elif target == source:
                raise StaffError("linker-deploy-source-target-overlap")
            for member in members:
                relative = member.relative_to(source)
                derived = target if relative == Path(".") else target / relative
                _preflight_target(derived, nas, root)
            target_signature = _tree_signature(target, root)
            source_plans.append((source, kind, members, target, target_signature))
        operation_path = destination
        before, before_identity = _listing(operation_path, root)
        outcomes = []
        any_failed = False
        try:
            for source, kind, members, target, _target_signature in source_plans:
                try:
                    result = core.create_hardlink(source, destination, None, strategy)
                    result_ok = bool(result)
                except Exception:
                    result_ok = False
                outcomes.append({"source": str(source), "target": str(target), "coreResult": result_ok})
                any_failed = any_failed or not result_ok
        except Exception:
            return _unknown_mutation(
                verb, "linker-deploy-outcome-unknown", operation_path, before,
                details={"conflict_strategy": strategy, "results": outcomes},
                attempt={"performed": True, "sources": len(source_plans)},
            )
        try:
            after, after_identity = _listing(operation_path, root)
        except StaffError as error:
            return _unknown_mutation(
                verb, error.signal, operation_path, before,
                details={"conflict_strategy": strategy, "results": outcomes},
                attempt={"performed": True, "sources": len(source_plans)},
            )
        except Exception:
            return _unknown_mutation(
                verb, "linker-deploy-outcome-unknown", operation_path, before,
                details={"conflict_strategy": strategy, "results": outcomes},
                attempt={"performed": True, "sources": len(source_plans)},
            )
        try:
            target_signatures = [_tree_signature(plan[3], root) for plan in source_plans]
        except StaffError as error:
            return _unknown_mutation(
                verb, error.signal, operation_path, before,
                details={"conflict_strategy": strategy, "results": outcomes},
                attempt={"performed": True, "sources": len(source_plans)},
            )
        except Exception:
            return _unknown_mutation(
                verb, "linker-deploy-outcome-unknown", operation_path, before,
                details={"conflict_strategy": strategy, "results": outcomes},
                attempt={"performed": True, "sources": len(source_plans)},
            )
        try:
            changed = before_identity != after_identity or any(
                before_target != after_target
                for before_target, after_target in zip(
                    [plan[4] for plan in source_plans], target_signatures
                )
            )
            ok = not any_failed
            signal = "none" if ok else "linker-deploy-failed"
            receipt = _receipt(verb, ok, signal, changed=changed,
                               details={"conflict_strategy": strategy, "results": outcomes, "entries": after},
                               observed={"path": str(operation_path), "entries": before},
                               attempt={"performed": True, "sources": len(source_plans)},
                               final={"ok": ok, "path": str(operation_path), "entries": len(after)},
                               could_change=[verb])
            receipt["entries"] = after
            return receipt
        except Exception:
            return _unknown_mutation(
                verb, "linker-deploy-outcome-unknown", operation_path, before,
                details={"conflict_strategy": strategy, "results": outcomes},
                attempt={"performed": True, "sources": len(source_plans)},
            )
    else:
        raise RequestError("linker-verb-unknown")

    before, before_identity = _listing(operation_path, root)
    try:
        if verb == "mkdir":
            assert parent is not None and new_name is not None
            result = core.create_directory(parent, new_name)
        elif verb == "rename":
            assert source is not None and new_name is not None
            result = core.rename_directory(source, new_name)
        else:
            assert source is not None
            result = core.delete_path(source)
        core_ok = isinstance(result, dict) and result.get("ok") is True
        status = result.get("status") if isinstance(result, dict) else "failed"
        after, after_identity = _listing(operation_path, root)
    except StaffError as error:
        return _unknown_mutation(verb, error.signal, operation_path, before)
    except Exception:
        return _unknown_mutation(verb, "linker-mutation-outcome-unknown", operation_path, before)
    try:
        changed = before_identity != after_identity
        ok = core_ok
        signal = "none" if ok else f"linker-{verb}-refused-or-failed"
        receipt = _receipt(verb, ok, signal, changed=changed,
                           details={"status": status, "entries": after},
                           observed={"path": str(operation_path), "entries": before},
                           attempt={"performed": True},
                           final={"ok": ok, "path": str(operation_path), "entries": len(after)},
                           could_change=[verb])
        receipt["entries"] = after
        return receipt
    except Exception:
        return _unknown_mutation(verb, "linker-mutation-outcome-unknown", operation_path, before)


def main_for(verb: str, argv: list[str] | None = None) -> int:
    started = time.monotonic()
    request = None
    secrets: set[str] = set()
    try:
        request = _read_request()
        _collect_secret_values(request[0], secrets)
        _collect_secret_values(request[1], secrets)
        if argv:
            raise RequestError("linker-argv-not-supported")
        nas, root = _roots()
        if verb in {"browse", "hardlink-scan"}:
            receipt = (_read_operation(verb, request[1], nas, root)
                       if verb == "browse" else _hardlink_scan(request[1], nas, root))
        elif verb in {"delete", "deploy", "mkdir", "rename"}:
            with quiet_mutations():
                receipt = _mutate(verb, request[1], nas, root)
        else:
            raise RequestError("linker-verb-unknown")
    except StaffError as error:
        receipt = _failure(verb, error.signal)
    except Exception:
        receipt = _failure(verb, "linker-staff-operation-failed")
    if verb in MUTATIONS:
        try:
            record_deed(verb, receipt["ok"], receipt["firstMissingSignal"], started)
        except (OSError, ValueError):
            if receipt["ok"]:
                receipt.update(ok=False, firstMissingSignal="linker-ledger-write-failed")
    return _emit(receipt, request, secrets)


def main(argv=None):
    import json
    args = list(argv or [])
    if args and args != ["--help"]:
        print(json.dumps(_failure("linker", "linker-verb-unknown"), separators=(",", ":")))
        return 1
    print(json.dumps({"schema": SCHEMA, "ok": True, "firstMissingSignal": "none",
                      "noun": "linker",
                      "verbs": ["browse", "delete", "deploy", "hardlink-scan", "mkdir", "rename", "tui"],
                      "mutationPerformed": False}, separators=(",", ":")))
    return 0

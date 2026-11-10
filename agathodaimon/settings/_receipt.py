"""Receipt handling shared by settings families."""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any


class Receipt:
    def __init__(self, kind: str, fields: list[str], schema: str | None = None) -> None:
        root = Path(os.environ.get("CADUCEUS_RECEIPT_ROOT", "/var/lib/caduceus/receipts"))
        self.run_dir = root / str(uuid.uuid4())
        self.run_dir.mkdir(parents=True, exist_ok=False)
        self.kind = kind
        self.fields = fields
        self.schema = schema
        self.backups: list[dict[str, Any]] = []
        self._saved: dict[Path, bytes | None] = {}
        self.commands: list[dict[str, Any]] = []
        self.changed = False
        self.timezone_command_performed = False

    def backup(self, path: Path) -> None:
        if path in self._saved:
            return
        existed = path.exists()
        original = path.read_bytes() if existed else None
        self._saved[path] = original
        stat_result = path.stat() if existed else None
        mode = (stat_result.st_mode & 0o777) if stat_result else None
        self.backups.append({"path": str(path), "bytes": len(original) if original is not None else 0, "mode": mode, "uid": stat_result.st_uid if stat_result else None, "gid": stat_result.st_gid if stat_result else None, "existed": existed})

    def replace(self, path: Path, payload: bytes) -> bool:
        if path.exists() and path.read_bytes() == payload:
            return False
        self.backup(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as handle:
                temporary = Path(handle.name)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            self.changed = True
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return True

    def rollback(self, path: Path, payload: bytes) -> None:
        if path.exists() and path.read_bytes() == payload:
            return
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.rollback.", delete=False) as handle:
                temporary = Path(handle.name); handle.write(payload); handle.flush(); os.fsync(handle.fileno())
            os.chmod(temporary, mode); os.replace(temporary, path)
            fd = os.open(path.parent, os.O_RDONLY)
            try: os.fsync(fd)
            finally: os.close(fd)
        finally:
            if temporary is not None: temporary.unlink(missing_ok=True)

    def restore_backups(self) -> None:
        for path, payload in reversed(list(self._saved.items())):
            if payload is None:
                path.unlink(missing_ok=True)
            else:
                self.rollback(path, payload)
                metadata = next(item for item in self.backups if item["path"] == str(path))
                if metadata["mode"] is not None: os.chmod(path, metadata["mode"])
                current = path.stat()
                if (current.st_uid, current.st_gid) != (metadata["uid"], metadata["gid"]):
                    os.chown(path, metadata["uid"], metadata["gid"])
        self.changed = False

    def finish(self, ok: bool, changed: bool = False, error: str | None = None) -> dict[str, Any]:
        metadata = {"ok": ok, "changed": bool(changed), "kind": self.kind, "fields": self.fields,
                    "backups": self.backups, "commands": self.commands}
        if self.schema is not None:
            metadata["schema"] = self.schema
        if ok:
            (self.run_dir / "run.json").write_text(json.dumps(metadata, sort_keys=True) + "\n", encoding="utf-8")
            result = {"ok": True, "changed": bool(changed), "receiptPath": str(self.run_dir / "run.json"), "receipt": metadata}
        else:
            self.run_dir.rmdir()
            result = {"ok": False, "firstMissingSignal": error or "failure", "receipt": metadata}
        if self.schema is not None:
            result["schema"] = self.schema
        return result

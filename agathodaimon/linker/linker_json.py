#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""One-shot JSON adapter for Linker's retained filesystem operations."""

import json
import pathlib
import sys
from typing import Any

from agathodaimon.linker.core import create_directory, create_hardlink, delete_path, rename_directory
from agathodaimon.linker.link_index import scan_hardlinks
from agathodaimon._envelope import appliance_runtime_path
from agathodaimon.linker.logger_utils import json_deed

NAS_ROOT = (appliance_runtime_path("config").parents[2] / "mnt/nas").resolve()
CONFLICT_STRATEGIES = {"fail", "skip", "overwrite", "rename"}


class AdapterError(Exception):
    """A malformed adapter request or an attempt to leave the NAS boundary."""


def emit(payload: dict[str, Any]) -> None:
    json.dump(payload, sys.stdout, sort_keys=True, separators=(",", ":"))
    sys.stdout.write("\n")


def require_string(request: dict[str, Any], field: str) -> str:
    value = request.get(field)
    if not isinstance(value, str) or not value:
        raise AdapterError(f"{field} must be a non-empty string")
    return value


def nas_path(value: str) -> pathlib.Path:
    path = pathlib.Path(value).resolve(strict=False)
    if path != NAS_ROOT and NAS_ROOT not in path.parents:
        raise AdapterError(f"path outside /mnt/nas: {value}")
    return path


def child_name(value: str) -> str:
    if not value or value in {".", ".."} or pathlib.Path(value).name != value:
        raise AdapterError("new_name must be a single directory name")
    return value


def scan_payload(path: pathlib.Path) -> list[dict[str, Any]]:
    return [
        {
            "path": str(entry.path),
            "name": entry.path.name,
            "nlink": entry.nlink,
            "inode": entry.inode,
            "is_dir": entry.is_dir,
            "is_hardlink": entry.is_hardlink,
        }
        for entry in scan_hardlinks(path)
    ]


def browse(path: pathlib.Path) -> dict[str, Any]:
    try:
        hardlinks = {entry.path.name: entry for entry in scan_hardlinks(path) if not entry.is_dir}
        entries = [entry for entry in path.iterdir() if not entry.name.startswith(".")]
        entries.sort(key=lambda entry: (not entry.is_dir(), entry.name.lower()))
    except OSError as error:
        return {"ok": False, "operation": "browse", "status": "failed", "error": str(error)}

    return {
        "ok": True,
        "operation": "browse",
        "path": str(path),
        "entries": [
            {
                "name": entry.name,
                "path": str(entry),
                "is_dir": entry.is_dir(),
                "is_hardlink": bool(hardlinks.get(entry.name) and hardlinks[entry.name].is_hardlink),
                "nlink": hardlinks[entry.name].nlink if entry.name in hardlinks else 1,
            }
            for entry in entries
        ],
    }


@json_deed
def run(request: dict[str, Any]) -> tuple[dict[str, Any], int]:
    operation = require_string(request, "operation")

    if operation == "browse":
        return browse(nas_path(require_string(request, "path"))), 0

    if operation == "hardlink-scan":
        path = nas_path(require_string(request, "path"))
        return {"ok": True, "operation": operation, "path": str(path), "entries": scan_payload(path)}, 0

    if operation == "deploy":
        destination = nas_path(require_string(request, "destination"))
        sources = request.get("sources")
        if not isinstance(sources, list) or not sources or not all(isinstance(source, str) and source for source in sources):
            raise AdapterError("sources must be a non-empty array of paths")
        strategy = request.get("conflict_strategy", "rename")
        if strategy not in CONFLICT_STRATEGIES:
            raise AdapterError("conflict_strategy must be fail, skip, overwrite, or rename")
        results = []
        for source_value in sources:
            source = nas_path(source_value)
            success = create_hardlink(source=source, destination_dir=destination, name=None, conflict_strategy=strategy)
            results.append({"source": str(source), "success": success})
        return {
            "ok": all(result["success"] for result in results),
            "operation": operation,
            "destination": str(destination),
            "conflict_strategy": strategy,
            "results": results,
        }, 0

    if operation == "delete":
        path = nas_path(require_string(request, "path"))
        result = delete_path(path)
        return {"operation": operation, "path": str(path), **result}, 0

    if operation == "rename":
        path = nas_path(require_string(request, "path"))
        new_name = child_name(require_string(request, "new_name"))
        target = nas_path(str(path.parent / new_name))
        result = rename_directory(path, new_name)
        return {"operation": operation, "path": str(path), "target": str(target), **result, "path": str(path)}, 0

    if operation == "mkdir":
        path = nas_path(require_string(request, "path"))
        new_name = child_name(require_string(request, "new_dir_name"))
        target = nas_path(str(path / new_name))
        result = create_directory(path, new_name)
        return {"operation": operation, "path": str(path), "target": str(target), **result, "path": str(path)}, 0

    raise AdapterError(f"unsupported operation: {operation}")


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise AdapterError("request must be a JSON object")
        payload, exit_code = run(request)
    except (AdapterError, json.JSONDecodeError) as error:
        payload, exit_code = {"ok": False, "status": "adapter_error", "error": str(error)}, 2
    except Exception as error:
        payload, exit_code = {"ok": False, "status": "adapter_error", "error": str(error)}, 2
    emit(payload)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

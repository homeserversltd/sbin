"""Bounded native Tailscale staff verbs and rollback-safe tailnet changes."""
from __future__ import annotations

import copy
import datetime
import fcntl
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, replace
from io import StringIO
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from agathodaimon._envelope import EnvelopeError, Request, appliance_runtime_path, attach, read

from agathodaimon.network.tailscale._core import (
    NOUN,
    VERBS,
    SCHEMA,
    TAILSCALE,
    KEA_CONFIG,
    NGINX,
    SYSTEMCTL,
    MAX_BYTES,
    KEY_PATTERN,
    NAME_PATTERN,
    LOGIN_URL,
    SECRET_MARKER,
    SITES_AVAILABLE,
    NGINX_CONF_D,
    OG_CONFIG,
    BACKUP_ROOT,
    Refused,
    TransactionInterrupted,
    Image,
    _receipt,
    _scrub,
    _safe_request,
    _kill_process_group,
    _run,
    _status,
    _read_regular,
    _load_runtime_config,
    _cors,
    _origin_label,
    _served_certificate_sans,
    _declared_tailnet,
    _home_routes,
    _preferences,
    _prepare_home,
    _validate_backup_argument,
    _tailnet_label_from_url,
    _rewrite_remote,
    _config_parts,
    _rewrite_config,
    _plan_runtime_config,
    _plan_optional_config,
    _image,
    _walk_tree,
    _snapshot,
    _within,
    _nginx_sources,
    _rewrite_nginx,
    _nginx_plan,
    _safe_components,
    _mkdir_chain,
    _fsync_directory,
    _write_all,
    _backup,
    _atomic_write,
    _restore,
    _certificate_module,
    _safe_backup_parent,
    _refuse_backup_overlap,
    _image_if_regular,
    _tls_readback,
    _signal_handlers,
    _current_tree_paths,
    _tailnet,
    _status_receipt,
    _up_receipt,
    _down_receipt,
    _authkey_receipt,
)

def _request() -> Request:
    stream = sys.stdin
    try:
        raw = stream.read()
    except (OSError, UnicodeError) as error:
        raise EnvelopeError("staff envelope read failed") from error
    if not raw.strip():
        return Request({}, False, {}, raw)
    try:
        sys.stdin = StringIO(raw)
        return read(
            known_fields=("action", "operation", "state", "key", "authkey", "name", "backup-dir", "backup_dir", "backupDir", "args"),
            declared_flags=("key", "authkey", "name", "backup-dir", "backup_dir", "backupDir"),
        )
    finally:
        sys.stdin = stream


def _parse(action_args: Sequence[str], request: Request) -> tuple[str, dict[str, str]]:
    args = list(action_args)
    payload = request.payload if isinstance(request.payload, Mapping) else {}
    if not args and "args" in payload:
        if not isinstance(payload["args"], list) or any(not isinstance(item, str) for item in payload["args"]):
            raise Refused("tailscale-arguments-invalid")
        args = list(payload["args"])
    allowed_actions = set(VERBS)
    action = args.pop(0) if args and args[0] in allowed_actions else None
    if action is None:
        for source in (payload, request.value):
            if isinstance(source, Mapping):
                candidate = next((source.get(key) for key in ("action", "operation", "state") if isinstance(source.get(key), str)), None)
                if candidate in allowed_actions:
                    action = candidate
                    break
    if action is None and request.verb in allowed_actions:
        action = request.verb
    if action is None:
        raise Refused("tailscale-operation-required")

    values: dict[str, str] = {}
    sources = [payload] + ([request.value] if isinstance(request.value, Mapping) else [])
    for source in sources:
        for field in ("key", "authkey", "name", "backup-dir", "backup_dir", "backupDir"):
            if field not in source:
                continue
            value = source[field]
            if not isinstance(value, str):
                raise Refused("tailscale-envelope-option-invalid")
            dest = "key" if field in {"key", "authkey"} else "name" if field == "name" else "backup-dir"
            if dest in values and values[dest] != value:
                raise Refused("tailscale-envelope-option-conflict")
            values[dest] = value
    seen: set[str] = set()
    index = 0
    while index < len(args):
        item = args[index]
        if item in {"--key", "--authkey", "--name", "--backup-dir"}:
            if index + 1 >= len(args) or args[index + 1].startswith("--"):
                raise Refused("tailscale-option-value-missing")
            flag, value = item, args[index + 1]
            index += 2
        elif any(item.startswith(prefix) for prefix in ("--key=", "--authkey=", "--name=", "--backup-dir=")):
            flag, value = item.split("=", 1)
            index += 1
        else:
            raise Refused("tailscale-arguments-invalid")
        dest = "key" if flag in {"--key", "--authkey"} else "name" if flag == "--name" else "backup-dir"
        if dest in seen:
            raise Refused("tailscale-option-duplicate")
        seen.add(dest)
        if dest in values and values[dest] != value:
            raise Refused("tailscale-envelope-option-conflict")
        values[dest] = value
    allowed = {"status": set(), "up": set(), "down": set(), "authkey": {"key"}, "tailnet": {"name", "backup-dir"}}[action]
    if set(values) - allowed:
        raise Refused("tailscale-option-not-admitted")
    return action, values


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["--help"]:
        print(json.dumps({"schema": SCHEMA, "verbs": ["status", "up", "down", "authkey --key <k>", "tailnet --name <n> [--backup-dir <absolute-path>]"]}, sort_keys=True))
        return 0
    request: Request | None = None
    try:
        request = _request()
        action, values = _parse(args, request)
        safe = _safe_request(request)
        if action == "status":
            result = _status_receipt()
        elif action == "up":
            result = _up_receipt()
        elif action == "down":
            result = _down_receipt()
        elif action == "authkey":
            result = _authkey_receipt(values.get("key"))
        else:
            result = _tailnet(values.get("name", ""), values.get("backup-dir"))
        result = attach(result, safe)
    except EnvelopeError:
        result = _receipt("unknown", False, "tailscale-envelope-invalid", attempt="read-envelope")
    except Refused as error:
        result = _receipt("unknown", False, error.signal, attempt="validate-request")
        if request is not None:
            result = attach(result, _safe_request(request))
    except Exception:
        result = _receipt("unknown", False, "tailscale-operation-failed", attempt="bounded-operation")
        if request is not None:
            result = attach(result, _safe_request(request))
    result = _scrub(result)
    print(json.dumps(result, sort_keys=True, ensure_ascii=False))
    return 0 if result.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())

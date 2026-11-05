"""Surgical INI helpers for settings."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from agathodaimon.settings._receipt import Receipt


def ini_read(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8").splitlines(keepends=True)
    except OSError:
        return []


def ini_get(lines: Iterable[str], key: str, section: str | None = None) -> str | None:
    active: str | None = None
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            active = stripped[1:-1].strip()
        if section is not None and active != section:
            continue
        match = re.match(r"^\s*" + re.escape(key) + r"\s*=\s*(.*?)\s*(?:[;#].*)?$", line)
        if match:
            return match.group(1).strip()
    return None


def ini_set(lines: list[str], key: str, value: str, section: str | None = None) -> list[str]:
    out: list[str] = []
    active: str | None = None
    replaced = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if section is not None and active == section and not replaced:
                out.append(f"{key}={value}\n")
                replaced = True
            active = stripped[1:-1].strip()
        if (section is None or active == section) and re.match(r"^\s*" + re.escape(key) + r"\s*=", line):
            if not replaced:
                prefix = line[: len(line) - len(line.lstrip())]
                out.append(f"{prefix}{key}={value}\n")
                replaced = True
            continue
        out.append(line)
    if section is not None and active == section and not replaced:
        out.append(f"{key}={value}\n")
        replaced = True
    if not replaced:
        if out and not out[-1].endswith("\n"):
            out[-1] += "\n"
        if section is not None:
            out.append(f"\n[{section}]\n")
        out.append(f"{key}={value}\n")
    return out


def set_file_value(receipt: Receipt, path: Path, key: str, value: str, section: str | None = None) -> None:
    lines = ini_read(path)
    receipt.replace(path, "".join(ini_set(lines, key, value, section)).encode())

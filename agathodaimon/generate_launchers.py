#!/usr/bin/env python3
"""Regenerate the Python-selection convention in Caduceus launchers.

GTK/PyGObject is supplied by the system Python. Launchers for the ``gui`` and
``settings`` nouns therefore execute ``/usr/bin/python3`` directly. Every
other Python launcher retains the Agathodaimon venv preference and system
fallback.
"""
from __future__ import annotations
import argparse
import re
from pathlib import Path

SYSTEM_PYTHON_NOUNS = frozenset({"gui", "settings"})
VENV_PREAMBLE = "PYTHON=${AGATHODAIMON_PYTHON:-/var/lib/caduceus/venv/bin/python3}\n[ -x \"$PYTHON\" ] || PYTHON=python3\n"
SYSTEM_PREAMBLE = "PYTHON=/usr/bin/python3\n"
PYTHON_PREAMBLE = re.compile(r"PYTHON=(?:\$\{AGATHODAIMON_PYTHON:-/var/lib/caduceus/venv/bin/python3\}|/usr/bin/python3)\n(?:\[ -x \"\$PYTHON\" \] \|\| PYTHON=python3\n)?")
ROUTE = re.compile(r"agathodaimon/cli\.py\" ([a-z0-9_-]+)(?: |\")")

def launcher_noun(body: str) -> str | None:
    match = ROUTE.search(body)
    return match.group(1) if match else None

def regenerate(root: Path, *, write: bool) -> list[Path]:
    changed = []
    for path in sorted(root.glob("caduceus-*")):
        if not path.is_file():
            continue
        body = path.read_text(encoding="utf-8")
        noun = launcher_noun(body)
        if noun is None:
            continue
        desired = SYSTEM_PREAMBLE if noun in SYSTEM_PYTHON_NOUNS else VENV_PREAMBLE
        candidate, replacements = PYTHON_PREAMBLE.subn(desired, body, count=1)
        if replacements != 1:
            raise RuntimeError(f"launcher has no recognized Python preamble: {path.name}")
        if candidate != body:
            changed.append(path)
            if write:
                path.write_text(candidate, encoding="utf-8")
    return changed

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    for path in regenerate(args.root, write=args.write):
        print(path.name)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

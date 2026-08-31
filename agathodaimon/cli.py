#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import sys
from pathlib import Path
from io import BytesIO, StringIO

class _EnvelopeStdin(StringIO):
    @property
    def buffer(self):
        return BytesIO(self.getvalue().encode("utf-8"))


ROOT = Path(__file__).resolve().parent
if str(ROOT.parent) not in sys.path: sys.path.insert(0, str(ROOT.parent))
ALIASES = {"cert": ("network", "cert"), "vault": ("storage", "vault"), "backup": ("storage", "backup"), "forgejo": ("storage", "backup", "forgejo"), "time": ("settings", "datetime"), "attendance": ("exousia", "attendance"), "pin": ("exousia", "pin")}
SERVICE_ALIASES = {
    "service-control": ("portals", "service-control"),
    "staff-daemon": ("python", "staff-daemon"),
    "disk-doors": ("storage", "disk-doors"),
    "ssh-exposure": ("settings", "ssh"),
    "desktop-cache": ("settings", "default-apps", "desktop-cache"),
    "rebis-profile-retire": ("update", "profile-retire"),
}

def _index(path: Path) -> dict:
    index = path / "index.json"
    if not index.is_file(): return {}
    return json.loads(index.read_text(encoding="utf-8"))

def _children(path: Path) -> list[str]: return list(_index(path).get("children", []))

def _load(path: Path):
    rel = path.relative_to(ROOT); safe = "agathodaimon.face_" + "_".join(rel.parts[:-1])
    spec = importlib.util.spec_from_file_location(safe, path)
    if spec is None or spec.loader is None: raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec); module.__package__ = "agathodaimon"; sys.modules[safe] = module; spec.loader.exec_module(module); return module

def _help(path: Path) -> None:
    print(json.dumps({"schema":"agathodaimon.cli.help.v1","path":str(path.relative_to(ROOT)),"ok":True,"mutationPerformed":False}))

def _slash_target(raw_path: str) -> Path | None:
    parts = tuple(part for part in raw_path.split("/") if part)
    if not parts or any(part in {".", ".."} for part in parts):
        return None
    path = ROOT
    for part in parts:
        if part not in _children(path):
            return None
        path /= part
    target = path / "index.py"
    return target if target.is_file() else None

def _invoke_envelope(path: Path, envelope: dict, raw_envelope: str | None = None) -> int:
    mod = _load(path)
    fn = getattr(mod, "main", None)
    if fn is None:
        print(json.dumps({"schema":"agathodaimon.cli.read.v1","path":str(path.parent.relative_to(ROOT)),"ok":True,"envelope":envelope,"mutationPerformed":False}))
        return 0
    original_stdin = sys.stdin
    try:
        sys.stdin = _EnvelopeStdin(raw_envelope if raw_envelope is not None else json.dumps(envelope))
        try:
            return int(fn([]) or 0)
        except SystemExit:
            transition = envelope.get("transition")
            if not isinstance(transition, str):
                raise
            command = transition.rstrip("/").rsplit("/", 1)[-1]
            return int(fn([command]) or 0)
        except Exception as exc:
            print(json.dumps({"schema": "agathodaimon.cli.envelope.v1", "ok": False, "error": str(exc), "mutationPerformed": False}))
            return 1
    finally:
        sys.stdin = original_stdin

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(json.dumps({"schema":"agathodaimon.cli.spine.v1","nouns":_children(ROOT)},indent=2)); return 0
    original=args[:]
    if len(args) == 1 and "/" in args[0]:
        raw_envelope = sys.stdin.read()
        try:
            envelope = json.loads(raw_envelope)
        except (TypeError, json.JSONDecodeError):
            print("invalid envelope JSON", file=sys.stderr)
            return 2
        if not isinstance(envelope, dict):
            print("envelope must be a JSON object", file=sys.stderr)
            return 2
        target = _slash_target(args[0])
        if target is None:
            print(f"unknown path: {args[0]}", file=sys.stderr)
            return 2
        return _invoke_envelope(target, envelope, raw_envelope)
    if len(args) == 2 and "/" in args[0]:
        try:
            envelope = json.loads(args[1])
        except (TypeError, json.JSONDecodeError):
            print("invalid envelope JSON", file=sys.stderr)
            return 2
        if not isinstance(envelope, dict):
            print("envelope must be a JSON object", file=sys.stderr)
            return 2
        raw_envelope = args[1]
        target = _slash_target(args[0])
        if target is None:
            print(f"unknown path: {args[0]}", file=sys.stderr)
            return 2
        return _invoke_envelope(target, envelope, raw_envelope)
    service_alias=args[0]=="service" and len(args)>1 and args[1] in SERVICE_ALIASES
    alias=SERVICE_ALIASES[args[1]] if service_alias else ALIASES.get(args[0],(args[0],))
    remainder=args[2:] if service_alias else args[1:]
    path=ROOT
    try:
        for part in alias:
            if part not in _children(path): raise ValueError(part)
            path/=part
        while remainder and remainder[0] in _children(path): path/=remainder.pop(0)
    except (ValueError,OSError,json.JSONDecodeError):
        print(f"unknown noun: {args[0]}",file=sys.stderr); return 2
    children=_children(path); has_index=(path/"index.py").is_file()
    if children and remainder and remainder[0] != "--help":
        print(f"unknown verb: {' '.join(original)}",file=sys.stderr); return 2
    if (remainder==["--help"] and (children or not has_index)) or (not remainder and children):
        print(json.dumps({"noun":original[0],"verbs":children},indent=2)); return 0
    if not has_index:
        if not remainder:
            print(json.dumps({"noun":original[0],"verbs":children},indent=2)); return 0
        print(f"unknown verb: {' '.join(original)}",file=sys.stderr); return 2
    if "--help" in remainder: _help(path); return 0
    mod=_load(path/"index.py"); fn=getattr(mod,"main",None)
    if fn is None:
        print(json.dumps({"schema":"agathodaimon.read.v1","path":str(path.relative_to(ROOT)),"ok":True,"mutationPerformed":False})); return 0
    if original == ["cert", "house-ca"]:
        try:
            payload = json.load(sys.stdin)
            remainder.extend(payload.get("args", []))
        except (json.JSONDecodeError, AttributeError):
            pass
    try: return int(fn(remainder) or 0)
    except TypeError as exc:
        if "positional argument" not in str(exc) and "positional arguments" not in str(exc): raise
        return int(fn() or 0)

if __name__ == "__main__": raise SystemExit(main())

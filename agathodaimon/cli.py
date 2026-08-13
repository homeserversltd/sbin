from __future__ import annotations
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT.parent) not in sys.path: sys.path.insert(0, str(ROOT.parent))

def _index(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))

def _load(path: Path):
    rel = path.relative_to(ROOT)
    safe = "agathodaimon.face_" + "_".join(rel.parts[:-1])
    spec = importlib.util.spec_from_file_location(safe, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    module.__package__ = "agathodaimon"
    sys.modules[safe] = module
    spec.loader.exec_module(module)
    return module

def _children(path: Path) -> list[str]:
    return list(_index(path / "index.json").get("children", []))

def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(json.dumps({"schema":"agathodaimon.cli.spine.v1", "nouns":_children(ROOT)}, indent=2)); return 0
    noun=args.pop(0); band=ROOT/noun
    if not band.is_dir() or noun.startswith("."): print(f"unknown noun: {noun}", file=sys.stderr); return 2
    verbs=_children(band)
    if not args or args == ["--help"]:
        print(json.dumps({"noun":noun,"verbs":verbs}, indent=2)); return 0
    verb=args.pop(0); child=band/verb
    if verb not in verbs or not child.is_dir() or not (child/"index.py").is_file():
        print(f"unknown verb: {noun} {verb}", file=sys.stderr); return 2
    if "--help" in args:
        print(json.dumps({"schema":"agathodaimon.cli.help.v1","noun":noun,"verb":verb,"ok":True,"mutationPerformed":False}))
        return 0
    mod=_load(child/"index.py")
    fn=getattr(mod,"main",None)
    if fn is None:
        print(json.dumps({"schema":"agathodaimon.read.v1","noun":noun,"verb":verb,"ok":True,"mutationPerformed":False})); return 0
    try: return int(fn(args) or 0)
    except TypeError as exc:
        if "positional argument" not in str(exc) and "positional arguments" not in str(exc): raise
        return int(fn() or 0)

if __name__ == "__main__": raise SystemExit(main())

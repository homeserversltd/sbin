#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import json
import os
import re
import stat
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

_CROSSING_SCHEMA = "agathodaimon.crossings.v1"
_CROSSING_PROFILES = {"homeserver", "homeconsole", "tv", "lab"}
_CROSSING_PART = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_CROSSING_JSON_LIMIT = 1024 * 1024


def _read_json_nofollow(path: Path):
    """Read one bounded regular JSON file without following path symlinks."""
    parts = path.parts
    if not path.is_absolute() or len(parts) < 2 or any(part in {".", ".."} for part in parts):
        raise OSError("unsafe JSON path")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    directory_fd = os.open("/", directory_flags)
    file_fd = None
    try:
        for part in parts[1:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = next_fd
        file_fd = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
    finally:
        os.close(directory_fd)
    try:
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _CROSSING_JSON_LIMIT:
            raise OSError("JSON source is not a bounded regular file")
        raw = bytearray()
        while len(raw) <= _CROSSING_JSON_LIMIT:
            block = os.read(file_fd, min(65536, _CROSSING_JSON_LIMIT + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        if len(raw) > _CROSSING_JSON_LIMIT:
            raise OSError("JSON source exceeds size limit")
        return json.loads(raw.decode("utf-8"))
    finally:
        os.close(file_fd)


def _profile_for_crossing() -> tuple[str, bool]:
    profile_path = Path("/etc/appliance/profile.json")
    try:
        value = _read_json_nofollow(profile_path)
    except FileNotFoundError:
        return "lab", True
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return "unknown", False
    if not isinstance(value, dict) or not isinstance(value.get("profile"), str):
        return "unknown", False
    profile = value["profile"]
    label = profile if len(profile) <= 64 and _CROSSING_PART.fullmatch(profile) else "unknown"
    return label, profile in _CROSSING_PROFILES


def _crossing_publication(profile: str) -> tuple[set[str], set[tuple[str, str]]] | None:
    try:
        value = _read_json_nofollow(ROOT / "crossings" / f"{profile}.json")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("schema") != _CROSSING_SCHEMA or value.get("profile") != profile:
        return None
    bands = value.get("bands")
    verbs = value.get("verbs")
    if not isinstance(bands, list) or not isinstance(verbs, list):
        return None
    clean_bands: set[str] = set()
    for band in bands:
        if (
            not isinstance(band, str)
            or not band
            or band.startswith("/")
            or band.endswith("/")
            or any(not _CROSSING_PART.fullmatch(part) for part in band.split("/"))
        ):
            return None
        if band.split("/", 1)[0] == "lib":
            return None
        clean_bands.add(band)
    clean_verbs: set[tuple[str, str]] = set()
    for pair in verbs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(part, str) and _CROSSING_PART.fullmatch(part) for part in pair)
        ):
            return None
        clean_verbs.add((pair[0], pair[1]))
    return clean_bands, clean_verbs


def _crossing_request(args: list[str]) -> tuple[str, str | tuple[str, str] | None, str, bool]:
    """Classify only the staff line's exact band or noun-verb forms."""
    if args and "/" in args[0]:
        raw = args[0]
        nonempty = [part for part in raw.split("/") if part]
        first_is_lib = bool(nonempty and nonempty[0] == "lib")
        canonical = (
            not raw.startswith("/")
            and not raw.endswith("/")
            and all(_CROSSING_PART.fullmatch(part) for part in raw.split("/"))
        )
        if not canonical:
            return "invalid", None, raw, first_is_lib
        if len(args) not in {1, 2} or (len(args) == 2 and not args[1].lstrip().startswith("{")):
            return "invalid", None, raw, first_is_lib
        return "band", raw, raw, first_is_lib
    if len(args) == 2 and all(_CROSSING_PART.fullmatch(part) for part in args):
        return "verb", (args[0], args[1]), f"{args[0]} {args[1]}", args[0] == "lib"
    if len(args) == 1 and _CROSSING_PART.fullmatch(args[0]):
        return "invalid", None, args[0], args[0] == "lib"
    return "invalid", None, "invalid-request", bool(args and args[0] == "lib")


def _crossing_resolved_target(args: list[str]) -> str | None:
    """Resolve a legacy noun-verb pair through the same declared aliases as main."""
    if len(args) != 2 or not all(_CROSSING_PART.fullmatch(part) for part in args):
        return None
    service_alias = args[0] == "service" and args[1] in SERVICE_ALIASES
    alias = SERVICE_ALIASES[args[1]] if service_alias else ALIASES.get(args[0], (args[0],))
    remainder = [] if service_alias else args[1:]
    path = ROOT
    try:
        for part in alias:
            if part not in _children(path):
                return None
            path /= part
        while remainder and remainder[0] in _children(path):
            path /= remainder.pop(0)
    except (ValueError, OSError, json.JSONDecodeError):
        return None
    if remainder:
        return None
    return path.relative_to(ROOT).as_posix()


def _refuse_crossing(profile: str, requested: str) -> int:
    print(json.dumps({
        "schema": "agathodaimon.front-door.v1",
        "ok": False,
        "firstMissingSignal": "agathodaimon-band-not-published",
        "profile": profile,
        "requested": requested,
    }, separators=(",", ":")))
    return 1


def _admit_caduceus_crossing(args: list[str]) -> bool:
    profile, profile_ok = _profile_for_crossing()
    form, request_key, requested, first_is_lib = _crossing_request(args)
    publication = _crossing_publication(profile) if profile_ok else None
    if not profile_ok or publication is None or first_is_lib:
        _refuse_crossing(profile, requested)
        return False
    bands, verbs = publication
    resolved_target = _crossing_resolved_target(args) if form == "verb" else None
    published_verb_targets = {
        target
        for pair in verbs
        if (target := _crossing_resolved_target(list(pair))) is not None
    }
    admitted = (
        isinstance(request_key, str) and form == "band" and request_key in bands
    ) or (
        form == "verb"
        and resolved_target is not None
        and resolved_target in published_verb_targets
    )
    if not admitted:
        _refuse_crossing(profile, requested)
        return False
    return True

def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if os.environ.get("SUDO_USER") == "caduceus" and os.geteuid() == 0:
        if not _admit_caduceus_crossing(args):
            return 1
        for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
            os.environ.pop(name, None)
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

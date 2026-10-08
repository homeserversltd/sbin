#!/usr/bin/env python3
from __future__ import annotations
import importlib.util
import getpass
import json
import os
import re
import stat
import sys
import warnings
from pathlib import Path
from io import BytesIO, StringIO

class _EnvelopeStdin(StringIO):
    @property
    def buffer(self):
        return BytesIO(self.getvalue().encode("utf-8"))


ROOT = Path(__file__).resolve().parent
if str(ROOT.parent) not in sys.path: sys.path.insert(0, str(ROOT.parent))
from agathodaimon._envelope import appliance_runtime_path
ALIASES = {"cert": ("network", "cert"), "vault": ("storage", "vault"), "upload": ("storage", "upload"), "nas": ("storage", "nas"), "backup": ("storage", "backup"), "forgejo": ("storage", "backup", "forgejo"), "time": ("settings", "datetime"), "attendance": ("exousia", "attendance"), "pin": ("exousia", "pin")}
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
_CROSSING_PART = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
_CROSSING_ROUTE_SEGMENT = r"(?:[a-z0-9][a-z0-9_.-]*|:[a-z][a-z0-9_]*)"
_CROSSING_API_ROUTE = re.compile(
    rf"^/api/v1/{_CROSSING_ROUTE_SEGMENT}(?:/{_CROSSING_ROUTE_SEGMENT})*$"
)
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
    try:
        profile_path = appliance_runtime_path("profile")
    except ValueError:
        return "unknown", False
    try:
        value = _read_json_nofollow(profile_path)
    except FileNotFoundError:
        return "lab", True
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return "unknown", False
    if not isinstance(value, dict) or not isinstance(value.get("profile"), str):
        return "unknown", False
    profile = value["profile"]
    valid = len(profile) <= 64 and _CROSSING_PART.fullmatch(profile) is not None
    return (profile if valid else "unknown"), valid


def _crossing_publication(
    profile: str,
) -> tuple[set[str], set[tuple[str, str]], set[str], set[tuple[str, str]], set[str]] | None:
    seat_profile = profile
    try:
        value = _read_json_nofollow(ROOT / "crossings" / f"{profile}.json")
    except FileNotFoundError:
        if profile == "lab":
            return None
        try:
            value = _read_json_nofollow(ROOT / "crossings" / "lab.json")
            seat_profile = "lab"
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            return None
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(value, dict) or value.get("schema") != _CROSSING_SCHEMA or value.get("profile") != seat_profile:
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
        if pair[0] == "lib":
            return None
        clean_verbs.add((pair[0], pair[1]))
    published_routes = value.get("routes")
    if not isinstance(published_routes, list):
        return None
    clean_routes: set[str] = set()
    for route in published_routes:
        if not isinstance(route, str) or _CROSSING_API_ROUTE.fullmatch(route) is None:
            return None
        clean_routes.add(route)

    administrative = value.get("administrative")
    if not isinstance(administrative, dict) or set(administrative) != {"bands", "verbs", "routes"}:
        return None
    admin_bands = administrative.get("bands")
    admin_verbs = administrative.get("verbs")
    admin_routes = administrative.get("routes")
    if not isinstance(admin_bands, list) or not isinstance(admin_verbs, list) or not isinstance(admin_routes, list):
        return None

    clean_admin_bands: set[str] = set()
    for band in admin_bands:
        if (
            not isinstance(band, str)
            or not band
            or band.startswith("/")
            or band.endswith("/")
            or any(not _CROSSING_PART.fullmatch(part) for part in band.split("/"))
            or band.split("/", 1)[0] == "lib"
            or band not in clean_bands
        ):
            return None
        clean_admin_bands.add(band)

    clean_admin_verbs: set[tuple[str, str]] = set()
    for pair in admin_verbs:
        if (
            not isinstance(pair, list)
            or len(pair) != 2
            or not all(isinstance(part, str) and _CROSSING_PART.fullmatch(part) for part in pair)
            or pair[0] == "lib"
        ):
            return None
        verb = (pair[0], pair[1])
        if verb not in clean_verbs:
            return None
        clean_admin_verbs.add(verb)

    clean_admin_routes: set[str] = set()
    for route in admin_routes:
        if not isinstance(route, str) or _CROSSING_API_ROUTE.fullmatch(route) is None or route not in clean_routes:
            return None
        clean_admin_routes.add(route)
    return clean_bands, clean_verbs, clean_admin_bands, clean_admin_verbs, clean_admin_routes


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
    resolved_target = _crossing_resolved_target(args) if form == "verb" else None
    resolved_is_lib = bool(resolved_target and resolved_target.split("/", 1)[0] == "lib")
    publication = _crossing_publication(profile) if profile_ok else None
    if not profile_ok or publication is None or first_is_lib or resolved_is_lib:
        _refuse_crossing(profile, requested)
        return False
    bands, verbs, _admin_bands, _admin_verbs, _admin_routes = publication
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


def _pin_required() -> bool:
    try:
        value = _read_json_nofollow(appliance_runtime_path("config"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return False
    global_config = value.get("global") if isinstance(value, dict) else None
    admin = global_config.get("admin") if isinstance(global_config, dict) else None
    return isinstance(admin, dict) and admin.get("pin_required") is True


def _take_envelope_pin(value: object) -> tuple[bool, object]:
    """Remove the secret flag from every supported Alkahest carrier location."""
    if not isinstance(value, dict):
        return False, None
    found = False
    pin = None
    for container in (value.get("payload"), value):
        if not isinstance(container, dict):
            continue
        flags = container.get("flags")
        exousia = flags.get("exousia") if isinstance(flags, dict) else None
        if isinstance(exousia, dict) and "pin" in exousia:
            candidate = exousia.pop("pin")
            if not found:
                found, pin = True, candidate
    return found, pin


def _argv_envelope_has_pin(args: list[str]) -> bool:
    for argument in args:
        if not isinstance(argument, str) or not argument.lstrip().startswith("{"):
            continue
        try:
            envelope = json.loads(argument)
        except (TypeError, json.JSONDecodeError):
            continue
        found, _pin = _take_envelope_pin(envelope)
        if found:
            return True
    return False


def _capture_piped_envelope() -> tuple[dict | None, bool, object]:
    """Buffer piped stdin once, scrub a PIN, then restore the consumer stream."""
    try:
        if sys.stdin.isatty():
            return None, False, None
        raw = sys.stdin.read()
    except (AttributeError, OSError, UnicodeError):
        return None, False, None
    envelope = None
    pin_present = False
    pin = None
    try:
        parsed = json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, dict):
        envelope = parsed
        pin_present, pin = _take_envelope_pin(envelope)
        if pin_present:
            raw = json.dumps(envelope, separators=(",", ":"))
    sys.stdin = _EnvelopeStdin(raw)
    return envelope, pin_present, pin


def _cli_target(args: list[str]) -> tuple[str | None, list[str]]:
    """Resolve slash, noun/verb, and declared service aliases to one band path."""
    if not args:
        return None, []
    if "/" in args[0]:
        raw = args[0]
        if (
            raw.startswith("/")
            or raw.endswith("/")
            or not all(_CROSSING_PART.fullmatch(part) for part in raw.split("/"))
            or len(args) not in {1, 2}
            or (len(args) == 2 and not args[1].lstrip().startswith("{"))
        ):
            return None, []
        return raw, []
    service_alias = args[0] == "service" and len(args) > 1 and args[1] in SERVICE_ALIASES
    alias = SERVICE_ALIASES[args[1]] if service_alias else ALIASES.get(args[0], (args[0],))
    remainder = args[2:] if service_alias else args[1:]
    path = ROOT
    try:
        for part in alias:
            if part not in _children(path):
                return None, []
            path /= part
        while remainder and remainder[0] in _children(path):
            path /= remainder.pop(0)
    except (OSError, json.JSONDecodeError, ValueError):
        return None, []
    return path.relative_to(ROOT).as_posix(), remainder


def _administrative_target(target: str, publication) -> bool:
    if publication is None:
        return False
    _bands, _verbs, admin_bands, admin_verbs, _routes = publication
    targets = {
        resolved
        for pair in admin_verbs
        if (resolved := _crossing_resolved_target(list(pair))) is not None
    }
    return any(
        target == published or target.startswith(published + "/")
        for published in admin_bands | targets
    )


def _administrative_candidate(target: str | None) -> bool:
    if target is None:
        return False
    return (
        target in {
            "appliance/service",
            "appliance/sudo-passwordless",
            "network/child-device",
            "network/dns",
            "portals/service-control",
            "storage/nas/attach",
            "storage/nas/detach",
            "storage/nas/setup",
            "storage/vault/open",
            "storage/vault/policy",
        }
        or target.startswith("settings/")
        or target in {"exousia/change", "exousia/reset-default"}
    )


def _envelope_operation(envelope: dict | None, remainder: list[str]) -> str | None:
    if remainder:
        if remainder[0] == "whitelist" and len(remainder) > 1:
            return f"whitelist {remainder[1]}"
        if remainder[0] in {"resolver", "device-name", "alias"} and len(remainder) > 1:
            return remainder[1].lower()
        return remainder[0].lower()
    if not isinstance(envelope, dict):
        return None
    payload = envelope.get("payload")
    containers = [payload, envelope]
    for container in containers:
        if not isinstance(container, dict):
            continue
        metadata = container.get("metadata")
        if isinstance(metadata, dict):
            containers.append(metadata)
        for key in ("action", "op", "operation", "verb"):
            value = container.get(key)
            if isinstance(value, str) and value:
                return value.lower()
    transition = envelope.get("transition")
    if isinstance(transition, str) and transition:
        parts = [part for part in re.split(r"[./:]", transition) if part]
        if parts:
            return parts[-1].lower()
    return None


def _admin_mutation_request(target: str, remainder: list[str], envelope: dict | None) -> bool:
    operation = _envelope_operation(envelope, remainder)
    read_only = {"get", "read", "status", "list", "show", "observed", "validate", "verify"}
    mutation = {"set", "change", "apply", "mutate", "write", "create", "remove", "update", "start", "stop", "restart", "enable", "disable", "reset-default", "unlock", "open", "register", "unregister"}
    if target.startswith("settings/"):
        if operation in read_only:
            return False
        if operation in mutation:
            return True
        payload = envelope.get("payload") if isinstance(envelope, dict) else None
        if not isinstance(payload, dict) and isinstance(envelope, dict):
            payload = envelope
        return isinstance(payload, dict) and any(key not in {"flags", "rooms", "stamps"} for key in payload)
    if target == "storage/vault/policy":
        return operation != "read"
    if target == "network/dns":
        return operation not in {"read", "status"}
    if target == "network/child-device":
        return operation not in read_only and operation != "whitelist get"
    if target == "appliance/service":
        return operation not in {"read", "get", "show", "list", "observed", "status"}
    if target == "portals/service-control":
        return operation not in read_only and not (operation and operation.endswith("-status"))
    if target == "appliance/sudo-passwordless":
        return operation not in {"read", "status", "get"}
    return True


def _prompt_administrative_pin() -> tuple[bool, str | None]:
    try:
        tty_fd = os.open("/dev/tty", os.O_RDWR | getattr(os, "O_NOCTTY", 0))
    except OSError:
        return False, None
    os.close(tty_fd)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return True, getpass.getpass("Appliance PIN: ")
    except (EOFError, OSError, getpass.GetPassWarning):
        return False, None


def _verify_administrative_pin(pin: object) -> bool:
    if not isinstance(pin, str):
        return False
    try:
        module = _load(ROOT / "lib" / "sacred_credential" / "index.py")
        verify = getattr(module, "verify_and_derive_caduceus", None)
        if not callable(verify):
            return False
        derived = verify(pin)
        close = getattr(derived, "close", None)
        if callable(close):
            close()
        return True
    except Exception:
        return False


def _refuse_administrative(signal: str) -> int:
    print(json.dumps({
        "schema": "agathodaimon.front-door.v1",
        "ok": False,
        "firstMissingSignal": signal,
    }, separators=(",", ":")))
    return 1


def _administrative_pin_admits(
    target: str | None,
    remainder: list[str],
    envelope: dict | None,
    pin_required: bool,
    caduceus_root: bool,
    pin_present: bool,
    pin: object,
    publication,
) -> bool:
    if not pin_required or caduceus_root or target is None:
        return True
    is_admin = (
        _administrative_candidate(target)
        if publication is None
        else _administrative_target(target, publication)
    )
    if not is_admin or not _admin_mutation_request(target, remainder, envelope):
        return True
    if not pin_present:
        tty_available, pin = _prompt_administrative_pin()
        if not tty_available:
            _refuse_administrative("agathodaimon-administrative-pin-required")
            return False
    if not _verify_administrative_pin(pin):
        pin = None
        _refuse_administrative("agathodaimon-administrative-pin-wrong")
        return False
    pin = None
    return True


def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    caduceus_root = os.environ.get("SUDO_USER") == "caduceus" and os.geteuid() == 0
    if caduceus_root:
        if not _admit_caduceus_crossing(args):
            return 1
        for name in ("SUDO_USER", "SUDO_UID", "SUDO_GID", "SUDO_COMMAND"):
            os.environ.pop(name, None)
    if _argv_envelope_has_pin(args):
        return _refuse_administrative("agathodaimon-administrative-pin-required")
    if not args:
        print(json.dumps({"schema":"agathodaimon.cli.spine.v1","nouns":_children(ROOT)},indent=2)); return 0
    original=args[:]
    pin_required = _pin_required()
    publication = None
    if pin_required:
        profile, profile_ok = _profile_for_crossing()
        publication = _crossing_publication(profile) if profile_ok else None
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
        pin_present, pin = _take_envelope_pin(envelope)
        if pin_present:
            raw_envelope = json.dumps(envelope, separators=(",", ":"))
        target = _slash_target(args[0])
        if target is None:
            print(f"unknown path: {args[0]}", file=sys.stderr)
            return 2
        cli_target, remainder = _cli_target(args)
        admitted = _administrative_pin_admits(
            cli_target, remainder, envelope, pin_required, caduceus_root,
            pin_present, pin, publication,
        )
        pin = None
        if not admitted:
            return 1
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
        cli_target, remainder = _cli_target(args)
        if not _administrative_pin_admits(
            cli_target, remainder, envelope, pin_required, caduceus_root,
            False, None, publication,
        ):
            return 1
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
    envelope, pin_present, pin = _capture_piped_envelope()
    cli_target = path.relative_to(ROOT).as_posix()
    admitted = _administrative_pin_admits(
        cli_target, remainder, envelope, pin_required, caduceus_root,
        pin_present, pin, publication,
    )
    pin = None
    if not admitted:
        return 1
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

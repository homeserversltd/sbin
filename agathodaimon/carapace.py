#!/usr/bin/env python3
"""Derive sold appliance crossings from Agathodaimon sclerite declarations."""
from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parent
FEATURES_PATH = ROOT / "sclerites.json"
DEFCONFIG_DIR = ROOT / "defconfigs"
CROSSINGS_DIR = ROOT / "crossings"
PROFILES = ("homeserver", "homeconsole", "tv", "homesi")
CROSSING_SCHEMA = "appliance.crossings.v1"
PART = re.compile(r"^[a-z0-9][a-z0-9_.-]*$")
ROUTE_SEGMENT = r"(?:[a-z0-9][a-z0-9_.-]*|:[a-z][a-z0-9_]*)"
API_ROUTE = re.compile(rf"^/api/v1/{ROUTE_SEGMENT}(?:/{ROUTE_SEGMENT})*$")
ADMIN_ROUTE_SEGMENT = rf"(?:{ROUTE_SEGMENT}|\{{[a-z][a-z0-9_]*\}})"
ADMIN_API_ROUTE = re.compile(
    rf"^(?:POST|PUT|PATCH|DELETE) /api/v1/{ADMIN_ROUTE_SEGMENT}(?:/{ADMIN_ROUTE_SEGMENT})*$"
)


class CarapaceError(ValueError):
    """A source declaration cannot be safely derived."""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CarapaceError(f"{path.relative_to(ROOT)}: JSON read failed: {error}") from error


def _object(value: Any, locus: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CarapaceError(f"{locus}: JSON object required")
    return value


def _strings(value: Any, locus: str, *, pattern: re.Pattern[str] | None = None) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CarapaceError(f"{locus}: string list required")
    if len(set(value)) != len(value):
        raise CarapaceError(f"{locus}: duplicate entries")
    if pattern is not None and any(pattern.fullmatch(item) is None for item in value):
        raise CarapaceError(f"{locus}: malformed entry")
    return list(value)


def _pairs(value: Any, locus: str) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        raise CarapaceError(f"{locus}: pair list required")
    result: list[tuple[str, str]] = []
    for pair in value:
        if not isinstance(pair, list) or len(pair) != 2 or any(
            not isinstance(part, str) or PART.fullmatch(part) is None for part in pair
        ):
            raise CarapaceError(f"{locus}: each alias must be a two-part identifier pair")
        result.append((pair[0], pair[1]))
    if len(set(result)) != len(result):
        raise CarapaceError(f"{locus}: duplicate alias pairs")
    if any(noun == "lib" for noun, _verb in result):
        raise CarapaceError(f"{locus}: lib aliases cannot cross")
    return result


def _routes(value: Any, locus: str, *, administrative: bool = False) -> list[str]:
    values = _strings(value, locus)
    for route in values:
        valid = ADMIN_API_ROUTE.fullmatch(route) if administrative and " " in route else API_ROUTE.fullmatch(route)
        if valid is None:
            raise CarapaceError(f"{locus}: malformed route {route!r}")
    return values


def _load_feature_tree() -> dict[str, Any]:
    tree = _object(_read_json(FEATURES_PATH), "sclerites.json")
    expected = {"schema", "always", "features", "implications", "choices"}
    if set(tree) != expected or tree.get("schema") != "agathodaimon.sclerites.v1":
        raise CarapaceError("sclerites.json: schema or top-level fields invalid")
    names = tree.get("features")
    if not isinstance(names, dict) or not names:
        raise CarapaceError("sclerites.json: non-empty features object required")
    for name, spec in names.items():
        if not isinstance(name, str) or PART.fullmatch(name) is None:
            raise CarapaceError(f"sclerites.json: invalid feature name {name!r}")
        if not isinstance(spec, dict) or set(spec) - {"requires", "requires_any", "implies"}:
            raise CarapaceError(f"sclerites.json: feature {name!r} has malformed fields")
        spec.setdefault("requires", [])
        spec.setdefault("requires_any", [])
        spec.setdefault("implies", [])
        spec["requires"] = _strings(spec["requires"], f"feature {name}.requires", pattern=PART)
        spec["requires_any"] = _strings(
            spec["requires_any"], f"feature {name}.requires_any", pattern=PART
        )
        spec["implies"] = _strings(spec["implies"], f"feature {name}.implies", pattern=PART)
    always = _strings(tree.get("always"), "sclerites.json.always", pattern=PART)
    if any(name not in names for name in always):
        raise CarapaceError("sclerites.json: always names an undeclared feature")
    for name, spec in names.items():
        for field in ("requires", "requires_any", "implies"):
            missing = sorted(set(spec[field]) - set(names))
            if missing:
                raise CarapaceError(f"sclerites.json: feature {name!r} {field} undeclared {missing}")
    implications = tree.get("implications")
    if not isinstance(implications, list):
        raise CarapaceError("sclerites.json.implications: list required")
    for index, rule in enumerate(implications):
        locus = f"sclerites.json.implications[{index}]"
        if not isinstance(rule, dict) or set(rule) != {"when_all", "implies"}:
            raise CarapaceError(f"{locus}: rule fields invalid")
        rule["when_all"] = _strings(rule["when_all"], f"{locus}.when_all", pattern=PART)
        rule["implies"] = _strings(rule["implies"], f"{locus}.implies", pattern=PART)
        if not rule["when_all"] or not rule["implies"]:
            raise CarapaceError(f"{locus}: non-empty when_all and implies required")
        if set(rule["when_all"] + rule["implies"]) - set(names):
            raise CarapaceError(f"{locus}: undeclared feature")
    choices = tree.get("choices")
    if not isinstance(choices, dict):
        raise CarapaceError("sclerites.json.choices: object required")
    for name, choice in choices.items():
        locus = f"sclerites.json.choices.{name}"
        if not isinstance(name, str) or PART.fullmatch(name) is None:
            raise CarapaceError(f"{locus}: invalid choice name")
        if not isinstance(choice, dict) or set(choice) != {"when_all", "options"}:
            raise CarapaceError(f"{locus}: choice fields invalid")
        choice["when_all"] = _strings(choice["when_all"], f"{locus}.when_all", pattern=PART)
        options = choice["options"]
        if not choice["when_all"] or not isinstance(options, dict) or len(options) < 2:
            raise CarapaceError(f"{locus}: at least two options and one condition required")
        if set(choice["when_all"]) - set(names):
            raise CarapaceError(f"{locus}: undeclared condition feature")
        for option, spec in options.items():
            option_locus = f"{locus}.options.{option}"
            if not isinstance(option, str) or PART.fullmatch(option) is None:
                raise CarapaceError(f"{option_locus}: invalid option name")
            if not isinstance(spec, dict) or set(spec) - {"features", "packages"}:
                raise CarapaceError(f"{option_locus}: option fields invalid")
            spec.setdefault("features", [])
            spec.setdefault("packages", [])
            spec["features"] = _strings(spec["features"], f"{option_locus}.features", pattern=PART)
            spec["packages"] = _strings(spec["packages"], f"{option_locus}.packages", pattern=PART)
            if set(spec["features"]) - set(names):
                raise CarapaceError(f"{option_locus}: undeclared feature")
        seen_option_features: set[str] = set()
        for option, spec in options.items():
            option_locus = f"{locus}.options.{option}"
            option_features = set(spec["features"])
            if not option_features:
                raise CarapaceError(f"{option_locus}.features: non-empty option feature set required")
            overlap = seen_option_features.intersection(option_features)
            if overlap:
                raise CarapaceError(
                    f"{option_locus}.features: overlaps another option at {sorted(overlap)}"
                )
            seen_option_features.update(option_features)
    return tree


def _close_features(selected: set[str], tree: Mapping[str, Any]) -> set[str]:
    features = tree["features"]
    rules = tree["implications"]
    while True:
        prior = len(selected)
        for name in sorted(selected):
            selected.update(features[name]["implies"])
        for rule in rules:
            if set(rule["when_all"]).issubset(selected):
                selected.update(rule["implies"])
        if len(selected) == prior:
            return selected


def _resolve_profile(profile: str, tree: Mapping[str, Any]) -> set[str]:
    path = DEFCONFIG_DIR / f"{profile}.json"
    config = _object(_read_json(path), f"defconfigs/{profile}.json")
    if set(config) != {"schema", "profile", "features", "choices"}:
        raise CarapaceError(f"defconfigs/{profile}.json: fields invalid")
    if config.get("schema") != "agathodaimon.defconfig.v1" or config.get("profile") != profile:
        raise CarapaceError(f"defconfigs/{profile}.json: schema/profile mismatch")
    explicit = _strings(config.get("features"), f"defconfigs/{profile}.json.features", pattern=PART)
    if set(explicit) & set(tree["always"]):
        raise CarapaceError(f"defconfigs/{profile}.json: always-on features must not be repeated")
    unknown = sorted(set(explicit) - set(tree["features"]))
    if unknown:
        raise CarapaceError(f"defconfigs/{profile}.json: undeclared features {unknown}")
    choice_values = _object(config.get("choices"), f"defconfigs/{profile}.json.choices")
    unknown_choices = sorted(set(choice_values) - set(tree["choices"]))
    if unknown_choices:
        raise CarapaceError(f"defconfigs/{profile}.json: undeclared choices {unknown_choices}")

    selected = _close_features(set(tree["always"]) | set(explicit), tree)
    for name, choice in tree["choices"].items():
        active = set(choice["when_all"]).issubset(selected)
        value = choice_values.get(name)
        if active:
            if not isinstance(value, str) or value not in choice["options"]:
                raise CarapaceChoiceError(profile, name, sorted(choice["options"]))
            option = choice["options"][value]
            selected.update(option["features"])
        elif name in choice_values:
            raise CarapaceError(f"defconfigs/{profile}.json: choice {name!r} has no active requiring feature")
    selected = _close_features(selected, tree)
    for name, choice in tree["choices"].items():
        if not set(choice["when_all"]).issubset(selected):
            continue
        declared = choice_values[name]
        memberships = [
            option
            for option, spec in choice["options"].items()
            if set(spec["features"]).intersection(selected)
        ]
        if len(memberships) != 1 or memberships[0] != declared:
            raise CarapaceError(
                f"defconfigs/{profile}.json.choices.{name}: declared option {declared!r} "
                f"contradicts materialized option feature memberships {memberships}"
            )
    for name in sorted(selected):
        missing = sorted(set(tree["features"][name]["requires"]) - selected)
        if missing:
            raise CarapaceError(f"defconfigs/{profile}.json: feature {name!r} requires {missing}")
        requires_any = tree["features"][name]["requires_any"]
        if requires_any and not set(requires_any).intersection(selected):
            raise CarapaceError(
                f"defconfigs/{profile}.json: feature {name!r} requires any of {requires_any}"
            )
    return selected


class CarapaceChoiceError(CarapaceError):
    def __init__(self, profile: str, choice: str, options: list[str]):
        super().__init__(
            f"defconfigs/{profile}.json: choice {choice!r} must name one of {options}"
        )


def _validate_claim(claim: Any, locus: str) -> dict[str, Any]:
    if not isinstance(claim, dict) or set(claim) - {"band", "verbs", "routes", "administrative"}:
        raise CarapaceError(f"{locus}: crossing contribution fields invalid")
    band = claim.get("band", False)
    if type(band) is not bool:
        raise CarapaceError(f"{locus}.band: boolean required")
    verbs = _pairs(claim.get("verbs", []), f"{locus}.verbs")
    routes = _routes(claim.get("routes", []), f"{locus}.routes")
    administrative = claim.get("administrative", {})
    if not isinstance(administrative, dict) or set(administrative) - {"band", "verbs", "routes"}:
        raise CarapaceError(f"{locus}.administrative: fields invalid")
    admin_band = administrative.get("band", False)
    if type(admin_band) is not bool:
        raise CarapaceError(f"{locus}.administrative.band: boolean required")
    if admin_band and not band:
        raise CarapaceError(f"{locus}: administrative band contribution requires its band")
    admin_verbs = _pairs(administrative.get("verbs", []), f"{locus}.administrative.verbs")
    if set(admin_verbs) - set(verbs):
        raise CarapaceError(f"{locus}: administrative aliases must also be declared in verbs")
    admin_routes = _routes(administrative.get("routes", []), f"{locus}.administrative.routes", administrative=True)
    return {
        "band": band,
        "verbs": verbs,
        "routes": routes,
        "administrative": {"band": admin_band, "verbs": admin_verbs, "routes": admin_routes},
    }


def _load_sclerites(tree: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    index_paths = sorted(ROOT.rglob("index.py"))
    owners: dict[str, dict[str, Any]] = {}
    for index_path in index_paths:
        band_path = index_path.parent
        rel = band_path.relative_to(ROOT).as_posix()
        metadata_path = band_path / "index.json"
        if not metadata_path.is_file():
            raise CarapaceError(f"{rel}: index.py has no adjacent index.json sclerite seat")
        metadata = _object(_read_json(metadata_path), f"{rel}/index.json")
        if "sclerite" not in metadata:
            raise CarapaceError(f"{rel}/index.json: sclerite declaration missing")
    for metadata_path in sorted(ROOT.rglob("index.json")):
        metadata = _object(_read_json(metadata_path), metadata_path.relative_to(ROOT).as_posix())
        if "sclerite" not in metadata:
            continue
        rel = metadata_path.parent.relative_to(ROOT).as_posix()
        if rel in owners:
            raise CarapaceError(f"{rel}: duplicate sclerite owner")
        sclerite = metadata["sclerite"]
        if not isinstance(sclerite, dict) or set(sclerite) != {"name", "features"}:
            raise CarapaceError(f"{rel}/index.json: sclerite must contain name and features")
        name = sclerite["name"]
        if not isinstance(name, str) or name not in tree["features"]:
            raise CarapaceError(f"{rel}/index.json: sclerite name must name a declared feature")
        contributions = sclerite["features"]
        if not isinstance(contributions, dict):
            raise CarapaceError(f"{rel}/index.json: sclerite.features object required")
        normalized: dict[str, Any] = {}
        for feature, claim in contributions.items():
            if not isinstance(feature, str) or feature not in tree["features"]:
                raise CarapaceError(f"{rel}/index.json: undeclared feature {feature!r}")
            normalized[feature] = _validate_claim(claim, f"{rel}.sclerite.features.{feature}")
        if rel.split("/", 1)[0] == "lib" and any(
            claim["band"] or claim["verbs"] or claim["routes"]
            or claim["administrative"]["band"] or claim["administrative"]["verbs"]
            or claim["administrative"]["routes"]
            for claim in normalized.values()
        ):
            raise CarapaceError(f"{rel}: lib is internal and cannot contribute crossings")
        owners[rel] = normalized
    return owners


def _derive(profile: str, selected: set[str], owners: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    bands: set[str] = set()
    verbs: set[tuple[str, str]] = set()
    routes: set[str] = set()
    admin_bands: set[str] = set()
    admin_verbs: set[tuple[str, str]] = set()
    admin_routes: set[str] = set()
    for owner in sorted(owners):
        for feature in sorted(selected):
            claim = owners[owner].get(feature)
            if claim is None:
                continue
            if claim["band"]:
                bands.add(owner)
            verbs.update(claim["verbs"])
            routes.update(claim["routes"])
            administrative = claim["administrative"]
            if administrative["band"]:
                admin_bands.add(owner)
            admin_verbs.update(administrative["verbs"])
            admin_routes.update(administrative["routes"])
    if any(band.split("/", 1)[0] == "lib" for band in bands | admin_bands):
        raise CarapaceError(f"{profile}: lib band cannot cross")
    if not admin_bands.issubset(bands) or not admin_verbs.issubset(verbs):
        raise CarapaceError(f"{profile}: administrative bands/aliases are not published")
    for route in admin_routes:
        if API_ROUTE.fullmatch(route) is not None and route not in routes:
            raise CarapaceError(f"{profile}: administrative route is not published: {route}")
        if API_ROUTE.fullmatch(route) is None and ADMIN_API_ROUTE.fullmatch(route) is None:
            raise CarapaceError(f"{profile}: malformed administrative route: {route}")
    return {
        "schema": CROSSING_SCHEMA,
        "profile": profile,
        "bands": sorted(bands),
        "verbs": [list(pair) for pair in sorted(verbs)],
        "routes": sorted(routes),
        "administrative": {
            "bands": sorted(admin_bands),
            "verbs": [list(pair) for pair in sorted(admin_verbs)],
            "routes": sorted(admin_routes),
        },
    }


def generate() -> dict[str, Any]:
    tree = _load_feature_tree()
    expected_defs = {f"{profile}.json" for profile in PROFILES}
    actual_defs = {path.name for path in DEFCONFIG_DIR.glob("*.json")}
    if actual_defs != expected_defs:
        raise CarapaceError(
            f"defconfigs: expected exactly {sorted(expected_defs)}, found {sorted(actual_defs)}"
        )
    owners = _load_sclerites(tree)
    planned: list[tuple[str, Path, bytes, bytes | None]] = []
    for profile in PROFILES:
        selected = _resolve_profile(profile, tree)
        result = _derive(profile, selected, owners)
        target = CROSSINGS_DIR / f"{profile}.json"
        rendered = (json.dumps(result, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            metadata = target.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise CarapaceError(f"{target.relative_to(ROOT)}: output must be a regular non-symlink file")
            prior = target.read_bytes()
        except FileNotFoundError:
            prior = None
        except OSError as error:
            raise CarapaceError(f"{target.relative_to(ROOT)}: output read failed: {error}") from error
        rel = target.relative_to(ROOT).as_posix()
        planned.append((rel, target, rendered, prior))

    generated: list[str] = []
    unchanged: list[str] = []
    for rel, target, rendered, prior in planned:
        if prior == rendered:
            unchanged.append(rel)
            continue
        try:
            target.write_bytes(rendered)
        except OSError as error:
            raise CarapaceError(f"{rel}: output write failed: {error}") from error
        generated.append(rel)
    return {"schema": "agathodaimon.carapace.generate.v1", "ok": True,
            "changed": generated, "unchanged": unchanged}


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args not in ([], ["generate"]):
        print("usage: python3 agathodaimon/carapace.py [generate]", file=sys.stderr)
        return 2
    try:
        result = generate()
    except CarapaceError as error:
        print(f"carapace: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

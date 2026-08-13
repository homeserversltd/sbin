"""Caduceus staff convergence for the HomeServer Matrix floor."""
from __future__ import annotations

import argparse
import json
import os
import pwd
import grp
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

from agathodaimon.reload import FingerprintGate, reload_services

SCHEMA = "caduceus.matrix.converge.v1"
FLOOR = ("matrix-synapse-py3", "nginx", "postgresql-client", "logrotate", "openssl", "unbound", "ca-certificates", "curl", "tar", "python3")


def result(argv: list[str], **kwargs: object) -> dict:
    completed = subprocess.run(argv, text=True, capture_output=True, check=False)
    return {"argv": argv, "exit": completed.returncode, "stdout": completed.stdout.strip(), "stderr": completed.stderr.strip(), **kwargs}


def require_floor() -> None:
    missing = [package for package in FLOOR if subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package], text=True, capture_output=True, check=False).stdout.strip() != "installed"]
    if missing:
        raise RuntimeError("matrix-floor-missing:" + ",".join(missing))
    for path, signal in ((Path("/usr/share/element-web/index.html"), "element-web-index"), (Path("/usr/share/element-web/.artifact-sha256"), "element-web-artifact-sha256")):
        if not path.is_file():
            raise RuntimeError("matrix-floor-missing:" + signal)


def atomic_text(path: Path, text: str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False) as out:
        out.write(text); out.flush(); os.fsync(out.fileno()); temporary = Path(out.name)
    os.chmod(temporary, mode); os.replace(temporary, path)


def reload_if_material_changed(service: str, paths: Sequence[Path], state_root: Path, plan: bool) -> dict:
    receipt = reload_services(
        [service],
        dry_run=plan,
        fingerprint_gates={service: FingerprintGate(paths, state_root / f"matrix-{service}-material.sha256")},
    )
    step = receipt["services"][0]
    if not receipt["ok"]:
        raise RuntimeError(receipt["firstMissingSignal"])
    return {**step, "reloaded": step["reload_outcome"] == "reloaded"}


def ensure_secret(path: Path) -> bool:
    if path.exists(): return False
    secret = subprocess.run(["openssl", "rand", "-hex", "32"], text=True, capture_output=True, check=True).stdout.strip()
    atomic_text(path, "registration_shared_secret: '" + secret + "'\n", 0o640)
    try:
        identity = pwd.getpwnam("matrix-synapse"); os.chown(path, identity.pw_uid, grp.getgrnam("matrix-synapse").gr_gid)
    except KeyError: pass
    return True


def update_portals(config_url: str) -> dict:
    shown = result(["curl", "-fsS", config_url + "/api/v1/config/show"])
    if shown["exit"] != 0: raise RuntimeError("caduceus-config-unreachable")
    try:
        document = json.loads(str(shown["stdout"]))["document"]
        portals = document["tabs"]["portals"]["data"]["portals"]
        visibility = document["tabs"]["portals"]["visibility"]["elements"]
        if not isinstance(portals, list) or not isinstance(visibility, dict): raise ValueError("shape")
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError("caduceus-config-unreachable")

    expected_portal = {"name": "Element", "url": "https://element.home.arpa"}
    element_portals = [item for item in portals if isinstance(item, dict) and item.get("name") == "Element"]
    drift: list[dict] = []
    if expected_portal not in element_portals:
        drift.append({"path": "tabs.portals.data.portals", "expected": expected_portal, "actual": element_portals})
    if visibility.get("Element") is not True:
        drift.append({"path": "tabs.portals.visibility.elements.Element", "expected": True, "actual": visibility.get("Element")})
    return {"portalsConverged": not drift, "portalDrift": drift}


def converge(plan: bool, config_url: str, state_root: Path) -> dict:
    paths = {"secret": Path("/etc/matrix-synapse/conf.d/90-birth-secrets.yaml"), "nginx": (Path("/etc/nginx/sites-available/matrix.home.arpa"), Path("/etc/nginx/sites-enabled/matrix.home.arpa"), Path("/etc/nginx/sites-available/element.home.arpa"), Path("/etc/nginx/sites-enabled/element.home.arpa")), "unbound": (Path("/etc/unbound/unbound.conf"), Path("/etc/unbound/unbound.conf.d/matrix.conf"))}
    planned = {"floor": list(FLOOR), "secret": str(paths["secret"]), "validate": [["nginx", "-t"], ["unbound-checkconf"], ["logrotate", "--debug", "/etc/logrotate.d/matrix-synapse"]], "config": config_url, "fingerprintState": str(state_root)}
    if plan: return {"schema": SCHEMA, "ok": True, "planned": True, "changed": None, "plan": planned, "firstMissingSignal": "none"}
    try:
        require_floor()
        secret_created = ensure_secret(paths["secret"])
        validations = [result(argv) for argv in planned["validate"]]
        if any(item["exit"] != 0 for item in validations): raise RuntimeError("matrix-config-validation-failed")
        portals = update_portals(config_url)
        nginx = reload_if_material_changed("nginx", paths["nginx"], state_root, False)
        unbound = reload_if_material_changed("unbound", paths["unbound"], state_root, False)
        return {"schema": SCHEMA, "ok": True, "planned": False, "changed": secret_created or nginx["changed"] or unbound["changed"], "secretCreated": secret_created, "validations": validations, **portals, "fingerprints": [nginx, unbound], "firstMissingSignal": "none"}
    except RuntimeError as error:
        return {"schema": SCHEMA, "ok": False, "planned": False, "changed": False, "firstMissingSignal": str(error)}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-matrix-converge")
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--config-url", default=os.environ.get("CADUCEUS_CONFIG_URL", "http://127.0.0.1:3014"))
    parser.add_argument("--state-root", type=Path, default=Path(os.environ.get("CADUCEUS_MATRIX_STATE_ROOT", "/var/lib/harmonia/state")))
    args = parser.parse_args(argv)
    value = converge(args.plan, args.config_url.rstrip("/"), args.state_root)
    print(json.dumps(value, sort_keys=True)); return 0 if value["ok"] else 1

if __name__ == "__main__": raise SystemExit(main())

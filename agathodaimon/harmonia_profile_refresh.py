"""Refresh Chia Harmonia profiles and own the corresponding path units."""
from __future__ import annotations
import argparse, fcntl, json, os, shutil, subprocess, tempfile
from pathlib import Path
from typing import Sequence

SCHEMA = "caduceus.harmonia.profile-refresh.v1"
PROFILES = ("chia-farmer-01", "chia-harvester-01", "chia-harvester-02")
SERVICE = """[Unit]
Description=Refresh the Chia Harmonia profile after its possessed source advances
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/agathodaimon/caduceus-harmonia-profile-refresh --refresh
Nice=10
IOSchedulingClass=idle
"""
PATH_UNIT = """[Unit]
Description=Watch the possessed harmonia-monad attachment for Chia profile advances

[Path]
PathChanged=/fulcrum/attachments/harmonia-monad
PathChanged=/fulcrum/.git/modules/attachments/harmonia-monad/HEAD
Unit=caduceus-harmonia-profile-refresh.service

[Install]
WantedBy=multi-user.target
"""

def run(argv: list[str], env: dict[str, str] | None = None) -> dict:
    p = subprocess.run(argv, text=True, capture_output=True, check=False, env=env)
    return {"argv": argv, "exit": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}

def atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False) as out:
        out.write(content); out.flush(); os.fsync(out.fileno()); temp = Path(out.name)
    os.chmod(temp, 0o644); os.replace(temp, path)

def selected(profile: str | None) -> str:
    value = profile or os.environ.get("HARMONIA_PROFILE_ID") or os.uname().nodename.split(".", 1)[0]
    if value not in PROFILES: raise ValueError("harmonia-profile-refresh-unsupported-profile:" + value)
    return value

def unit_paths(unit_dir: Path) -> dict[str, Path]:
    return {"service": unit_dir / "caduceus-harmonia-profile-refresh.service", "path": unit_dir / "caduceus-harmonia-profile-refresh.path"}

def install(unit_dir: Path, plan: bool) -> dict:
    paths = unit_paths(unit_dir)
    output = {"schema": SCHEMA, "ok": True, "operation": "install", "planned": plan, "units": {kind: str(path) for kind, path in paths.items()}, "commands": [["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", "caduceus-harmonia-profile-refresh.path"]], "firstMissingSignal": "none"}
    if plan: return output
    atomic(paths["service"], SERVICE); atomic(paths["path"], PATH_UNIT)
    steps = [run(command) for command in output["commands"]]
    output["results"] = steps; output["ok"] = all(step["exit"] == 0 for step in steps)
    if not output["ok"]: output["firstMissingSignal"] = "harmonia-profile-refresh-unit-install-failed"
    return output

def uninstall(unit_dir: Path, plan: bool) -> dict:
    paths = unit_paths(unit_dir)
    commands = [["systemctl", "disable", "--now", "caduceus-harmonia-profile-refresh.path"], ["systemctl", "daemon-reload"]]
    output = {"schema": SCHEMA, "ok": True, "operation": "uninstall", "planned": plan, "units": {kind: str(path) for kind, path in paths.items()}, "commands": commands, "firstMissingSignal": "none"}
    if plan: return output
    first = run(commands[0]);
    if first["exit"] != 0 and "not loaded" not in first["stderr"]: output.update(ok=False, firstMissingSignal="harmonia-profile-refresh-unit-uninstall-failed", results=[first]); return output
    for path in paths.values(): path.unlink(missing_ok=True)
    second = run(commands[1]); output["results"] = [first, second]; output["ok"] = second["exit"] == 0
    if not output["ok"]: output["firstMissingSignal"] = "harmonia-profile-refresh-unit-uninstall-failed"
    return output

def refresh(profile: str, plan: bool, source: Path, harmonia: str, config: Path, state: Path) -> dict:
    root = state / "receipts" / "profile-refresh"; capsule = Path(tempfile.gettempdir()) / f"caduceus-profile-refresh-{profile}"
    commands = [[harmonia, "capsule", "pack", profile, "--out", str(capsule), "--harmonia-root", str(source)], [harmonia, "capsule", "install", str(capsule), "--config-dir", str(config), "--apply"], [harmonia, "run-profile", str(config / "profiles" / profile / "index.json"), "--apply", "--receipt-dir", str(root / "applied-profile")]]
    answer = {"schema": SCHEMA, "ok": True, "operation": "refresh", "profile": profile, "planned": plan, "commands": commands, "receiptRoot": str(root), "firstMissingSignal": "none"}
    if plan: return answer
    if not (source / "profiles" / profile / "index.json").is_file(): return {**answer, "ok": False, "firstMissingSignal": "harmonia-profile-refresh-profile-missing"}
    state.mkdir(parents=True, exist_ok=True); lock = state / "profile-refresh.lock"
    with lock.open("a+") as held:
        try: fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: return {**answer, "changed": False, "skipped": "locked"}
        env = os.environ.copy(); env["HARMONIA_SUBSCRIPTION_PATH"] = str(state / "subscription.json")
        outcomes = [run(command, env) for command in commands]
        shutil.rmtree(capsule, ignore_errors=True)
    answer["results"] = outcomes; answer["ok"] = all(item["exit"] == 0 for item in outcomes); answer["changed"] = answer["ok"]
    if not answer["ok"]: answer["firstMissingSignal"] = "harmonia-profile-refresh-command-failed"
    return answer

def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-harmonia-profile-refresh")
    action = parser.add_mutually_exclusive_group(); action.add_argument("--install", action="store_true"); action.add_argument("--uninstall", action="store_true"); action.add_argument("--refresh", action="store_true")
    parser.add_argument("--plan", action="store_true"); parser.add_argument("--profile"); parser.add_argument("--unit-dir", type=Path, default=Path("/etc/systemd/system")); parser.add_argument("--source", type=Path, default=Path("/fulcrum/attachments/harmonia-monad")); parser.add_argument("--harmonia", default="/usr/local/bin/harmonia"); parser.add_argument("--config", type=Path, default=Path("/etc/harmonia")); parser.add_argument("--state", type=Path, default=Path("/var/lib/harmonia"))
    args = parser.parse_args(argv)
    try:
        value = install(args.unit_dir, args.plan) if args.install else uninstall(args.unit_dir, args.plan) if args.uninstall else refresh(selected(args.profile), args.plan, args.source, args.harmonia, args.config, args.state)
    except ValueError as error: value = {"schema": SCHEMA, "ok": False, "firstMissingSignal": str(error)}
    print(json.dumps(value, sort_keys=True)); return 0 if value["ok"] else 1
if __name__ == "__main__": raise SystemExit(main())

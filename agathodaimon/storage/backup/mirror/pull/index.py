"""Pull the HomeServer's primary NAS into this box's backup drive."""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

from agathodaimon.lib.keyman_export.index import export_credential
from agathodaimon.storage.nas import deed

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("nas_sync_guard", HERE.parents[2] / "nas-sync" / "index.py")
if spec is None or spec.loader is None:
    raise RuntimeError("nas-sync-guard-unavailable")
nas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nas)
SCHEMA = "caduceus.backup.mirror.pull.v1"


def wipe(buf):
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def seat():
    try:
        routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
        candidates = []
        for line in routes:
            row = line.split()
            if len(row) >= 8 and row[1] == "00000000" and int(row[3], 16) & 3 == 3:
                gateway = ipaddress.IPv4Address(int(row[2], 16).to_bytes(4, "little"))
                if int(gateway):
                    candidates.append((int(row[6]), str(gateway)))
        if not candidates:
            raise ValueError("no route")
        host = min(candidates)[1]
    except (OSError, ValueError, IndexError):
        raise nas.Refusal("default-gateway-unavailable")
    port = None
    try:
        info = json.loads(Path("/etc/appliance/ruyi.json").read_text())
        gateway = info.get("gateway_seat", {})
        if gateway.get("ipv4") == host:
            port = gateway.get("caduceus_port")
    except (OSError, ValueError, AttributeError):
        pass
    if type(port) is not int or not 0 < port < 65536:
        try:
            config = json.loads(Path("/etc/appliance/config.json").read_text())
            port = config.get("caduceus", {}).get("seat_port")
        except (OSError, ValueError, AttributeError):
            port = None
    if type(port) is not int or not 0 < port < 65536:
        port = 8787
    return host, port


def run_rsync(host, port, username, password, dest, cap, dry_run):
    if len(username) + len(password) > 4000 or b"\n" in username or b"\n" in password:
        raise nas.Refusal("mirror-credential-invalid")
    read_fd, write_fd = os.pipe()
    try:
        for part in (username, b"\n", password):
            view = memoryview(part)
            while view:
                view = view[os.write(write_fd, view):]
        os.close(write_fd)
        write_fd = -1
        env = os.environ.copy()
        env.update(CADUCEUS_MIRROR_CREDENTIAL_FD=str(read_fd), CADUCEUS_MIRROR_IPV4=host,
                   CADUCEUS_MIRROR_PORT=str(port))
        remote_shell = shlex.join([sys.executable, str(HERE.parents[1] / "tunnel.py")])
        argv = ["/usr/bin/rsync", "-aH", "--stats", "--delete-delay", "--exclude=lost+found",
                "--max-delete=" + str(cap), "-e", remote_shell]
        if dry_run:
            argv.append("-n")
        argv.extend(["homeserver:/", str(dest) + "/"])
        return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True, env=env,
                              pass_fds=(read_fd,), check=False)
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def source_measure(stats):
    count = stats.get("Number of files", "")
    detail = re.search(r"\(([^)]*)\)", count)
    if detail:
        count = 0
        for field in detail.group(1).split(", "):
            match = re.fullmatch(r"([a-z]+):\s*([0-9,]+)", field.strip())
            if not match:
                raise nas.Refusal("source-stats-unavailable")
            if match.group(1) != "dir":
                count += int(match.group(2).replace(",", ""))
    elif re.fullmatch(r"0", count):
        count = 0
    else:
        raise nas.Refusal("source-stats-unavailable")
    size = re.match(r"^([0-9,]+) bytes", stats.get("Total file size", ""))
    if size is None:
        raise nas.Refusal("source-stats-unavailable")
    return count, int(size.group(1).replace(",", ""))


def destination():
    # Proof only: scratch destination must live below AGATHODAIMON_SCRATCH_ROOT.
    root = os.environ.get("AGATHODAIMON_SCRATCH_ROOT")
    raw = os.environ.get("CADUCEUS_MIRROR_SCRATCH_DESTINATION")
    if raw is None:
        return Path("/mnt/nas_backup"), False
    if root is None:
        raise nas.Refusal("mirror-scratch-invalid")
    base = Path(root).resolve(strict=True)
    path = Path(raw).resolve(strict=True)
    if base == Path("/") or path == base or not path.is_relative_to(base) or not path.is_dir():
        raise nas.Refusal("mirror-scratch-invalid")
    return path, True


def pull(metadata):
    started = time.monotonic()
    result = {"schema": SCHEMA, "ok": False, "converged": False, "outcome": "refused",
              "planned": False, "firstMissingSignal": "none", "checks": [], "rsyncExitCode": None,
              "rsyncStats": None, "maxDelete": None, "homeserver": None}
    lock = None
    username = password = None
    attempted = False
    dry_run = metadata.get("dryRun", False)
    result["planned"] = dry_run is True
    try:
        if type(dry_run) is not bool:
            raise nas.Refusal("mirror-dry-run-invalid")
        baseline = metadata.get("baseline")
        if baseline is not None and (not isinstance(baseline, dict) or any(
                type(baseline.get(k)) is not int or baseline[k] < 0 for k in ("fileCount", "totalBytes"))):
            raise nas.Refusal("mirror-baseline-invalid")
        lock = nas.acquire_lock()
        nas.checked(result["checks"], "single-instance-lock")
        dest, scratch = destination()
        if not scratch:
            source, _ = nas.mount_info(dest, nas.command)
            facts = nas.device_facts(source, nas.command)
            label = nas.partlabel(facts, nas.command)
            if label in nas.DENYLIST or label != "homeserver-backup-nas":
                raise nas.Refusal("backup-partlabel-invalid")
            nas.checked(result["checks"], "backup-device", partlabel=label)
            scopes = nas.kernel_gate(facts, facts, nas.command)
            nas.checked(result["checks"], "current-boot-kernel-log-clean", attachScopes=scopes[:1])
        else:
            nas.checked(result["checks"], "proof-only-scratch-destination")
        files, size = nas.measure(dest)
        nas.checked(result["checks"], "destination-measured", fileCount=files, totalBytes=size)
        reference = baseline["fileCount"] if baseline is not None else files
        cap = max(1000, reference * 20 // 100)
        result["maxDelete"] = cap
        host, port = seat()
        result["homeserver"] = {"ipv4": host, "port": port}
        username, password = export_credential("backup_pair")
        if not username or not password:
            raise nas.Refusal("backup-pair-credential-unavailable")
        # A dry traversal supplies remote source counts before any delete-capable pull.
        scan = run_rsync(host, port, username, password, dest, cap, True)
        result["rsyncExitCode"] = scan.returncode
        result["rsyncStats"] = nas.parse_rsync_stats(scan.stdout)
        if scan.returncode:
            raise nas.Refusal("mirror-source-scan-failed")
        source_files, source_bytes = source_measure(result["rsyncStats"])
        nas.checked(result["checks"], "source-measured", fileCount=source_files, totalBytes=source_bytes)
        if baseline is not None:
            reasons = nas.shrink_reasons(source_files, source_bytes, baseline)
            if reasons:
                raise nas.Refusal("source-shrink-refused:" + ",".join(reasons))
            nas.checked(result["checks"], "shrink-canary")
        if dry_run:
            result.update(ok=False, outcome="planned", converged=False, firstMissingSignal="planned-only")
        else:
            attempted = True
            run = run_rsync(host, port, username, password, dest, cap, False)
            result["rsyncExitCode"] = run.returncode
            result["rsyncStats"] = nas.parse_rsync_stats(run.stdout)
            if run.returncode:
                raise nas.Refusal("rsync-delete-cap-exceeded" if run.returncode == 25 else "mirror-rsync-failed")
            result.update(ok=True, converged=True, outcome="ok", firstMissingSignal="none")
    except nas.Refusal as error:
        result.update(outcome="failed" if attempted else "refused", firstMissingSignal=str(error))
    except Exception:
        result.update(outcome="failed" if attempted else "refused", firstMissingSignal="mirror-pull-unavailable")
    finally:
        wipe(username)
        wipe(password)
        if lock is not None:
            os.close(lock)
        if not result["planned"]:
            try:
                deed.record("mirror-pull", "nas-sync", result, started)
            except Exception:
                result.update(ok=False, converged=False, outcome="failed", firstMissingSignal="mirror-deed-unavailable")
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(65537)
        if len(raw) > 65536:
            raise ValueError("large")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("invalid")
        metadata = request.get("metadata")
        if metadata is None and isinstance(request.get("payload"), dict):
            metadata = request["payload"].get("metadata")
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("invalid")
        result = pull(metadata)
    except (ValueError, UnicodeError):
        result = {"schema": SCHEMA, "ok": False, "converged": False, "outcome": "refused",
                  "planned": False, "firstMissingSignal": "mirror-request-invalid", "checks": [],
                  "rsyncExitCode": None, "rsyncStats": None, "maxDelete": None, "homeserver": None}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] or result["outcome"] == "planned" else 1


if __name__ == "__main__":
    raise SystemExit(main())

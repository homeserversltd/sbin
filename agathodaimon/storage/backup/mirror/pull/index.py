"""Pull the HomeServer's primary NAS into this box's backup drive."""
from __future__ import annotations

import importlib.util
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from agathodaimon import _envelope
from agathodaimon.lib.keyman_export.index import export_credential
from agathodaimon.storage.nas import deed

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location("nas_sync_guard", HERE.parents[2] / "nas-sync" / "_sync.py")
if spec is None or spec.loader is None:
    raise RuntimeError("nas-sync-guard-unavailable")
nas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nas)


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


def prove_home(host, port, mac):
    connection = None
    try:
        connection = http.client.HTTPConnection(host, port, timeout=5)
        connection.request("GET", "/api/v1/ruyi?seat=1")
        response = connection.getresponse()
        body = response.read(65536)
        if response.status != 200 or len(body) == 65536:
            raise ValueError("invalid seat response")
        value = json.loads(body)
        peer = value.get("seat", {}).get("mac")
        if (value.get("ok") is not True or value.get("service") != "caduceus"
                or not isinstance(peer, str) or peer.lower() != mac):
            raise ValueError("unproven seat")
    except Exception:
        raise nas.Refusal("mirror-home-unproven") from None
    finally:
        if connection is not None:
            connection.close()


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
        idle = 600
        if os.environ.get("AGATHODAIMON_SCRATCH_ROOT"):
            idle = int(os.environ.get("CADUCEUS_MIRROR_PROOF_IDLE_SECONDS", "600"))
            if not 0 < idle <= 600:
                raise nas.Refusal("mirror-scratch-invalid")
        argv = ["/usr/bin/rsync", "-aH", "--stats", "--delete-delay", "--exclude=lost+found",
                "--timeout=" + str(idle), "-e", remote_shell]
        if dry_run:
            argv.append("-n")
        else:
            argv.append("--max-delete=" + str(cap))
        argv.extend(["homeserver:/", str(dest) + "/"])
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env, pass_fds=(read_fd,))
        first = bytearray()
        def drain():
            line_done = False
            while True:
                chunk = process.stderr.read(4096)
                if not chunk:
                    break
                if not line_done:
                    part, separator, _ = chunk.partition(b"\n")
                    first.extend(part[:max(0, 4097 - len(first))])
                    line_done = bool(separator) or len(first) > 4096
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        stdout = process.stdout.read().decode("utf-8", "replace")
        code = process.wait()
        reader.join()
        signal = None
        if len(first) <= 4096:
            try:
                value = json.loads(first)
                candidate = value.get("signal") if value.get("ok") is False else None
                if isinstance(candidate, str) and (candidate in {
                    "mirror-copy-stalled", "mirror-tunnel-failed", "mirror-upgrade-invalid",
                    "mirror-remote-command-invalid", "mirror-credential-invalid", "backup-mirror-busy",
                    "mirror-serve-lock-busy", "backup-pair-unknown", "backup-mirror-child-failed",
                } or re.fullmatch(r"mirror-http-([0-9]{3}|invalid)", candidate)):
                    signal = candidate
            except (ValueError, AttributeError, UnicodeError):
                pass
        return subprocess.CompletedProcess(argv, code, stdout, signal)
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


def proof():
    names = ("AGATHODAIMON_SCRATCH_ROOT", "BACKUP_DRIVE_PROOF_KEYMAN",
             "BACKUP_DRIVE_PROOF_SEAT", "CADUCEUS_MIRROR_SCRATCH_DESTINATION")
    values = [os.environ.get(name) for name in names]
    if all(value is None for value in values):
        return None
    if not all(values):
        raise nas.Refusal("mirror-scratch-invalid")
    try:
        root, keyman, target, dest = values
        if not all(Path(p).is_absolute() for p in (root, keyman, dest)):
            raise ValueError("relative path")
        base = Path(root).resolve(strict=True)
        executable = Path(keyman).resolve(strict=True)
        path = Path(dest).resolve(strict=True)
        host, port = target.rsplit(":", 1)
        port = int(port)
        if (base == Path("/") or not base.is_dir() or not executable.is_relative_to(base)
                or not executable.is_file() or not os.access(executable, os.X_OK)
                or path == base or not path.is_relative_to(base) or not path.is_dir()
                or host != "127.0.0.1" or not 0 < port < 65536):
            raise ValueError("invalid proof")
        return base, str(executable), host, port, path
    except (OSError, ValueError, RuntimeError):
        raise nas.Refusal("mirror-scratch-invalid") from None


def own_box(context):
    path = context[0] / "ruyi.json" if context else Path("/etc/appliance/ruyi.json")
    try:
        if context:
            # Never follow a scratch identity link into the live appliance.
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            with os.fdopen(fd, "r", encoding="utf-8") as stream:
                info = json.load(stream)
        else:
            info = json.loads(path.read_text())
        mac = info.get("self", {}).get("mac")
        if not isinstance(mac, str) or not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", mac):
            raise ValueError("invalid mac")
        return {"mac": mac.lower(), "hostname": socket.gethostname()}
    except (OSError, ValueError, AttributeError, TypeError):
        raise nas.Refusal("backup-drive-mac-unavailable") from None


def rsync_failure(run, fallback):
    return run.stderr or ("mirror-copy-stalled" if run.returncode == 30 else fallback)


def report_home(result, password, started):
    """Best-effort report to the already-proven peer; never echo its token."""
    home, box = result.get("homeserver"), result.get("box")
    if result["planned"] or not password or not home or not box:
        return
    connection = None
    try:
        credential = bytes(password).decode("utf-8")
        signal = "none" if result["outcome"] == "ok" else result["firstMissingSignal"].split(":", 1)[0]
        if signal == "current-boot-kernel-error-names-backing-drive":
            signal = "kernel-error-on-backup-drive"
        if not re.fullmatch(r"[a-z0-9-]{1,40}", signal) or credential in signal:
            signal = "pull-failed"
        # Even the fallback must not contain a coincidentally short credential.
        if credential in signal:
            return
        body = json.dumps({"mac": box["mac"], "credential": credential, "outcome": result["outcome"],
                           "signal": signal, "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                           "durationMs": max(0, int((time.monotonic() - started) * 1000))})
        connection = http.client.HTTPConnection(home["ipv4"], home["port"], timeout=5)
        connection.request("POST", "/api/v1/storage/backup/pair/report", body=body,
                           headers={"Content-Type": "application/json"})
        connection.getresponse().close()
    except Exception:
        pass
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def pull(metadata):
    started = time.monotonic()
    result = {"ok": False, "converged": False, "outcome": "refused",
              "planned": False, "firstMissingSignal": "none", "checks": [], "rsyncExitCode": None,
              "rsyncStats": None, "maxDelete": None, "homeserver": None}
    lock = None
    username = password = None
    attempted = False
    context = None
    proof_valid = False
    dry_run = metadata.get("dryRun", False)
    result["planned"] = dry_run is True
    try:
        context = proof()
        proof_valid = True
        try:
            result["box"] = own_box(context)
        except nas.Refusal:
            pass
        if type(dry_run) is not bool:
            raise nas.Refusal("mirror-dry-run-invalid")
        baseline = metadata.get("baseline")
        if baseline is not None and (not isinstance(baseline, dict) or any(
                type(baseline.get(k)) is not int or baseline[k] < 0 for k in ("fileCount", "totalBytes"))):
            raise nas.Refusal("mirror-baseline-invalid")
        home = metadata.get("home")
        if home is None:
            raise nas.Refusal("mirror-home-unenrolled")
        if (not isinstance(home, dict) or set(home) != {"mac"}
                or not isinstance(home["mac"], str)
                or not re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", home["mac"])):
            raise nas.Refusal("mirror-request-invalid")
        lock = nas.acquire_lock()
        nas.checked(result["checks"], "single-instance-lock")
        dest, scratch = (context[4], True) if context else (Path("/mnt/nas_backup"), False)
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
        host, port = (context[2], context[3]) if context else seat()
        prove_home(host, port, home["mac"])
        result["homeserver"] = {"ipv4": host, "port": port, "mac": home["mac"]}
        username, password = (export_credential("backup_pair", scratch_root=context[0], exporter=context[1])
                              if context else export_credential("backup_pair"))
        if not username or not password:
            raise nas.Refusal("backup-pair-credential-unavailable")
        # A dry traversal supplies remote source counts before any delete-capable pull.
        scan = run_rsync(host, port, username, password, dest, None, True)
        result["rsyncExitCode"] = scan.returncode
        result["rsyncStats"] = nas.parse_rsync_stats(scan.stdout)
        if scan.returncode:
            raise nas.Refusal(rsync_failure(scan, "mirror-source-scan-failed"))
        source_files, source_bytes = source_measure(result["rsyncStats"])
        nas.checked(result["checks"], "source-measured", fileCount=source_files, totalBytes=source_bytes)
        reference = baseline["fileCount"] if baseline is not None else source_files
        cap = max(1000, reference * 20 // 100)
        result["maxDelete"] = cap
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
                raise nas.Refusal(rsync_failure(run, "rsync-delete-cap-exceeded" if run.returncode == 25 else "mirror-rsync-failed"))
            final_files, final_bytes = source_measure(result["rsyncStats"])
            nas.checked(result["checks"], "source-remeasured-after-sync", fileCount=final_files, totalBytes=final_bytes)
            result.update(finalFileCount=final_files, finalTotalBytes=final_bytes)
            result.update(ok=True, converged=True, outcome="ok", firstMissingSignal="none")
    except nas.Refusal as error:
        result.update(outcome="failed" if attempted else "refused", firstMissingSignal=str(error))
    except Exception:
        result.update(outcome="failed" if attempted else "refused", firstMissingSignal="mirror-pull-unavailable")
    finally:
        report_home(result, password, started)
        wipe(username)
        wipe(password)
        if lock is not None:
            os.close(lock)
        if not result["planned"] and proof_valid:
            try:
                deed_receipt = {**result, "firstMissingSignal": result["firstMissingSignal"].split(":", 1)[0]}
                if deed_receipt["firstMissingSignal"] == "current-boot-kernel-error-names-backing-drive":
                    deed_receipt["firstMissingSignal"] = "kernel-error-on-backup-drive"
                counts = ({"file_count": result["finalFileCount"], "total_bytes": result["finalTotalBytes"]}
                          if result["ok"] else None)
                deed.record("mirror-pull", "nas-sync", deed_receipt, started, counts=counts)
            except Exception:
                pass
    return result


def main(argv=None):
    words = sys.argv[1:] if argv is None else list(argv)
    if words:
        print(json.dumps({"ok": False, "firstMissingSignal": "mirror-arguments-invalid"}, sort_keys=True))
        return 1
    try:
        request = _envelope.read(max_input_bytes=65536).value
        metadata = request.get("metadata")
        if metadata is None and isinstance(request.get("payload"), dict):
            metadata = request["payload"].get("metadata")
        if metadata is None:
            metadata = {}
        if not isinstance(metadata, dict):
            raise ValueError("invalid")
        result = pull(metadata)
    except (ValueError, UnicodeError) as error:
        if isinstance(error, _envelope.EnvelopeError) and isinstance(error.__cause__, OSError):
            raise error.__cause__  # Transport I/O was never a mirror validation refusal.
        result = {"ok": False, "converged": False, "outcome": "refused",
                  "planned": False, "firstMissingSignal": "mirror-request-invalid", "checks": [],
                  "rsyncExitCode": None, "rsyncStats": None, "maxDelete": None, "homeserver": None}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] or result["outcome"] == "planned" else 1


if __name__ == "__main__":
    raise SystemExit(main())

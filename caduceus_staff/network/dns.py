from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence


class DnsError(RuntimeError):
    """A bounded, operator-readable Unbound managed-drop-in failure."""


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class DnsManager:
    """Install exactly one bounded, managed Unbound local-data drop-in."""

    ROOT_CONFIG = Path("/etc/unbound/unbound.conf")
    DROPIN_DIR = Path("/etc/unbound/unbound.conf.d")
    TARGET_NAME = "laptop-home-arpa.conf"
    CHECKCONF = "unbound-checkconf"
    SERVICE = "unbound"
    MAX_PAYLOAD_BYTES = 8192
    ACTION = "network dns"
    INTENT_TARGET = "/api/dns/unbound/drop-in"
    READ_INCLUDE_PATH = Path("/etc/unbound/unbound.conf.d/caduceus-local-names.conf")
    BEGIN = "# BEGIN CADUCEUS OWNED DEVICE RECORDS"
    END = "# END CADUCEUS OWNED DEVICE RECORDS"

    def __init__(
        self,
        root_config: str | Path | None = None,
        dropin_dir: str | Path | None = None,
        include_path: str | Path | None = None,
        *,
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.root_config = Path(root_config or os.environ.get("CADUCEUS_UNBOUND_CONFIG", self.ROOT_CONFIG))
        self.dropin_dir = Path(dropin_dir or os.environ.get("CADUCEUS_UNBOUND_DROPIN_DIR", self.DROPIN_DIR))
        self.target = self.dropin_dir / self.TARGET_NAME
        self.read_include = Path(include_path or os.environ.get("CADUCEUS_UNBOUND_INCLUDE", self.READ_INCLUDE_PATH))
        self._command_runner = command_runner or self._run

    @staticmethod
    def _run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)

    def _command(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self._command_runner(command)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError(f"command failed: {' '.join(command)}: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip() or f"exit {result.returncode}"
            raise DnsError(f"command failed: {' '.join(command)}: {detail}")
        return result

    @staticmethod
    def _digest(payload: bytes | None) -> str | None:
        return hashlib.sha256(payload).hexdigest() if payload is not None else None

    def _safe_target(self, target: str | None) -> Path:
        if target not in (None, self.TARGET_NAME):
            raise DnsError("dns-target-not-admitted")
        if self.target.name != self.TARGET_NAME or self.target.parent != self.dropin_dir:
            raise DnsError("dns-target-not-admitted")
        if self.dropin_dir.is_symlink() or self.target.is_symlink():
            raise DnsError("dns-target-symlink-refused")
        return self.target

    @staticmethod
    def _validate_payload(payload: Any) -> bytes:
        if not isinstance(payload, str):
            raise DnsError("dns-payload-missing")
        encoded = payload.encode("utf-8")
        if not encoded or len(encoded) > DnsManager.MAX_PAYLOAD_BYTES or "\x00" in payload:
            raise DnsError("dns-payload-invalid")
        lines = payload.splitlines()
        if not lines or lines[0].strip() != "server:":
            raise DnsError("dns-payload-not-unbound")
        records: set[str] = set()
        pattern = re.compile(
            r'^\s+local-data:\s+"laptop\.home\.arpa\. IN A 192\.168\.123\.(19|20)"\s*$'
        )
        for line in lines[1:]:
            match = pattern.fullmatch(line)
            if not match or match.group(1) in records:
                raise DnsError("dns-payload-not-admitted")
            records.add(match.group(1))
        if records != {"19", "20"}:
            raise DnsError("dns-payload-not-admitted")
        return (payload.rstrip() + "\n").encode("utf-8")

    def _root_text(self) -> str:
        try:
            return self.root_config.read_text(encoding="utf-8")
        except OSError as exc:
            raise DnsError(f"dns-root-config-unreadable: {exc}") from exc

    def _stage_full_config(self, candidate: bytes) -> Path:
        root_text = self._root_text()
        expected_include = f'include-toplevel: "{self.dropin_dir}/*.conf"'
        if expected_include not in root_text:
            raise DnsError("dns-managed-include-missing")
        stage: Path | None = None
        try:
            stage = Path(tempfile.mkdtemp(prefix="caduceus-unbound-stage-"))
            stage_dropins = stage / "unbound.conf.d"
            stage_dropins.mkdir(mode=0o700)
            if self.dropin_dir.exists():
                for sibling in self.dropin_dir.iterdir():
                    if sibling.name == self.TARGET_NAME:
                        continue
                    if sibling.is_symlink() or not sibling.is_file():
                        raise DnsError("dns-neighbor-not-regular")
                    shutil.copy2(sibling, stage_dropins / sibling.name)
            (stage_dropins / self.TARGET_NAME).write_bytes(candidate)
            stage_root = stage / "unbound.conf"
            stage_root.write_text(root_text.replace(expected_include, f'include-toplevel: "{stage_dropins}/*.conf"'), encoding="utf-8")
            return stage
        except Exception:
            if stage is not None:
                shutil.rmtree(stage, ignore_errors=True)
            raise

    def _validate_staged(self, candidate: bytes) -> None:
        stage = self._stage_full_config(candidate)
        try:
            self._command([self.CHECKCONF, str(stage / "unbound.conf")])
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def _validate_owned_staged(self, candidate: bytes) -> None:
        root_text = self._root_text()
        expected_include = f'include-toplevel: "{self.dropin_dir}/*.conf"'
        if expected_include not in root_text:
            raise DnsError("dns-managed-include-missing")
        stage = Path(tempfile.mkdtemp(prefix="caduceus-unbound-owned-stage-"))
        try:
            stage_dropins = stage / "unbound.conf.d"
            stage_dropins.mkdir(mode=0o700)
            if self.dropin_dir.exists():
                for sibling in self.dropin_dir.iterdir():
                    if sibling.is_symlink() or not sibling.is_file():
                        raise DnsError("dns-neighbor-not-regular")
                    if sibling != self.read_include:
                        shutil.copy2(sibling, stage_dropins / sibling.name)
            (stage_dropins / self.read_include.name).write_bytes(candidate)
            stage_root = stage / "unbound.conf"
            stage_root.write_text(root_text.replace(expected_include, f'include-toplevel: "{stage_dropins}/*.conf"'), encoding="utf-8")
            self._command([self.CHECKCONF, str(stage_root)])
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def _validate_live(self) -> None:
        self._command([self.CHECKCONF, str(self.root_config)])

    def _replace_bytes(self, target: Path, payload: bytes, mode: int = 0o644) -> None:
        self.dropin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        if self.dropin_dir.is_symlink():
            raise DnsError("dns-target-symlink-refused")
        with tempfile.NamedTemporaryFile(dir=self.dropin_dir, prefix=f".{target.name}.", delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
        try:
            temporary.chmod(mode)
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def _restore(self, previous: bytes | None, mode: int) -> None:
        if previous is None:
            self.target.unlink(missing_ok=True)
        else:
            self._replace_bytes(self.target, previous, mode)
        self._validate_live()
        self._command(["systemctl", "reload", self.SERVICE])

    def status(self) -> dict[str, Any]:
        return {
            "schema": "caduceus.network.dns.v1",
            "action": "status",
            "target": str(self.target),
            "rootConfig": str(self.root_config),
            "targetExists": self.target.is_file() and not self.target.is_symlink(),
            "firstMissingSignal": "none",
            "ok": True,
        }

    def read_status(self) -> dict[str, Any]:
        """Additive read-actuator view without changing the mutation membrane's status."""
        result = self.status()
        result["actuator"] = "network.dns.status"
        result["read"] = self.read()
        result["mutationPerformed"] = False
        return result

    def _owned_lines(self) -> list[str]:
        try:
            text = self.read_include.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise DnsError(f"failed to read owned include {self.read_include}: {exc}") from exc
        if self.BEGIN not in text or self.END not in text:
            return []
        return text.split(self.BEGIN, 1)[1].split(self.END, 1)[0].splitlines()

    def read(self) -> dict[str, Any]:
        """Read only Caduceus-owned records; an absent include is an empty well."""
        devices: dict[str, dict[str, Any]] = {}
        aliases: list[dict[str, str]] = []
        for line in self._owned_lines():
            match = re.search(r'local-data:\s+"([^\s]+)\.?\s+IN\s+(A|PTR|CNAME)\s+([^\s"]+)"', line, re.I)
            if not match:
                continue
            name, record_type, target = match.group(1).rstrip(".").lower(), match.group(2).upper(), match.group(3).rstrip(".").lower()
            if record_type == "CNAME":
                aliases.append({"name": name, "target": target})
            elif record_type == "A":
                devices.setdefault(name, {"name": name, "a": [], "ptr": []})["a"].append(target)
            else:
                devices.setdefault(target, {"name": target, "a": [], "ptr": []})["ptr"].append(name)
        return {"include": str(self.read_include), "exists": self.read_include.is_file(), "devices": [devices[key] for key in sorted(devices)], "aliases": sorted(aliases, key=lambda item: item["name"]), "mutationPerformed": False, "firstMissingSignal": "none"}

    @staticmethod
    def canonical_name(hostname: str) -> str:
        label = hostname.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise DnsError("dns-hostname-malformed")
        return f"{label}.home.arpa."

    @staticmethod
    def _reverse_name(address: str) -> str:
        try:
            ip = ipaddress.IPv4Address(address)
        except ipaddress.AddressValueError as exc:
            raise DnsError("dns-ipv4-malformed") from exc
        return ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa."

    @staticmethod
    def _alias_name(label: str) -> str:
        value = label.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
            raise DnsError("dns-alias-label-malformed")
        return f"{value}.home.arpa."

    def _include_text(self) -> str:
        try:
            return self.read_include.read_text(encoding="utf-8")
        except FileNotFoundError:
            return f"{self.BEGIN}\n{self.END}\n"
        except OSError as exc:
            raise DnsError(f"failed to read owned include {self.read_include}: {exc}") from exc

    def _split_owned_include(self, text: str) -> tuple[str, str, str]:
        if text.count(self.BEGIN) != 1 or text.count(self.END) != 1:
            raise DnsError("dns-ownership-markers-invalid")
        before, rest = text.split(self.BEGIN, 1)
        owned, after = rest.split(self.END, 1)
        return before, owned, after

    def _render_owned(self, lines: list[str]) -> bytes:
        text = self._include_text()
        before, _owned, after = self._split_owned_include(text)
        payload = before + self.BEGIN + "\n"
        payload += "".join(f'    local-data: "{line}"\n' for line in sorted(lines))
        payload += self.END + after
        return payload.encode("utf-8")

    def _owned_records(self) -> list[str]:
        records: list[str] = []
        for line in self._owned_lines():
            match = re.fullmatch(r'\s*local-data:\s+"(.+)"\s*', line, re.I)
            if match:
                records.append(match.group(1))
        return records

    def _observed_owner_names(self) -> set[str]:
        names: set[str] = set()
        paths = [self.root_config, self.read_include]
        if self.dropin_dir.is_dir():
            paths.extend(path for path in self.dropin_dir.glob("*.conf") if path != self.read_include)
        for path in paths:
            try:
                text = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                continue
            except OSError as exc:
                raise DnsError(f"dns-observed-record-unreadable: {exc}") from exc
            for name in re.findall(r'local-data:\s+"([^\s]+)', text, re.I):
                names.add(name.rstrip(".").lower())
        return names

    def _validate_candidate(self, lines: list[str], new_owners: set[str]) -> None:
        owned_names: set[str] = set()
        cname_names: set[str] = set()
        for line in lines:
            match = re.fullmatch(r"([^\s]+)\s+IN\s+(A|PTR|CNAME)\s+([^\s]+)", line, re.I)
            if not match:
                raise DnsError("dns-owned-record-malformed")
            owner, record_type = match.group(1).rstrip(".").lower(), match.group(2).upper()
            if record_type == "CNAME":
                cname_names.add(owner)
            else:
                owned_names.add(owner)
        if cname_names & owned_names:
            raise DnsError("dns-cname-a-owner-conflict")
        observed = self._observed_owner_names()
        existing_owned = {line.split()[0].rstrip(".").lower() for line in self._owned_records()}
        if any(owner in observed - existing_owned for owner in new_owners):
            raise DnsError("dns-observed-record-collision")

    def _candidate_apply(self, lines: list[str], expected: list[tuple[str, str]]) -> dict[str, Any]:
        candidate = self._render_owned(lines)
        previous = self.read_include.read_bytes() if self.read_include.exists() else None
        mode = self.read_include.stat().st_mode & 0o777 if self.read_include.exists() else 0o644
        receipt: dict[str, Any] = {"config_valid": False, "reload_outcome": "not-run", "live_query_readback": [], "mutationPerformed": False}
        try:
            self._validate_owned_staged(candidate)
            receipt["config_valid"] = True
            self._replace_bytes(self.read_include, candidate, mode)
            self._command(["systemctl", "reload", self.SERVICE])
            receipt["reload_outcome"] = "reloaded"
            for record_type, owner in expected:
                result = self._command(["unbound-host", "-t", record_type, owner])
                receipt["live_query_readback"].append({"type": record_type, "owner": owner, "output": result.stdout.strip()})
            receipt["mutationPerformed"] = True
            return receipt
        except DnsError as exc:
            receipt["first_failing_boundary"] = str(exc)
            try:
                if previous is None:
                    self.read_include.unlink(missing_ok=True)
                else:
                    self._replace_bytes(self.read_include, previous, mode)
                self._command(["systemctl", "reload", self.SERVICE])
                receipt["candidate"] = "restored"
            except DnsError as rollback:
                receipt["candidate"] = "restore-failed"
                receipt["rollback_error"] = str(rollback)
            raise DnsError(json.dumps(receipt, sort_keys=True)) from exc

    def owned_preimage(self) -> bytes | None:
        return self.read_include.read_bytes() if self.read_include.exists() else None

    def restore_owned_preimage(self, previous: bytes | None) -> dict[str, Any]:
        mode = self.read_include.stat().st_mode & 0o777 if self.read_include.exists() else 0o644
        if previous is None:
            self.read_include.unlink(missing_ok=True)
        else:
            self._replace_bytes(self.read_include, previous, mode)
        self._validate_live()
        self._command(["systemctl", "reload", self.SERVICE])
        restored = self.read_include.read_bytes() if self.read_include.exists() else None
        if restored != previous:
            raise DnsError("dns-preimage-restoration-mismatch")
        return {"config_valid": True, "reload_outcome": "reloaded", "restoration_verified": True}

    def create_device_name(self, hostname: str, address: str) -> dict[str, Any]:
        canonical = self.canonical_name(hostname)
        reverse = self._reverse_name(address)
        lines = self._owned_records()
        additions = [f"{canonical} IN A {address}", f"{reverse} IN PTR {canonical}"]
        if any(value in lines for value in additions):
            if all(value in lines for value in additions):
                return {"action": "device-name-create", "state": "noop", "canonical_name": canonical, "mutationPerformed": False, "verification": []}
            raise DnsError("dns-device-projection-incomplete")
        self._validate_candidate(lines + additions, {canonical.rstrip(".").lower(), reverse.rstrip(".").lower()})
        return {"action": "device-name-create", "state": "applied", "canonical_name": canonical, "verification": self._candidate_apply(lines + additions, [("A", canonical), ("PTR", reverse)])}

    def remove_device_name(self, hostname: str, address: str) -> dict[str, Any]:
        canonical, reverse = self.canonical_name(hostname), self._reverse_name(address)
        removals = {f"{canonical} IN A {address}", f"{reverse} IN PTR {canonical}"}
        lines = self._owned_records()
        present = removals & set(lines)
        if not present:
            return {"action": "device-name-remove", "state": "noop", "canonical_name": canonical, "mutationPerformed": False, "verification": []}
        if present != removals:
            raise DnsError("dns-device-projection-incomplete")
        return {"action": "device-name-remove", "state": "applied", "canonical_name": canonical, "verification": self._candidate_apply([line for line in lines if line not in removals], [("A", canonical), ("PTR", reverse)])}

    def create_alias(self, alias_label: str, hostname: str) -> dict[str, Any]:
        alias, canonical = self._alias_name(alias_label), self.canonical_name(hostname)
        lines = self._owned_records()
        record = f"{alias} IN CNAME {canonical}"
        if record in lines:
            return {"action": "alias-create", "state": "noop", "alias": alias, "mutationPerformed": False, "verification": []}
        self._validate_candidate(lines + [record], {alias.rstrip(".").lower()})
        return {"action": "alias-create", "state": "applied", "alias": alias, "verification": self._candidate_apply(lines + [record], [("CNAME", alias)])}

    def remove_alias(self, alias_label: str, hostname: str) -> dict[str, Any]:
        alias, canonical = self._alias_name(alias_label), self.canonical_name(hostname)
        record = f"{alias} IN CNAME {canonical}"
        lines = self._owned_records()
        if record not in lines:
            return {"action": "alias-remove", "state": "noop", "alias": alias, "mutationPerformed": False, "verification": []}
        return {"action": "alias-remove", "state": "applied", "alias": alias, "verification": self._candidate_apply([line for line in lines if line != record], [("CNAME", alias)])}

    def apply(self, metadata: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(metadata, dict):
            raise DnsError("dns-metadata-invalid")
        target = self._safe_target(metadata.get("target"))
        candidate = self._validate_payload(metadata.get("dropIn"))
        dry_run = metadata.get("dryRun", False)
        if not isinstance(dry_run, bool):
            raise DnsError("dns-dry-run-invalid")
        previous = target.read_bytes() if target.exists() else None
        before_hash, after_hash = self._digest(previous), self._digest(candidate)
        receipt: dict[str, Any] = {
            "schema": "caduceus.network.dns.v1",
            "action": "apply-managed-drop-in",
            "target": str(target),
            "beforeHash": before_hash,
            "afterHash": after_hash,
            "stagedValidation": False,
            "liveValidation": False,
            "reload": "not-run",
            "rollback": "not-needed",
            "mutationPerformed": False,
            "ok": True,
            "firstMissingSignal": "none",
        }
        self._validate_staged(candidate)
        receipt["stagedValidation"] = True
        if dry_run:
            receipt["action"] = "plan-managed-drop-in"
            return receipt
        if previous == candidate:
            self._validate_live()
            receipt["liveValidation"] = True
            receipt["reload"] = "not-needed-idempotent"
            return receipt
        mode = target.stat().st_mode & 0o777 if target.exists() else 0o644
        try:
            self._replace_bytes(target, candidate, mode)
            self._validate_live()
            receipt["liveValidation"] = True
            self._command(["systemctl", "reload", self.SERVICE])
            receipt["reload"] = "reloaded"
            receipt["mutationPerformed"] = True
            return receipt
        except DnsError as exc:
            try:
                self._restore(previous, mode)
                receipt["rollback"] = "restored-and-revalidated"
            except DnsError as rollback:
                receipt["rollback"] = "failed"
                receipt["ok"] = False
                receipt["firstMissingSignal"] = f"{exc}; dns-rollback-failed: {rollback}"
                return receipt
            receipt["ok"] = False
            receipt["firstMissingSignal"] = str(exc)
            return receipt


def _failure(action: str, reason: str) -> dict[str, Any]:
    return {
        "schema": "caduceus.network.dns.v1",
        "action": action,
        "ok": False,
        "mutationPerformed": False,
        "firstMissingSignal": reason,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="caduceus-network-dns")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("read")
    device = commands.add_parser("device-name")
    device.add_argument("action", choices=("create", "remove"))
    device.add_argument("--hostname", required=True)
    device.add_argument("--ip", required=True)
    alias = commands.add_parser("alias")
    alias.add_argument("action", choices=("create", "remove"))
    alias.add_argument("--label", required=True)
    alias.add_argument("--hostname", required=True)
    intent = commands.add_parser("intent")
    intent.add_argument("method")
    intent.add_argument("target")
    intent.add_argument("--metadata-json", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    manager = DnsManager()
    try:
        if args.command == "status":
            receipt = manager.read_status()
        elif args.command == "read":
            receipt = {"schema": "caduceus.network.dns.v1", "actuator": "network.dns.read", "action": "read", "ok": True, "result": manager.read(), "mutationPerformed": False, "firstMissingSignal": "none"}
        elif args.command == "device-name":
            receipt = manager.create_device_name(args.hostname, args.ip) if args.action == "create" else manager.remove_device_name(args.hostname, args.ip)
            receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.device_name.{args.action}", "ok": True, "firstMissingSignal": "none"}
        elif args.command == "alias":
            receipt = manager.create_alias(args.label, args.hostname) if args.action == "create" else manager.remove_alias(args.label, args.hostname)
            receipt |= {"schema": "caduceus.network.dns.v1", "actuator": f"network.dns.alias.{args.action}", "ok": True, "firstMissingSignal": "none"}
        else:
            if args.method != "POST" or args.target != DnsManager.INTENT_TARGET:
                raise DnsError("dns-intent-not-admitted")
            try:
                metadata = json.loads(args.metadata_json)
            except json.JSONDecodeError as exc:
                raise DnsError("dns-metadata-invalid") from exc
            receipt = manager.apply(metadata)
    except DnsError as exc:
        receipt = _failure(args.command, str(exc))
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

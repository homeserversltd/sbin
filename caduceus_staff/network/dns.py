from __future__ import annotations

import argparse
import hashlib
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

    def __init__(
        self,
        root_config: str | Path | None = None,
        dropin_dir: str | Path | None = None,
        *,
        command_runner: CommandRunner | None = None,
    ) -> None:
        self.root_config = Path(root_config or os.environ.get("CADUCEUS_UNBOUND_CONFIG", self.ROOT_CONFIG))
        self.dropin_dir = Path(dropin_dir or os.environ.get("CADUCEUS_UNBOUND_DROPIN_DIR", self.DROPIN_DIR))
        self.target = self.dropin_dir / self.TARGET_NAME
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
            receipt = manager.status()
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

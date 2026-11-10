from __future__ import annotations

import glob
import hashlib
import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Sequence

from agathodaimon import _load_trace
from agathodaimon._nidus.write import WriteError, write
from agathodaimon.reload.index import reload_services

# Managed drop-in lineage carried from sbin 0851389; direct-file lineage remains above.
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
    READ_INCLUDE_PATH = Path("/etc/unbound/unbound.conf.d/agathodaimon-local-names.conf")
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
        self._incomplete_owned_restore = False

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

    def _reload_service(self) -> dict[str, Any]:
        receipt = reload_services([self.SERVICE], command_runner=self._command_runner)
        step = receipt["services"][0]
        if not receipt["ok"]:
            raise DnsError(receipt["firstMissingSignal"])
        return step

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
            stage = Path(tempfile.mkdtemp(prefix="agathodaimon-unbound-stage-"))
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

    def _validate_owned_staged(self, candidate: bytes, gateway_candidate: bytes | None = None) -> None:
        root_text = self._root_text()
        expected_include = f'include-toplevel: "{self.dropin_dir}/*.conf"'
        if expected_include not in root_text:
            raise DnsError("dns-managed-include-missing")
        stage = Path(tempfile.mkdtemp(prefix="agathodaimon-unbound-owned-stage-"))
        try:
            stage_dropins = stage / "unbound.conf.d"
            stage_dropins.mkdir(mode=0o700)
            if self.dropin_dir.exists():
                for sibling in self.dropin_dir.iterdir():
                    if sibling.is_symlink() or not sibling.is_file():
                        raise DnsError("dns-neighbor-not-regular")
                    if sibling.name == "caduceus-local-names.conf" and gateway_candidate is not None:
                        (stage_dropins / sibling.name).write_bytes(gateway_candidate)
                    elif sibling != self.read_include:
                        shutil.copy2(sibling, stage_dropins / sibling.name)
            (stage_dropins / self.read_include.name).write_bytes(candidate)
            stage_root = stage / "unbound.conf"
            stage_root.write_text(root_text.replace(expected_include, f'include-toplevel: "{stage_dropins}/*.conf"'), encoding="utf-8")
            self._command([self.CHECKCONF, str(stage_root)])
        finally:
            shutil.rmtree(stage, ignore_errors=True)

    def _validate_live(self) -> None:
        self._command([self.CHECKCONF, str(self.root_config)])

    def _replace_bytes(self, target: Path, payload: bytes | None, mode: int = 0o644) -> None:
        self.dropin_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        if self.dropin_dir.is_symlink():
            raise DnsError("dns-target-symlink-refused")
        try:
            write([{"path": target, "candidate": payload, "mode": mode}])
        except WriteError as exc:
            raise exc.cause

    def _restore(self, previous: bytes | None, mode: int) -> None:
        self._replace_bytes(self.target, previous, mode)
        self._validate_live()
        self._reload_service()

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

    _INCLUDE = re.compile(r'^\s*(?:include|include-toplevel)\s*:\s*"([^"\r\n]+)"', re.I)
    _LOCAL_DATA = re.compile(r'\blocal-data\s*:\s*"([^\s"]+)\.?\s+(?:IN\s+)?(A|PTR|CNAME)\s+([^\s"]+)', re.I)
    _ALIAS_MARKER = re.compile(r'\s+# agathodaimon-alias ([^\s]+)\s*$')

    def _config_paths(self) -> list[Path]:
        """Return the root and every recursively referenced Unbound fragment."""
        paths: list[Path] = []
        seen: set[Path] = set()

        def visit(path: Path, required: bool) -> None:
            resolved = path.resolve(strict=False)
            if resolved in seen:
                return
            try:
                text = path.read_text(encoding="utf-8")
            except FileNotFoundError:
                if required:
                    raise DnsError(f"dns-root-config-unreadable: {path}")
                return
            except OSError as exc:
                raise DnsError(f"dns-config-unreadable: {path}: {exc}") from exc
            seen.add(resolved)
            paths.append(path)
            for line in text.splitlines():
                match = self._INCLUDE.match(line)
                if not match:
                    continue
                candidate = Path(match.group(1))
                if not candidate.is_absolute():
                    candidate = path.parent / candidate
                matches = sorted(Path(value) for value in glob.glob(str(candidate)))
                if matches:
                    for included in matches:
                        visit(included, required=False)
                elif not any(character in str(candidate) for character in "*?["):
                    visit(candidate, required=False)

        visit(self.root_config, required=True)
        return paths

    def _all_local_records(self) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for path in self._config_paths():
            text = path.read_text(encoding="utf-8")
            owned = False
            inside_markers = False
            for line in text.splitlines():
                if self.BEGIN in line:
                    inside_markers = True
                    owned = path == self.read_include
                    continue
                if self.END in line:
                    owned = False
                    inside_markers = False
                    continue
                match = None if line.lstrip().startswith("#") else self._LOCAL_DATA.search(line)
                if not match:
                    continue
                records.append({
                    "name": match.group(1).rstrip(".").lower(),
                    "type": match.group(2).upper(),
                    "target": match.group(3).rstrip(".").lower(),
                    "provenance": "owned" if owned else "legacy",
                    "source": str(path),
                    "inside_markers": inside_markers,
                })
                marker = self._ALIAS_MARKER.search(line)
                if owned and match.group(2).upper() == "A" and marker:
                    records[-1]["alias_target"] = marker.group(1).rstrip(".").lower()
        return records

    def read(self) -> dict[str, Any]:
        """Read configured local-data identity under one optional transient span."""
        with _load_trace.span(
            "agathodaimon.network.dns.local_data_read",
            road="local-file",
            source_state="configured-unbound-files",
        ):
            return self._read_local_data()

    def _read_local_data(self) -> dict[str, Any]:
        """Read every configured local-data identity; ownership only governs writes."""
        devices: dict[str, dict[str, Any]] = {}
        aliases: list[dict[str, str]] = []
        for record in self._all_local_records():
            name, record_type, target, provenance = record["name"], record["type"], record["target"], record["provenance"]
            if record_type == "CNAME" or "alias_target" in record:
                alias = {"name": name, "target": record.get("alias_target", target), "provenance": provenance}
                if alias not in aliases:
                    aliases.append(alias)
                continue
            if record_type == "A":
                device = devices.setdefault(name, {"name": name, "a": [], "ptr": [], "a_records": [], "ptr_records": [], "provenance": []})
                if target not in device["a"]:
                    device["a"].append(target)
                device["a_records"].append({"address": target, "provenance": provenance})
            else:
                device = devices.setdefault(target, {"name": target, "a": [], "ptr": [], "a_records": [], "ptr_records": [], "provenance": []})
                if name not in device["ptr"]:
                    device["ptr"].append(name)
                device["ptr_records"].append({"name": name, "provenance": provenance})
        for device in devices.values():
            device["a"].sort()
            device["ptr"].sort()
            device["a_records"].sort(key=lambda item: (item["address"], item["provenance"]))
            device["ptr_records"].sort(key=lambda item: (item["name"], item["provenance"]))
            records_with_provenance = device["a_records"] + device["ptr_records"]
            device["provenance"] = sorted({item["provenance"] for item in records_with_provenance})
        return {"include": str(self.read_include), "exists": self.read_include.is_file(), "devices": [devices[key] for key in sorted(devices)], "aliases": sorted(aliases, key=lambda item: (item["name"], item["target"], item["provenance"])), "mutationPerformed": False, "firstMissingSignal": "none"}

    @staticmethod
    def canonical_name(hostname: str) -> str:
        label = hostname.strip().lower().rstrip(".")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise DnsError("dns-hostname-malformed")
        return "home.arpa." if label == "home" else f"{label}.home.arpa."

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
        if value == "home":
            raise DnsError("dns-alias-owner-conflict")
        return f"{value}.home.arpa."

    def _include_text(self) -> str:
        try:
            return self.read_include.read_text(encoding="utf-8")
        except FileNotFoundError:
            return f"server:\n{self.BEGIN}\n{self.END}\n"
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
        before, owned, after = self._split_owned_include(text)
        remaining = [(line, self._record_parts(line)) for line in lines]
        rendered: list[str] = []
        for raw in owned.splitlines(keepends=True):
            match = re.fullmatch(r'\s*local-data:\s+"([^"\r\n]+)"\s*(#.*)?(?:\r?\n)?', raw, re.I)
            if not match:
                rendered.append(raw)
                continue
            suffix = match.group(2) or ""
            marker = self._ALIAS_MARKER.fullmatch(" " + suffix)
            old = self._record_parts(match.group(1) + (f" # agathodaimon-alias {marker.group(1)}" if marker else ""))
            index = next((i for i, (_, parts) in enumerate(remaining) if parts == old), None)
            if index is not None:
                remaining.pop(index)
                rendered.append(raw)
                continue
            index = next((i for i, (_, parts) in enumerate(remaining) if parts[0] == old[0] and (parts[1] == old[1] or old[1] == "CNAME" and parts[3] is not None)), None)
            if index is None:
                continue
            line, _parts = remaining.pop(index)
            owner, kind, target, alias_target = self._record_parts(line)
            marker = f" # agathodaimon-alias {alias_target}" if alias_target else ""
            rendered.append(f'    local-data: "{owner} IN {kind} {target}"{marker}\n')
        for line, _parts in remaining:
            owner, kind, target, alias_target = self._record_parts(line)
            marker = f" # agathodaimon-alias {alias_target}" if alias_target else ""
            rendered.append(f'    local-data: "{owner} IN {kind} {target}"{marker}\n')
        payload = before + self.BEGIN + "".join(rendered) + self.END + after
        return payload.encode("utf-8")

    def _owned_records(self) -> list[str]:
        records: list[str] = []
        for line in self._owned_lines():
            match = re.fullmatch(r'\s*local-data:\s+"([^"\r\n]+)"\s*(#.*)?', line, re.I)
            if match:
                suffix = match.group(2) or ""
                marker = self._ALIAS_MARKER.fullmatch(" " + suffix)
                if suffix.startswith("# agathodaimon-alias") and not marker:
                    raise DnsError("dns-owned-record-malformed")
                records.append(match.group(1) + (f" # agathodaimon-alias {marker.group(1)}" if marker else ""))
        return records

    @staticmethod
    def _record_parts(line: str) -> tuple[str, str, str, str | None]:
        match = re.fullmatch(r"([^\s]+)\s+IN\s+(A|PTR|CNAME)\s+([^\s]+)(?:\s+# agathodaimon-alias ([^\s]+))?", line, re.I)
        if not match or (match.group(4) and match.group(2).upper() != "A"):
            raise DnsError("dns-owned-record-malformed")
        owner, kind, target, alias_target = match.groups()
        owner, kind = owner.rstrip(".").lower() + ".", kind.upper()
        target = target if kind == "A" else target.rstrip(".").lower() + "."
        return owner, kind, target, alias_target.rstrip(".").lower() + "." if alias_target else None

    def _alias_bindings(self, lines: list[str]) -> dict[str, str]:
        bindings: dict[str, str] = {}
        for line in lines:
            owner, kind, target, alias_target = self._record_parts(line)
            canonical = target if kind == "CNAME" else alias_target
            if canonical is not None:
                if owner in bindings and bindings[owner] != canonical:
                    raise DnsError("dns-alias-owner-conflict")
                bindings[owner] = canonical
        return bindings

    def _migrate_gateway_records(self, lines: list[str]) -> list[str]:
        """Retire the old gateway identity only in the owned record set."""
        old = "homeserver.home.arpa."
        apex = self.canonical_name("home")
        migrated = []
        for line in lines:
            owner, kind, target, marker = self._record_parts(line)
            if owner == old and kind == "A" and marker is None:
                continue
            if kind == "PTR" and target == old:
                target = apex
            if kind == "CNAME" and target == old:
                target = apex
            if marker == old:
                marker = apex
            migrated.append(f"{owner} IN {kind} {target}" + (f" # agathodaimon-alias {marker}" if marker else ""))
        return migrated

    def _gateway_file_candidate(self) -> tuple[Path, bytes | None, bytes | None]:
        path = self.dropin_dir / "caduceus-local-names.conf"
        if not path.exists():
            return path, None, None
        if path.is_symlink() or not path.is_file():
            raise DnsError("dns-neighbor-not-regular")
        original = path.read_bytes()
        text = original.decode("utf-8")
        if self.BEGIN not in text and self.END not in text:
            return path, original, original
        before, owned, after = self._split_owned_include(text)
        old = "homeserver.home.arpa."
        apex = self.canonical_name("home")
        output = []
        for raw in owned.splitlines(keepends=True):
            match = re.fullmatch(r'(\s*local-data:\s+\")([^"\r\n]+)(\"[^\r\n]*)(\r?\n)?', raw, re.I)
            if not match:
                output.append(raw)
                continue
            try:
                owner, kind, target, marker = self._record_parts(match.group(2))
            except DnsError:
                output.append(raw)
                continue
            if owner == old and kind == "A" and marker is None:
                continue
            if kind == "PTR" and target == old:
                body = f"{owner} IN PTR {apex}"
                raw = match.group(1) + body + match.group(3) + (match.group(4) or "")
            output.append(raw)
        candidate = (before + self.BEGIN + "".join(output) + self.END + after).encode("utf-8")
        return path, original, candidate

    def _project_aliases(self, lines: list[str], *, removed_targets: set[str] | None = None) -> list[str]:
        """Refresh marked A aliases and migrate owned CNAMEs in one candidate."""
        bindings = self._alias_bindings(lines)
        base = [line for line in lines if self._record_parts(line)[1] != "CNAME" and self._record_parts(line)[3] is None]
        addresses: dict[str, set[str]] = {}
        for line in base:
            owner, kind, target, _alias_target = self._record_parts(line)
            if kind == "A":
                addresses.setdefault(owner, set()).add(target)
        other_addresses: dict[str, set[str]] = {}
        for record in self._all_local_records():
            if record["provenance"] != "owned" and record["type"] == "A" and (record["name"] != "home.arpa" or record["source"] == str(self.root_config)):
                other_addresses.setdefault(record["name"] + ".", set()).add(record["target"])

        def resolve(owner: str) -> set[str]:
            seen: set[str] = set()
            while owner in bindings:
                if owner in seen:
                    raise DnsError("dns-alias-target-unresolved")
                seen.add(owner)
                owner = bindings[owner]
            if owner in addresses:
                return addresses[owner]
            fallback = other_addresses.get(owner, set())
            if len(fallback) == 1:
                return fallback
            if not fallback and owner in (removed_targets or set()):
                return set()
            raise DnsError("dns-alias-target-unresolved")

        for alias, canonical in sorted(bindings.items()):
            base.extend(f"{alias} IN A {address} # agathodaimon-alias {canonical}" for address in sorted(resolve(canonical)))
        return base

    def _observed_owner_names(self) -> set[str]:
        names: set[str] = set()
        for record in self._all_local_records():
            names.add(record["name"])
        return names

    def _validate_candidate(self, lines: list[str], new_owners: set[str]) -> None:
        owned_names: set[str] = set()
        cname_names: set[str] = set()
        alias_names: set[str] = set()
        device_addresses: dict[str, str] = {}
        for line in lines:
            owner, record_type, target, alias_target = self._record_parts(line)
            owner = owner.rstrip(".")
            if record_type == "CNAME":
                cname_names.add(owner)
            elif alias_target:
                alias_names.add(owner)
            else:
                owned_names.add(owner)
                if record_type == "A":
                    if target in device_addresses and device_addresses[target] != owner:
                        raise DnsError("dns-observed-record-collision")
                    device_addresses[target] = owner
        if cname_names & owned_names:
            raise DnsError("dns-cname-a-owner-conflict")
        if alias_names & owned_names or cname_names & alias_names:
            raise DnsError("dns-alias-owner-conflict")
        observed = self._all_local_records()
        proposed_apex = {target for target, owner in device_addresses.items() if owner == "home.arpa"}
        base_apex = {record["target"] for record in observed if record["source"] == str(self.root_config) and record["name"] == "home.arpa" and record["type"] == "A"}
        if proposed_apex and proposed_apex != base_apex:
            raise DnsError("dns-gateway-apex-address-mismatch")
        for record in observed:
            if record["provenance"] == "owned":
                continue
            if record["name"] == "home.arpa" and record["type"] == "A" and proposed_apex == base_apex and record["name"] in new_owners:
                continue
            if record["name"] in new_owners or (record["type"] == "A" and record["target"] in device_addresses and device_addresses[record["target"]] != record["name"]):
                raise DnsError("dns-observed-record-collision")

    def _live_query_readback(self, query_tool: str, record_type: str, owner: str,
                             wanted: set[str]) -> tuple[dict[str, Any], set[str], bool]:
        command = [query_tool, "@127.0.0.1", owner, record_type, "+short", "+tries=1", "+time=1"]
        for attempt in range(1, 6):
            try:
                result = self._command_runner(command)
            except subprocess.TimeoutExpired as exc:
                stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
                stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
                result = subprocess.CompletedProcess(command, 124, stdout, stderr)
                timed_out = True
            except OSError as exc:
                raise DnsError(f"command failed: {' '.join(command)}: {exc}") from exc
            else:
                timed_out = False
            output = result.stdout
            diagnostic = timed_out or any(
                line.lstrip().startswith(";") and
                ("timed out" in line.lower() or "timeout" in line.lower() or "communications error" in line.lower())
                for line in (output + "\n" + result.stderr).splitlines()
            )
            answered = {line.strip().rstrip(".").lower() for line in output.splitlines()
                        if line.strip() and not line.lstrip().startswith(";")}
            row = {"type": record_type, "owner": owner, "output": output, "readback_attempts": attempt}
            if attempt == 5 or (not diagnostic and answered == wanted and result.returncode == 0):
                return row, answered, result.returncode != 0 or (diagnostic and not answered)
            time.sleep(1)
        raise AssertionError("unreachable readback retry")

    def _candidate_apply(self, lines: list[str], expected: list[tuple[str, str]]) -> dict[str, Any]:
        query_tool = shutil.which("dig")
        if query_tool is None:
            raise DnsError("dns-live-query-tool-missing")
        previous_lines = self._owned_records()
        gateway_path, gateway_previous, gateway_candidate = self._gateway_file_candidate()
        lines = self._migrate_gateway_records(lines)
        previous_targets = {owner for owner, kind, _target, marker in map(self._record_parts, previous_lines) if kind == "A" and marker is None} | self._alias_bindings(previous_lines).keys()
        current_targets = {owner for owner, kind, _target, marker in map(self._record_parts, lines) if kind == "A" and marker is None} | self._alias_bindings(lines).keys()
        lines = self._project_aliases(lines, removed_targets=previous_targets - current_targets)
        existing_owners = {self._record_parts(line)[0].rstrip(".") for line in previous_lines}
        self._validate_candidate(lines, {self._record_parts(line)[0].rstrip(".") for line in lines} - existing_owners)
        candidate = self._render_owned(lines)
        queries = set(expected)
        queries.update(("A", alias) for alias in self._alias_bindings(previous_lines) | self._alias_bindings(lines))
        values: dict[tuple[str, str], set[str]] = {}
        for line in lines:
            owner, kind, target, _alias_target = self._record_parts(line)
            values.setdefault((kind, owner), set()).add(target.rstrip(".").lower())
        for record in self._all_local_records():
            if record["provenance"] != "owned":
                changed_gateway_row = gateway_candidate != gateway_previous and record["source"] == str(gateway_path) and record["inside_markers"]
                if changed_gateway_row and record["name"] == "homeserver.home.arpa" and record["type"] == "A":
                    continue
                if changed_gateway_row and record["type"] == "PTR" and record["target"] == "homeserver.home.arpa":
                    values.setdefault((record["type"], record["name"] + "."), set()).add("home.arpa")
                    continue
                values.setdefault((record["type"], record["name"] + "."), set()).add(record["target"])
        previous = self.read_include.read_bytes() if self.read_include.exists() else None
        mode = self.read_include.stat().st_mode & 0o777 if self.read_include.exists() else 0o644
        gateway_mode = gateway_path.stat().st_mode & 0o777 if gateway_previous is not None else 0o644
        changed = candidate != previous or gateway_candidate != gateway_previous
        receipt: dict[str, Any] = {"config_valid": False, "reload_outcome": "not-run", "live_query_readback": [], "mutationPerformed": False}
        def check() -> None:
            self._validate_owned_staged(candidate, gateway_candidate)
            receipt["config_valid"] = True

        reload_attempted = False

        def reload() -> None:
            nonlocal reload_attempted
            candidate_live = (self.read_include.read_bytes() if self.read_include.exists() else None) == candidate
            first_candidate_reload = not reload_attempted and candidate_live
            reload_attempted = True
            self._reload_service()
            if first_candidate_reload:
                receipt["reload_outcome"] = "reloaded"

        def readback() -> None:
            if not changed:
                receipt["reload_outcome"] = "not-needed-idempotent"
            for record_type, owner in sorted(queries):
                wanted = values.get((record_type, owner), set())
                row, answered, diagnostic = self._live_query_readback(query_tool, record_type, owner, wanted)
                receipt["live_query_readback"].append(row)
                if wanted and not answered:
                    raise DnsError(f"dns-live-query-empty: {record_type} {owner}")
                if not wanted and answered:
                    raise DnsError(f"dns-live-query-still-present: {record_type} {owner}")
                if answered != wanted:
                    raise DnsError(f"dns-live-query-mismatch: {record_type} {owner}")
                if diagnostic:
                    raise DnsError(f"dns-live-query-unavailable: {record_type} {owner}")

        edits = [{"path": self.read_include, "candidate": candidate, "mode": mode}]
        if gateway_candidate is not None:
            edits.insert(0, {"path": gateway_path, "candidate": gateway_candidate, "mode": gateway_mode})
        try:
            result = write(edits, check=check, reload=reload, readback=readback)
            receipt["mutationPerformed"] = result["changed"]
            return receipt
        except WriteError as exc:
            receipt["first_failing_boundary"] = str(exc.cause)
            if exc.restore_errors:
                receipt["candidate"] = "restore-failed"
                receipt["rollback_error"] = str(exc.restore_errors[0])
                self._incomplete_owned_restore = True
            else:
                receipt["candidate"] = "restored"
            raise DnsError(json.dumps(receipt, sort_keys=True)) from exc

    def owned_preimage(self) -> bytes | None:
        return self.read_include.read_bytes() if self.read_include.exists() else None

    def restore_owned_preimage(self, previous: bytes | None) -> dict[str, Any]:
        mode = self.read_include.stat().st_mode & 0o777 if self.read_include.exists() else 0o644
        self._replace_bytes(self.read_include, previous, mode)
        self._validate_live()
        self._reload_service()
        restored = self.read_include.read_bytes() if self.read_include.exists() else None
        if restored != previous:
            raise DnsError("dns-preimage-restoration-mismatch")
        if self._incomplete_owned_restore:
            raise DnsError("dns-gateway-preimage-restoration-unproven")
        return {"config_valid": True, "reload_outcome": "reloaded", "restoration_verified": True}

    def create_device_name(self, hostname: str, address: str) -> dict[str, Any]:
        canonical = self.canonical_name(hostname)
        reverse = self._reverse_name(address)
        lines = self._owned_records()
        if canonical == "home.arpa.":
            records = self._all_local_records()
            observed = {r["target"] for r in records if r["name"] == "home.arpa" and r["type"] == "A" and r["source"] == str(self.root_config)}
            if observed != {address}:
                raise DnsError("dns-gateway-apex-address-mismatch")
            reverse_present = any(r["name"] == reverse.rstrip(".") and r["type"] == "PTR" and r["target"] in {"home.arpa", "homeserver.home.arpa"} for r in records)
            additions = [] if reverse_present else [f"{reverse} IN PTR {canonical}"]
            verification = self._candidate_apply(lines + additions, [("A", canonical), ("PTR", reverse)])
            return {"action": "device-name-create", "state": "applied" if verification["mutationPerformed"] else "noop", "canonical_name": canonical, "mutationPerformed": verification["mutationPerformed"], "verification": verification}
        if canonical in self._alias_bindings(lines):
            raise DnsError("dns-alias-owner-conflict")
        addresses = {target for owner, kind, target, marker in map(self._record_parts, lines) if owner == canonical and kind == "A" and marker is None}
        reverses = {owner for owner, kind, target, _marker in map(self._record_parts, lines) if kind == "PTR" and target == canonical}
        if {self._reverse_name(value) for value in addresses} != reverses:
            raise DnsError("dns-device-projection-incomplete")
        retained = [line for line in lines if not (self._record_parts(line)[0] == canonical and self._record_parts(line)[1] == "A" or self._record_parts(line)[1:3] == ("PTR", canonical))]
        additions = [f"{canonical} IN A {address}", f"{reverse} IN PTR {canonical}"]
        verification = self._candidate_apply(retained + additions, [("A", canonical), ("PTR", reverse)] + [("PTR", old) for old in reverses])
        return {"action": "device-name-create", "state": "applied" if verification["mutationPerformed"] else "noop", "canonical_name": canonical, "mutationPerformed": verification["mutationPerformed"], "verification": verification}

    def remove_device_name(self, hostname: str, address: str) -> dict[str, Any]:
        canonical, reverse = self.canonical_name(hostname), self._reverse_name(address)
        if canonical == "home.arpa.":
            lines = self._owned_records()
            retained = [line for line in lines if self._record_parts(line) != (reverse, "PTR", canonical, None)]
            verification = self._candidate_apply(retained, [("PTR", reverse)])
            return {"action": "device-name-remove", "state": "applied" if verification["mutationPerformed"] else "noop", "canonical_name": canonical, "mutationPerformed": verification["mutationPerformed"], "verification": verification}
        removals = {(canonical, "A", address, None), (reverse, "PTR", canonical, None)}
        lines = self._owned_records()
        present = removals & set(map(self._record_parts, lines))
        if present and present != removals:
            raise DnsError("dns-device-projection-incomplete")
        verification = self._candidate_apply([line for line in lines if self._record_parts(line) not in removals], [("A", canonical), ("PTR", reverse)] if present else [])
        return {"action": "device-name-remove", "state": "applied" if verification["mutationPerformed"] else "noop", "canonical_name": canonical, "mutationPerformed": verification["mutationPerformed"], "verification": verification}

    def create_alias(self, alias_label: str, hostname: str) -> dict[str, Any]:
        alias, canonical = self._alias_name(alias_label), self.canonical_name(hostname)
        lines = self._migrate_gateway_records(self._owned_records())
        bindings = self._alias_bindings(lines)
        if alias == canonical or any(self._record_parts(line)[0] == alias for line in lines) and bindings.get(alias) != canonical:
            raise DnsError("dns-alias-owner-conflict")
        retained = [line for line in lines if self._record_parts(line)[0] != alias]
        verification = self._candidate_apply(retained + [f"{alias} IN CNAME {canonical}"], [("A", alias)])
        return {"action": "alias-create", "state": "applied" if verification["mutationPerformed"] else "noop", "alias": alias, "mutationPerformed": verification["mutationPerformed"], "verification": verification}

    def remove_alias(self, alias_label: str, hostname: str) -> dict[str, Any]:
        alias, canonical = self._alias_name(alias_label), self.canonical_name(hostname)
        lines = self._migrate_gateway_records(self._owned_records())
        matches = self._alias_bindings(lines).get(alias) == canonical
        retained = [line for line in lines if not (matches and self._record_parts(line)[0] == alias)]
        verification = self._candidate_apply(retained, [("A", alias)] if matches else [])
        return {"action": "alias-remove", "state": "applied" if verification["mutationPerformed"] else "noop", "alias": alias, "mutationPerformed": verification["mutationPerformed"], "verification": verification}

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
        if dry_run:
            self._validate_staged(candidate)
            receipt["stagedValidation"] = True
            receipt["action"] = "plan-managed-drop-in"
            return receipt
        mode = target.stat().st_mode & 0o777 if target.exists() else 0o644
        reload_calls = 0

        def check() -> None:
            self._validate_staged(candidate)
            receipt["stagedValidation"] = True

        def verify() -> None:
            self._validate_live()
            receipt["liveValidation"] = True

        def reload() -> None:
            nonlocal reload_calls
            reload_calls += 1
            normal_reload = receipt["liveValidation"] and reload_calls == 1
            if not normal_reload:
                self._validate_live()
            self._reload_service()
            if normal_reload:
                receipt["reload"] = "reloaded"

        def readback() -> None:
            if previous == candidate:
                verify()
                receipt["reload"] = "not-needed-idempotent"

        try:
            result = write([{"path": target, "candidate": candidate, "mode": mode}],
                           check=check, verify=verify, reload=reload, readback=readback)
            receipt["mutationPerformed"] = result["changed"]
            return receipt
        except WriteError as exc:
            restored = any(row["step"] == "restore" for row in exc.parts["attempt"]["steps"])
            if not receipt["stagedValidation"] or previous == candidate or not restored:
                raise exc.cause
            receipt["ok"] = False
            if exc.restore_errors:
                receipt["rollback"] = "failed"
                receipt["firstMissingSignal"] = f"{exc.cause}; dns-rollback-failed: {exc.restore_errors[0]}"
            else:
                receipt["rollback"] = "restored-and-revalidated"
                receipt["firstMissingSignal"] = str(exc.cause)
            return receipt




def create_alias(alias_label: str, hostname: str, *, manager: DnsManager | None = None) -> dict[str, Any]:
    """Compose alias admission without rewriting an already-correct legacy A.

    Older portal names can live outside the managed include. They are reusable
    only when their sole A answer is the target's and they own no reverse record;
    every new or managed alias still goes through the ordinary alias writer.
    """
    manager = manager or DnsManager()
    alias, canonical = manager._alias_name(alias_label), manager.canonical_name(hostname)
    records = manager._all_local_records()
    existing = [row for row in records if row["name"] == alias.rstrip(".")]
    target = [row for row in records if row["name"] == canonical.rstrip(".") and row["type"] == "A"]
    owned_target = [row for row in target if row["provenance"] == "owned"]
    addresses = {row["target"] for row in owned_target or target}
    if (
        alias != canonical and len(addresses) == 1 and existing
        and all(row["provenance"] != "owned" and row["type"] == "A" for row in existing)
        and {row["target"] for row in existing} == addresses
        and not any(row["type"] == "PTR" and row["target"] == alias.rstrip(".") for row in records)
    ):
        verification = manager._candidate_apply(manager._owned_records(), [("A", alias)])
        return {
            "action": "alias-create", "state": "applied" if verification["mutationPerformed"] else "noop", "alias": alias,
            "mutationPerformed": verification["mutationPerformed"], "verification": verification,
        }
    return manager.create_alias(alias_label, hostname)

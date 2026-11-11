from __future__ import annotations

import ipaddress
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Sequence

from agathodaimon._nidus import unit
from agathodaimon._nidus.lock import identity_locked
from agathodaimon._nidus.write import WriteError, write
from agathodaimon.network.dns._manager import CommandRunner, DnsError, DnsManager

class ResolverControl:
    """Bounded owner for the resolver-control portion of Unbound configuration."""

    CONFIG = Path("/etc/unbound/unbound.conf")
    BLOCKLIST = Path("/etc/unbound/blocklist.conf")
    CHECKCONF = "/usr/sbin/unbound-checkconf"
    UPDATE = "/usr/local/lib/updates/modules/adblock/index.py"
    PRESETS = {
        "quad9": ["9.9.9.9", "149.112.112.112"],
        "cloudflare": ["1.1.1.1", "1.0.0.1"],
        "google": ["8.8.8.8", "8.8.4.4"],
    }
    _BLOCKLIST = re.compile(r'^(?P<indent>[ \t]*)(?P<comment>#\s*)?include:\s*["\']?/etc/unbound/blocklist\.conf["\']?(?P<tail>\s*(?:#.*)?)$', re.M)
    _TOP = re.compile(r'^[A-Za-z][A-Za-z0-9-]*:\s*(?:#.*)?$', re.M)

    def __init__(self, config: Path | None = None, *, runner: CommandRunner | None = None) -> None:
        self.config = config or Path(os.environ.get("CADUCEUS_UNBOUND_CONFIG", self.CONFIG))
        self.runner = runner or DnsManager._run

    def _run(self, argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
        try:
            result = self.runner(argv)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError("resolver-command-unavailable") from exc
        if result.returncode:
            raise DnsError("resolver-command-failed")
        return result

    def _read(self) -> str:
        try:
            return self.config.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise DnsError("resolver-config-unreadable") from exc

    @identity_locked
    def _install(self, before: str, after: str) -> None:
        mode = self.config.stat().st_mode & 0o777
        verified = False

        def check() -> None:
            if before == after:
                self._run([self.CHECKCONF, str(self.config)])
                return
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=self.config.parent, prefix=".agathodaimon-resolver-", delete=False) as handle:
                staged = Path(handle.name)
                try:
                    handle.write(after)
                    handle.flush()
                    os.fsync(handle.fileno())
                    os.chmod(staged, mode)
                    self._run([self.CHECKCONF, str(staged)])
                finally:
                    staged.unlink(missing_ok=True)

        def verify() -> None:
            nonlocal verified
            self._run([self.CHECKCONF, str(self.config)])
            verified = True

        calls = 0
        def reload() -> None:
            nonlocal calls
            calls += 1
            if not verified or calls > 1:
                self._run([self.CHECKCONF, str(self.config)])
            unit.reload("unbound", runner=self._run)

        try:
            write([{"path": self.config, "candidate": after.encode("utf-8"), "mode": mode}],
                  check=check, verify=verify, reload=reload)
        except WriteError as exc:
            if exc.restore_errors:
                raise exc.restore_errors[0]
            raise exc.cause

    @staticmethod
    def _forward_section(text: str) -> tuple[int, int]:
        matches = list(re.finditer(r'^forward-zone:\s*(?:#.*)?$', text, re.M))
        if len(matches) != 1:
            raise DnsError("resolver-forward-zone-ambiguous")
        start = matches[0].start()
        subsequent = ResolverControl._TOP.search(text, matches[0].end())
        return start, subsequent.start() if subsequent else len(text)

    @staticmethod
    def _forward_values(text: str) -> tuple[list[str], bool]:
        start, end = ResolverControl._forward_section(text)
        section = text[start:end]
        addresses = re.findall(r'^\s*forward-addr:\s+([^\s#]+)', section, re.M)
        dot = bool(re.search(r'^\s*forward-tls-upstream:\s+yes\s*(?:#.*)?$', section, re.M | re.I))
        return addresses, dot

    def status(self) -> dict[str, Any]:
        text = self._read()
        matches = list(self._BLOCKLIST.finditer(text))
        if len(matches) != 1:
            raise DnsError("resolver-blocklist-include-ambiguous")
        addresses, dot = self._forward_values(text)
        count = 0
        updated = None
        try:
            stat_result = self.BLOCKLIST.stat()
            updated = int(stat_result.st_mtime)
            with self.BLOCKLIST.open(encoding="utf-8", errors="replace") as handle:
                count = sum(1 for line in handle if line.lstrip().startswith("local-zone:"))
        except FileNotFoundError:
            pass
        try:
            active = unit.systemctl("is-active", "--quiet", "unbound", runner=self.runner).returncode == 0
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DnsError("resolver-service-status-unavailable") from exc
        return {"ok": True, "action": "status", "adblockEnabled": matches[0].group("comment") is None, "upstreams": addresses, "dnsOverTls": dot, "blocklistDomainCount": count, "blocklistLastUpdate": updated, "unboundActive": active, "mutationPerformed": False, "firstMissingSignal": "none"}

    @identity_locked
    def adblock(self, enabled: Any) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise DnsError("resolver-adblock-enabled-invalid")
        before = self._read()
        matches = list(self._BLOCKLIST.finditer(before))
        if len(matches) != 1:
            raise DnsError("resolver-blocklist-include-ambiguous")
        match = matches[0]
        line = f'{match.group("indent")}{"" if enabled else "# "}include: "/etc/unbound/blocklist.conf"{match.group("tail")}'
        after = before[:match.start()] + line + before[match.end():]
        self._install(before, after)
        return {"ok": True, "action": "adblock", "enabled": enabled, "mutationPerformed": before != after, "reload": "reloaded", "firstMissingSignal": "none"}

    @identity_locked
    def update_blocklist(self) -> dict[str, Any]:
        self._run([sys.executable, self.UPDATE])
        unit.reload("unbound", runner=self._run)
        status = self.status()
        return {"ok": True, "action": "blocklist-update", "domainCount": status["blocklistDomainCount"], "mutationPerformed": True, "reload": "reloaded", "firstMissingSignal": "none"}

    @identity_locked
    def upstream(self, metadata: Any) -> dict[str, Any]:
        if not isinstance(metadata, dict) or set(metadata) - {"preset", "custom", "dot"}:
            raise DnsError("resolver-upstream-input-invalid")
        dot = metadata.get("dot")
        if not isinstance(dot, bool):
            raise DnsError("resolver-dot-invalid")
        preset, custom = metadata.get("preset"), metadata.get("custom")
        if isinstance(preset, str) and custom is None:
            if preset not in self.PRESETS:
                raise DnsError("resolver-upstream-preset-invalid")
            addresses = self.PRESETS[preset]
        elif preset is None and isinstance(custom, list) and custom:
            addresses = custom
        else:
            raise DnsError("resolver-upstream-input-invalid")
        if len(addresses) > 8 or any(not isinstance(value, str) for value in addresses):
            raise DnsError("resolver-upstream-address-invalid")
        canonical: list[str] = []
        for value in addresses:
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError as exc:
                raise DnsError("resolver-upstream-address-invalid") from exc
            if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or parsed.is_link_local:
                raise DnsError("resolver-upstream-address-refused")
            canonical.append(str(parsed))
        before = self._read()
        start, end = self._forward_section(before)
        lines = ["forward-zone:", '    name: "."', f'    forward-tls-upstream: {"yes" if dot else "no"}']
        lines.extend(f'    forward-addr: {address}{"@853" if dot else ""}' for address in canonical)
        after = before[:start] + "\n".join(lines) + "\n" + before[end:]
        self._install(before, after)
        return {"ok": True, "action": "upstream", "upstreams": canonical, "dnsOverTls": dot, "mutationPerformed": before != after, "reload": "reloaded", "firstMissingSignal": "none"}


def resolver_control(action: str, metadata: Any = None) -> dict[str, Any]:
    try:
        resolver = ResolverControl()
        if action == "status" and metadata is None:
            return resolver.status()
        if action == "adblock" and isinstance(metadata, dict):
            return resolver.adblock(metadata.get("enabled"))
        if action == "blocklist-update" and metadata is None:
            return resolver.update_blocklist()
        if action == "upstream":
            return resolver.upstream(metadata)
        raise DnsError("resolver-action-invalid")
    except DnsError as exc:
        return {"ok": False, "action": action, "mutationPerformed": False, "firstMissingSignal": str(exc)}

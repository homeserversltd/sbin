from __future__ import annotations

import argparse
import os
import re
from pathlib import Path
from typing import Any, Sequence

from caduceus_staff.receipts import emit_actuator


class DnsError(RuntimeError):
    pass


class DnsReader:
    INCLUDE_PATH = Path("/etc/unbound/unbound.conf.d/caduceus-local-names.conf")
    BEGIN = "# BEGIN CADUCEUS OWNED DEVICE RECORDS"
    END = "# END CADUCEUS OWNED DEVICE RECORDS"

    def __init__(self, include_path: str | Path | None = None) -> None:
        self.include_path = Path(include_path or os.environ.get("CADUCEUS_UNBOUND_INCLUDE", self.INCLUDE_PATH))

    def _owned_lines(self) -> list[str]:
        try:
            text = self.include_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise DnsError(f"failed to read owned include {self.include_path}: {exc}") from exc
        if self.BEGIN not in text or self.END not in text:
            return []
        return text.split(self.BEGIN, 1)[1].split(self.END, 1)[0].splitlines()

    def read(self) -> dict[str, Any]:
        devices: dict[str, dict[str, Any]] = {}
        aliases: list[dict[str, str]] = []
        for line in self._owned_lines():
            match = re.search(r'local-data:\s+"([^\s]+)\.?\s+IN\s+(A|PTR|CNAME)\s+([^\s"]+)"', line, re.I)
            if not match:
                continue
            name, record_type, target = match.group(1).rstrip(".").lower(), match.group(2).upper(), match.group(3).rstrip(".").lower()
            if record_type == "CNAME":
                aliases.append({"name": name, "target": target})
                continue
            if record_type == "A":
                entry = devices.setdefault(name, {"name": name, "a": [], "ptr": []})
                entry["a"].append(target)
            else:
                entry = devices.setdefault(target, {"name": target, "a": [], "ptr": []})
                entry["ptr"].append(name)
        return {"include": str(self.include_path), "exists": self.include_path.is_file(), "devices": [devices[key] for key in sorted(devices)], "aliases": sorted(aliases, key=lambda item: item["name"])}

    def status(self) -> dict[str, Any]:
        return {"include": str(self.include_path), "exists": self.include_path.is_file(), "owned_records": len(self.read()["devices"]), "firstMissingSignal": "none"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-network-dns")
    parser.add_argument("command", choices=("status", "read"))
    args = parser.parse_args(argv)
    try:
        reader = DnsReader()
        result = getattr(reader, args.command)()
        return emit_actuator("network.dns." + args.command, "caduceus.staff.network.dns.v1", args.command, result)
    except DnsError as exc:
        return emit_actuator("network.dns." + args.command, "caduceus.staff.network.dns.v1", args.command, None, ok=False, first_missing_signal=str(exc))


if __name__ == "__main__":
    raise SystemExit(main())

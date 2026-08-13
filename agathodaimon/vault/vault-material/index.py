"""Private Keyman-to-cryptsetup hook for the fixed HomeConsole vault record."""
from __future__ import annotations

import json
import re
import subprocess
import sys
from typing import Any, Sequence

import agathodaimon.lib.sacred_credential.index as sacred_credential

_SCHEMA = "caduceus.vault.keyman-open.v1"
_SERVICE = "homeconsole-vault"
_CRYPTSETUP = "/usr/sbin/cryptsetup"
_DEVICE = re.compile(r"^/dev/[A-Za-z0-9._-]+$")
_MAPPER = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _receipt(ok: bool, present: bool, signal: str) -> dict[str, Any]:
    return {"schema": _SCHEMA, "ok": ok, "present": present, "firstMissingSignal": signal}


def _wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def open_from_seated_record(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != {"device", "mapper"}:
        return _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    device, mapper = payload.get("device"), payload.get("mapper")
    if (
        not isinstance(device, str)
        or not _DEVICE.fullmatch(device)
        or not isinstance(mapper, str)
        or not _MAPPER.fullmatch(mapper)
    ):
        return _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    if not sacred_credential.seated_service_record_present(_SERVICE):
        return _receipt(True, False, "none")

    material = bytearray()
    try:
        material = sacred_credential.read_seated_service_password(_SERVICE)
        result = subprocess.run(
            [_CRYPTSETUP, "open", "--batch-mode", "--key-file", "-", device, mapper],
            input=bytes(material),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
        return _receipt(
            result.returncode == 0,
            True,
            "none" if result.returncode == 0 else "agathodaimon-vault-keyman-open-refused",
        )
    except (OSError, subprocess.SubprocessError, sacred_credential.CaduceusAccessRefused):
        return _receipt(False, True, "agathodaimon-vault-keyman-open-refused")
    finally:
        _wipe(material)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        value = open_from_seated_record(json.load(sys.stdin))
    except (json.JSONDecodeError, UnicodeDecodeError):
        value = _receipt(False, True, "agathodaimon-vault-open-request-invalid")
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

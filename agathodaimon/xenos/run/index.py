"""Thin Caduceus staff-envelope caller for caduceus-xenos-run."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Sequence

from agathodaimon._envelope import EnvelopeError, attach, read_fields

LAUNCHER = Path("/usr/local/sbin/agathodaimon/caduceus-xenos-run")


def _receipt(first_missing_signal: str) -> dict[str, object]:
    return {"ok": False, "firstMissingSignal": first_missing_signal}


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    try:
        request = read_fields("id", "band")
    except EnvelopeError as exc:
        print(json.dumps(_receipt(str(exc)), separators=(",", ":")))
        return 0
    xenos_id = request.payload.get("id")
    band = request.payload.get("band")
    if not isinstance(xenos_id, str) or not xenos_id:
        result = _receipt("xenos-id-missing")
    elif not isinstance(band, str) or not band:
        result = _receipt("xenos-band-missing")
    else:
        try:
            completed = subprocess.run(
                [str(LAUNCHER), xenos_id, "band", band],
                input=request.raw_envelope,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            result = _receipt("xenos-run-launcher-unavailable")
        else:
            try:
                parsed = json.loads(completed.stdout)
            except (TypeError, json.JSONDecodeError):
                parsed = None
            if isinstance(parsed, dict):
                result = parsed
            else:
                result = _receipt("xenos-run-launcher-response-invalid")
            if completed.returncode != 0 and result.get("ok") is not False:
                result = _receipt("xenos-run-launcher-exit-nonzero")
    print(json.dumps(attach(result, request), separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

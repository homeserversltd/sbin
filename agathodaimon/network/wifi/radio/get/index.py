"""Read Wi-Fi device presence and the NetworkManager radio state."""
import json
from pathlib import Path

from agathodaimon.network.wifi import _nmcli


def main(argv=None):
    result = _nmcli._receipt("radio-get", True)
    result.update(schema="caduceus.network.wifi.radio.get.v1",
                  present=False, enabled=False, device=None)
    if Path("/usr/bin/nmcli").exists():
        try:
            devices = _nmcli._run_nmcli(("-t", "-f", "TYPE,DEVICE", "device"))
            for line in devices.splitlines():
                fields = _nmcli._nmcli_fields(line)
                if len(fields) == 2 and fields[0] == "wifi" and fields[1]:
                    result["present"] = True
                    result["device"] = fields[1]
                    break
            if result["present"]:
                state = _nmcli._run_nmcli(("radio", "wifi")).strip()
                if state not in ("enabled", "disabled"):
                    raise _nmcli.WifiRefused("wifi-radio-state-invalid")
                result["enabled"] = state == "enabled"
        except _nmcli.WifiRefused as error:
            result.update(ok=False, completed=False, firstMissingSignal=str(error))
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1

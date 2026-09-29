"""NetworkManager Wi-Fi staff actuator."""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from typing import Any, Sequence

SCHEMA = "caduceus.staff.network-wifi.v1"
COMMAND_TIMEOUT = 10
MAX_FIELD_BYTES = 128
MAX_DNS_BYTES = 256


class WifiRefused(ValueError):
    """A bounded Wi-Fi input or command refusal."""


def _receipt(action: str, ok: bool, signal: str = "none") -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "action": action,
        "completed": ok,
        "firstMissingSignal": signal,
    }


def _text(payload: dict[str, Any], key: str, maximum: int = MAX_FIELD_BYTES) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise WifiRefused(f"wifi-{key}-required")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WifiRefused(f"wifi-{key}-invalid") from exc
    if not raw or len(raw) > maximum or any(byte <= 0x1F or byte == 0x7F for byte in raw):
        raise WifiRefused(f"wifi-{key}-invalid")
    return value


def _password(payload: dict[str, Any]) -> str | None:
    if "password" not in payload:
        return None
    value = payload["password"]
    if not isinstance(value, str):
        raise WifiRefused("wifi-password-invalid")
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise WifiRefused("wifi-password-invalid") from exc
    if len(raw) > MAX_FIELD_BYTES or any(char in value for char in ("\x00", "\r", "\n")):
        raise WifiRefused("wifi-password-invalid")
    return value


def _ipv4(value: str, signal: str) -> str:
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise WifiRefused(signal) from exc


def _cidr(value: str) -> str:
    address, separator, prefix = value.partition("/")
    if not separator or not re.fullmatch(r"[0-9]+", prefix):
        raise WifiRefused("wifi-address-invalid")
    address = _ipv4(address, "wifi-address-invalid")
    try:
        prefix_value = int(prefix)
    except ValueError as exc:
        raise WifiRefused("wifi-address-invalid") from exc
    if prefix_value > 32:
        raise WifiRefused("wifi-address-invalid")
    return f"{address}/{prefix_value}"


def _static_options(payload: dict[str, Any], args: list[str]) -> None:
    if "gateway" in payload:
        gateway = payload["gateway"]
        if not isinstance(gateway, str):
            raise WifiRefused("wifi-gateway-required")
        if gateway:
            args.extend(("ipv4.gateway", _ipv4(gateway, "wifi-gateway-invalid")))
    if "dns" in payload:
        dns = payload["dns"]
        if not isinstance(dns, str):
            raise WifiRefused("wifi-dns-invalid")
        if dns:
            try:
                encoded = dns.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise WifiRefused("wifi-dns-invalid") from exc
            if len(encoded) > MAX_DNS_BYTES or any(byte <= 0x1F or byte == 0x7F for byte in encoded):
                raise WifiRefused("wifi-dns-invalid")
            if any(not entry.strip() or _is_invalid_ipv4(entry.strip()) for entry in dns.split(",")):
                raise WifiRefused("wifi-dns-invalid")
            args.extend(("ipv4.dns", dns))


def _is_invalid_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return True
    return False


def _ipv4_modify_args(uuid: str, payload: dict[str, Any]) -> list[str]:
    method = payload.get("method")
    if not isinstance(method, str) or method not in {"auto", "static"}:
        raise WifiRefused("wifi-ipv4-method-invalid")
    args = [
        "connection", "modify", "uuid", uuid, "ipv4.method",
        "manual" if method == "static" else "auto",
    ]
    if method == "static":
        try:
            address = _cidr(_text(payload, "address"))
        except WifiRefused as exc:
            raise WifiRefused("wifi-address-invalid") from exc
        args.extend(("ipv4.addresses", address))
        _static_options(payload, args)
    else:
        args.extend(("ipv4.addresses", "", "ipv4.gateway", "", "ipv4.dns", ""))
    return args


def _stop(process: subprocess.Popen[bytes]) -> None:
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.communicate()
    except (OSError, ValueError):
        pass


def _run_nmcli(args: Sequence[str], password: str | None = None) -> str:
    try:
        process = subprocess.Popen(
            ["/usr/bin/nmcli", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, ValueError) as exc:
        raise WifiRefused("wifi-nmcli-unavailable") from exc

    if process.stdin is None:
        _stop(process)
        raise WifiRefused("wifi-nmcli-stdin-unavailable")
    try:
        if password:
            process.stdin.write((password + "\n").encode("utf-8"))
            process.stdin.flush()
        process.stdin.close()
        process.stdin = None
    except (BrokenPipeError, OSError, ValueError) as exc:
        _stop(process)
        raise WifiRefused("wifi-nmcli-stdin-write-failed") from exc

    try:
        output, _ = process.communicate(timeout=COMMAND_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        _stop(process)
        raise WifiRefused("wifi-nmcli-timeout") from exc
    except (OSError, ValueError) as exc:
        _stop(process)
        raise WifiRefused("wifi-nmcli-failed") from exc
    if process.returncode != 0:
        raise WifiRefused("wifi-nmcli-failed")
    return output.decode("utf-8", errors="replace")


def _nmcli_fields(line: str) -> list[str]:
    fields: list[str] = []
    field: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            field.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(field))
            field = []
        else:
            field.append(char)
    if escaped:
        field.append("\\")
    fields.append("".join(field))
    return fields


def _active_uuid(interface: str, output: str) -> str:
    for line in output.splitlines():
        fields = _nmcli_fields(line)
        if len(fields) >= 4 and fields[3] == interface and fields[1]:
            return fields[1]
    raise WifiRefused("wifi-interface-active-connection-missing")


def _dispatch(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return _receipt("invalid", False, "wifi-body-not-object")
    kind = payload.get("kind")
    supported = {
        "radio": {"kind", "enabled"},
        "connect_device": {"kind", "interface"},
        "connect_wifi": {"kind", "ssid", "password"},
        "disconnect": {"kind", "interface"},
        "forget": {"kind", "uuid"},
        "ipv4_device": {"kind", "interface", "method", "address", "gateway", "dns"},
        "ipv4_wifi": {"kind", "uuid", "method", "address", "gateway", "dns"},
    }
    if not isinstance(kind, str) or kind not in supported:
        return _receipt("invalid", False, "wifi-action-invalid")
    if set(payload) - supported[kind]:
        return _receipt(kind, False, "wifi-payload-field-unknown")

    try:
        if kind == "radio":
            enabled = payload.get("enabled")
            if type(enabled) is not bool:
                raise WifiRefused("wifi-enabled-required")
            _run_nmcli(("radio", "wifi", "on" if enabled else "off"))
        elif kind == "connect_device":
            interface = _text(payload, "interface")
            _run_nmcli(("device", "connect", interface))
        elif kind == "connect_wifi":
            password = _password(payload)
            ssid = _text(payload, "ssid")
            args = ["device", "wifi", "connect", ssid]
            if password:
                args.insert(0, "--ask")
            _run_nmcli(args, password if password else None)
        elif kind == "disconnect":
            interface = _text(payload, "interface")
            _run_nmcli(("device", "disconnect", interface))
        elif kind == "forget":
            uuid = _text(payload, "uuid")
            _run_nmcli(("connection", "delete", "uuid", uuid))
        elif kind == "ipv4_wifi":
            uuid = _text(payload, "uuid")
            modify = _ipv4_modify_args(uuid, payload)
            _run_nmcli(modify)
            _run_nmcli(("connection", "down", "uuid", uuid))
            _run_nmcli(("connection", "up", "uuid", uuid))
        else:
            interface = _text(payload, "interface")
            modify = _ipv4_modify_args("validated", payload)
            query = _run_nmcli(("-t", "-f", "NAME,UUID,TYPE,DEVICE", "connection", "show", "--active"))
            uuid = _active_uuid(interface, query)
            modify[3] = uuid
            _run_nmcli(modify)
            _run_nmcli(("connection", "down", "uuid", uuid))
            _run_nmcli(("connection", "up", "uuid", uuid))
    except WifiRefused as exc:
        return _receipt(kind, False, str(exc))
    return _receipt(kind, True)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        value = _receipt("invalid", False, "wifi-arguments-invalid")
    else:
        try:
            raw = sys.stdin.read()
            request = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError):
            value = _receipt("invalid", False, "wifi-input-invalid")
        else:
            if not isinstance(request, dict):
                value = _receipt("invalid", False, "wifi-body-not-object")
            else:
                payload = request.get("payload") if "schema" in request else request
                value = _dispatch(payload)
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

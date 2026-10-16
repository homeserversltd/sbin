"""Stateless display policy and bounded Linux DRM mode observation."""
from __future__ import annotations

import ctypes
import fcntl
import glob
import ipaddress
import json
import math
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from fractions import Fraction
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

AUTO_RESOLUTION_CEILINGS = {
    "homeconsole": (2560, 1440),
    "tv": (1920, 1080),
    "default": (1920, 1080),
}
DEFAULT_REFRESH_RATE = 60
MAX_DEVICES = 16
MAX_CONNECTORS = 128
MAX_ENCODERS = 256
MAX_CRTCS = 128
MAX_MODES = 512
MAX_PROPERTIES = 512
MAX_TOTAL_CONNECTORS = 128
MAX_TOTAL_MODES = 8192
MAX_RETRIES = 3
MAX_CONFIG_BYTES = 1024 * 1024
MAX_PROFILE_BYTES = 64 * 1024
MAX_HTTP_BYTES = 64 * 1024
DISPLAY_SETTING_UNREAD_DEFAULTS = "display-setting-unread-defaults"
CADUCEUS_URL_DEFAULT = "http://127.0.0.1:8787"
DISPLAY_ROUTE = "/api/v1/settings/display"

DRM_MODE_TYPE_PREFERRED = 1 << 3
DRM_MODE_FLAG_INTERLACE = 1 << 4
DRM_MODE_FLAG_DBLSCAN = 1 << 5
DRM_MODE_CONNECTED = 1


class _CardResources(ctypes.Structure):
    _fields_ = [
        ("fb_id_ptr", ctypes.c_uint64), ("crtc_id_ptr", ctypes.c_uint64),
        ("connector_id_ptr", ctypes.c_uint64), ("encoder_id_ptr", ctypes.c_uint64),
        ("count_fbs", ctypes.c_uint32), ("count_crtcs", ctypes.c_uint32),
        ("count_connectors", ctypes.c_uint32), ("count_encoders", ctypes.c_uint32),
        ("min_width", ctypes.c_uint32), ("max_width", ctypes.c_uint32),
        ("min_height", ctypes.c_uint32), ("max_height", ctypes.c_uint32),
    ]


class _ModeInfo(ctypes.Structure):
    _fields_ = [
        ("clock", ctypes.c_uint32),
        ("hdisplay", ctypes.c_uint16), ("hsync_start", ctypes.c_uint16),
        ("hsync_end", ctypes.c_uint16), ("htotal", ctypes.c_uint16),
        ("hskew", ctypes.c_uint16), ("vdisplay", ctypes.c_uint16),
        ("vsync_start", ctypes.c_uint16), ("vsync_end", ctypes.c_uint16),
        ("vtotal", ctypes.c_uint16), ("vscan", ctypes.c_uint16),
        ("vrefresh", ctypes.c_uint32), ("flags", ctypes.c_uint32),
        ("type", ctypes.c_uint32), ("name", ctypes.c_char * 32),
    ]


class _Crtc(ctypes.Structure):
    _fields_ = [
        ("set_connectors_ptr", ctypes.c_uint64), ("count_connectors", ctypes.c_uint32),
        ("crtc_id", ctypes.c_uint32), ("fb_id", ctypes.c_uint32),
        ("x", ctypes.c_uint32), ("y", ctypes.c_uint32),
        ("gamma_size", ctypes.c_uint32), ("mode_valid", ctypes.c_uint32),
        ("mode", _ModeInfo),
    ]


class _Encoder(ctypes.Structure):
    _fields_ = [
        ("encoder_id", ctypes.c_uint32), ("encoder_type", ctypes.c_uint32),
        ("crtc_id", ctypes.c_uint32), ("possible_crtcs", ctypes.c_uint32),
        ("possible_clones", ctypes.c_uint32),
    ]


class _Connector(ctypes.Structure):
    _fields_ = [
        ("encoders_ptr", ctypes.c_uint64), ("modes_ptr", ctypes.c_uint64),
        ("props_ptr", ctypes.c_uint64), ("prop_values_ptr", ctypes.c_uint64),
        ("count_modes", ctypes.c_uint32), ("count_props", ctypes.c_uint32),
        ("count_encoders", ctypes.c_uint32), ("encoder_id", ctypes.c_uint32),
        ("connector_id", ctypes.c_uint32), ("connector_type", ctypes.c_uint32),
        ("connector_type_id", ctypes.c_uint32), ("connection", ctypes.c_uint32),
        ("mm_width", ctypes.c_uint32), ("mm_height", ctypes.c_uint32),
        ("subpixel", ctypes.c_uint32), ("pad", ctypes.c_uint32),
    ]


# Linux _IOC encoding; ioctl numbers derive from the local UAPI structure sizes.
def _iowr(number: int, size: int) -> int:
    nr_bits, type_bits, size_bits = 8, 8, 14
    nr_shift = 0
    type_shift = nr_shift + nr_bits
    size_shift = type_shift + type_bits
    dir_shift = size_shift + size_bits
    ioc_read, ioc_write = 2, 1
    return ((ioc_read | ioc_write) << dir_shift) | (ord("d") << type_shift) | (number << nr_shift) | (size << size_shift)


_IOCTL_GETRESOURCES = _iowr(0xA0, ctypes.sizeof(_CardResources))
_IOCTL_GETCRTC = _iowr(0xA1, ctypes.sizeof(_Crtc))
_IOCTL_GETENCODER = _iowr(0xA6, ctypes.sizeof(_Encoder))
_IOCTL_GETCONNECTOR = _iowr(0xA7, ctypes.sizeof(_Connector))


class _EnumerationChanged(Exception):
    pass


def _ioctl_struct(fd: int, code: int, value: ctypes.Structure) -> ctypes.Structure:
    payload = bytearray(ctypes.string_at(ctypes.addressof(value), ctypes.sizeof(value)))
    fcntl.ioctl(fd, code, payload, True)
    return type(value).from_buffer_copy(payload)


def _array_pointer(array: Any) -> int:
    return ctypes.addressof(array) if array is not None else 0


def _checked_count(value: int, maximum: int, label: str) -> int:
    if value < 0 or value > maximum:
        raise _EnumerationChanged(f"{label}-count-out-of-bounds")
    return int(value)


def _resource_counts(value: _CardResources) -> tuple[int, int, int, int]:
    return (
        _checked_count(value.count_crtcs, MAX_CRTCS, "crtc"),
        _checked_count(value.count_connectors, MAX_CONNECTORS, "connector"),
        _checked_count(value.count_encoders, MAX_ENCODERS, "encoder"),
        _checked_count(value.count_fbs, 4096, "framebuffer"),
    )


def _get_resources(fd: int) -> tuple[list[int], list[int], list[int]]:
    first = cast(_CardResources, _ioctl_struct(fd, _IOCTL_GETRESOURCES, _CardResources()))
    crtc_count, connector_count, encoder_count, fb_count = _resource_counts(first)
    crtcs = (ctypes.c_uint32 * crtc_count)() if crtc_count else None
    connectors = (ctypes.c_uint32 * connector_count)() if connector_count else None
    encoders = (ctypes.c_uint32 * encoder_count)() if encoder_count else None
    fbs = (ctypes.c_uint32 * fb_count)() if fb_count else None
    request = _CardResources(
        _array_pointer(fbs), _array_pointer(crtcs), _array_pointer(connectors),
        _array_pointer(encoders), fb_count, crtc_count, connector_count,
        encoder_count, 0, 0, 0, 0,
    )
    filled = cast(_CardResources, _ioctl_struct(fd, _IOCTL_GETRESOURCES, request))
    counts = _resource_counts(filled)
    if counts != (crtc_count, connector_count, encoder_count, fb_count):
        raise _EnumerationChanged("resources-count-changed")
    return (
        [int(x) for x in connectors] if connectors is not None else [],
        [int(x) for x in encoders] if encoders is not None else [],
        [int(x) for x in crtcs] if crtcs is not None else [],
    )


def _mode_key(mode: _ModeInfo) -> tuple[Any, ...]:
    return (
        int(mode.clock), int(mode.hdisplay), int(mode.hsync_start), int(mode.hsync_end),
        int(mode.htotal), int(mode.hskew), int(mode.vdisplay), int(mode.vsync_start),
        int(mode.vsync_end), int(mode.vtotal), int(mode.vscan), int(mode.flags),
    )


def _mode_fraction(mode: _ModeInfo) -> Fraction | None:
    if not mode.clock or not mode.htotal or not mode.vtotal:
        return None
    numerator = int(mode.clock) * 1000
    denominator = int(mode.htotal) * int(mode.vtotal)
    if mode.flags & DRM_MODE_FLAG_INTERLACE:
        numerator *= 2
    if mode.flags & DRM_MODE_FLAG_DBLSCAN:
        denominator *= 2
    if mode.vscan > 1:
        denominator *= int(mode.vscan)
    return Fraction(numerator, denominator)


_CONNECTOR_TYPES = {
    1: "VGA", 2: "DVI-I", 3: "DVI-D", 4: "DVI-A", 5: "Composite",
    6: "SVIDEO", 7: "LVDS", 8: "Component", 9: "DIN", 10: "DP",
    11: "HDMI-A", 12: "HDMI-B", 13: "TV", 14: "eDP", 15: "Virtual",
    16: "DSI", 17: "DPI", 18: "Writeback", 19: "SPI", 20: "USB",
}


def _connector_name(connector: _Connector) -> str:
    prefix = _CONNECTOR_TYPES.get(int(connector.connector_type), f"TYPE-{int(connector.connector_type)}")
    return f"{prefix}-{int(connector.connector_type_id)}"


def _mode_record(mode: _ModeInfo, *, device: str, connector_id: int, connector_name: str,
                 current: bool = False) -> dict[str, Any]:
    rate = _mode_fraction(mode)
    try:
        name = bytes(mode.name).split(b"\0", 1)[0].decode("ascii", "replace")
    except (AttributeError, UnicodeDecodeError):
        name = ""
    return {
        "device": device,
        "connector_id": connector_id,
        "connector_name": connector_name,
        "width": int(mode.hdisplay),
        "height": int(mode.vdisplay),
        "name": name,
        "refresh_hz": float(rate) if rate is not None else None,
        "refresh_num": rate.numerator if rate is not None else None,
        "refresh_den": rate.denominator if rate is not None else None,
        "vrefresh": int(mode.vrefresh),
        "interlaced": bool(mode.flags & DRM_MODE_FLAG_INTERLACE),
        "preferred": bool(mode.type & DRM_MODE_TYPE_PREFERRED),
        "current": bool(current),
        "source": "kms",
    }


def _connector_query(fd: int, connector_id: int) -> tuple[_Connector, list[_ModeInfo], list[int], list[int]]:
    scratch_mode = _ModeInfo()
    first = _Connector()
    first.connector_id = connector_id
    first.count_modes = 1
    first.modes_ptr = ctypes.addressof(scratch_mode)
    counted = _ioctl_struct(fd, _IOCTL_GETCONNECTOR, first)
    if counted.connector_id != connector_id:
        raise _EnumerationChanged("connector-id-changed")
    mode_count = _checked_count(counted.count_modes, MAX_MODES, "mode")
    prop_count = _checked_count(counted.count_props, MAX_PROPERTIES, "property")
    encoder_count = _checked_count(counted.count_encoders, MAX_ENCODERS, "connector-encoder")
    mode_capacity = max(1, mode_count)
    modes = (_ModeInfo * mode_capacity)()
    props = (ctypes.c_uint32 * prop_count)() if prop_count else None
    prop_values = (ctypes.c_uint64 * prop_count)() if prop_count else None
    encoders = (ctypes.c_uint32 * encoder_count)() if encoder_count else None
    request = _Connector()
    request.connector_id = connector_id
    request.count_modes = mode_capacity
    request.count_props = prop_count
    request.count_encoders = encoder_count
    request.modes_ptr = _array_pointer(modes)
    request.props_ptr = _array_pointer(props)
    request.prop_values_ptr = _array_pointer(prop_values)
    request.encoders_ptr = _array_pointer(encoders)
    filled = cast(_Connector, _ioctl_struct(fd, _IOCTL_GETCONNECTOR, request))
    counts = (int(filled.count_modes), int(filled.count_props), int(filled.count_encoders))
    if filled.connector_id != connector_id or counts != (mode_count, prop_count, encoder_count):
        raise _EnumerationChanged("connector-array-count-or-id-changed")
    return (
        filled,
        [modes[i] for i in range(mode_count)],
        [int(props[i]) for i in range(prop_count)] if props is not None else [],
        [int(encoders[i]) for i in range(encoder_count)] if encoders is not None else [],
    )


def _current_mode(fd: int, connector: _Connector, encoders: Sequence[int], crtcs: Sequence[int]) -> _ModeInfo | None:
    encoder_id = int(connector.encoder_id)
    if not encoder_id:
        return None
    if encoder_id not in encoders:
        raise _EnumerationChanged("stale-connector-encoder-id")
    encoder = _Encoder()
    encoder.encoder_id = encoder_id
    encoder = _ioctl_struct(fd, _IOCTL_GETENCODER, encoder)
    if int(encoder.encoder_id) != encoder_id:
        raise _EnumerationChanged("stale-encoder-id")
    crtc_id = int(encoder.crtc_id)
    if not crtc_id:
        return None
    if crtc_id not in crtcs:
        raise _EnumerationChanged("stale-encoder-crtc-id")
    crtc = _Crtc()
    crtc.crtc_id = crtc_id
    crtc = _ioctl_struct(fd, _IOCTL_GETCRTC, crtc)
    if int(crtc.crtc_id) != crtc_id:
        raise _EnumerationChanged("stale-crtc-id")
    return crtc.mode if crtc.mode_valid else None


def _scan_card(device: str) -> list[dict[str, Any]]:
    fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
    try:
        connector_ids, encoder_ids, crtc_ids = _get_resources(fd)
        result: list[dict[str, Any]] = []
        total_modes = 0
        for connector_id in connector_ids:
            detail, mode_infos, _properties, encoder_list = _connector_query(fd, connector_id)
            total_modes += len(mode_infos)
            if total_modes > MAX_TOTAL_MODES:
                raise _EnumerationChanged("device-mode-total-out-of-bounds")
            # Repeat the bounded query so same-count hotplug/content changes are not partial success.
            check, check_modes, check_props, check_encoders = _connector_query(fd, connector_id)
            if (
                int(detail.connection) != int(check.connection)
                or int(detail.encoder_id) != int(check.encoder_id)
                or [ _mode_key(m) for m in mode_infos ] != [ _mode_key(m) for m in check_modes ]
                or _properties != check_props
                or encoder_list != check_encoders
            ):
                raise _EnumerationChanged("connector-content-changed")
            connector_name = _connector_name(detail)
            current_info = _current_mode(fd, detail, encoder_ids, crtc_ids)
            current_key = _mode_key(current_info) if current_info is not None else None
            modes = [
                _mode_record(info, device=device, connector_id=connector_id,
                             connector_name=connector_name, current=_mode_key(info) == current_key)
                for info in mode_infos
            ]
            result.append({
                "device": device,
                "connector_id": connector_id,
                "connector_name": connector_name,
                "connected": int(detail.connection) == DRM_MODE_CONNECTED,
                "connection": int(detail.connection),
                "encoder_id": int(detail.encoder_id),
                "modes": modes,
                "current_mode": _mode_record(current_info, device=device,
                    connector_id=connector_id, connector_name=connector_name, current=True)
                    if current_info is not None else None,
                "source": "kms",
            })
        # A second resources read catches connector/encoder/CRTC hotplug with stable per-array counts.
        final_connectors, final_encoders, final_crtcs = _get_resources(fd)
        if final_connectors != connector_ids or final_encoders != encoder_ids or final_crtcs != crtc_ids:
            raise _EnumerationChanged("resource-identifiers-changed")
        return [record for record in result if record["connected"]]
    finally:
        os.close(fd)


def _card_devices() -> list[str]:
    devices = [
        path for path in glob.glob("/dev/dri/card*")
        if re.fullmatch(r"card[0-9]+", os.path.basename(path))
    ]
    devices.sort(key=lambda path: int(os.path.basename(path)[4:]))
    return devices[:MAX_DEVICES + 1]


def connected_connectors() -> dict[str, Any]:
    """Read a complete, bounded KMS snapshot; never return partial connector arrays."""
    devices = _card_devices()
    if len(devices) > MAX_DEVICES:
        return {"ok": False, "status": "drm-unavailable", "connectors": [],
                "errors": ["drm-device-count-out-of-bounds"], "device_count": len(devices)}
    if not devices:
        return {"ok": False, "status": "drm-unavailable", "connectors": [],
                "errors": ["no-primary-drm-card-nodes"], "device_count": 0}
    combined: list[dict[str, Any]] = []
    errors: list[str] = []
    for device in devices:
        last_error = "drm-enumeration-failed"
        for _attempt in range(MAX_RETRIES):
            try:
                card_connectors = _scan_card(device)
                combined_modes = sum(len(item["modes"]) for item in combined)
                card_modes = sum(len(item["modes"]) for item in card_connectors)
                if (len(combined) + len(card_connectors) > MAX_TOTAL_CONNECTORS
                        or combined_modes + card_modes > MAX_TOTAL_MODES):
                    raise _EnumerationChanged("global-display-array-limit")
                combined.extend(card_connectors)
                last_error = ""
                break
            except (OSError, _EnumerationChanged, ValueError, OverflowError) as exc:
                last_error = f"{type(exc).__name__}:{str(exc)[:120]}"
        if last_error:
            errors.append(f"{device}:{last_error}")
    if errors:
        return {"ok": False, "status": "drm-unavailable", "connectors": [],
                "errors": errors[:MAX_DEVICES], "device_count": len(devices)}
    combined.sort(key=lambda connector: (
        int(os.path.basename(connector["device"])[4:]), int(connector["connector_id"]),
        str(connector["connector_name"]),
    ))
    return {
        "ok": True,
        "status": "connected" if combined else "no-connected-screen",
        "connectors": combined,
        "errors": [],
        "device_count": len(devices),
    }


def _rate_fraction(mode: Mapping[str, Any]) -> Fraction | None:
    numerator, denominator = mode.get("refresh_num"), mode.get("refresh_den")
    if (isinstance(numerator, int) and not isinstance(numerator, bool)
            and isinstance(denominator, int) and not isinstance(denominator, bool)
            and numerator > 0 and denominator > 0):
        return Fraction(numerator, denominator)
    millihz = mode.get("refresh_millihz")
    if isinstance(millihz, int) and not isinstance(millihz, bool) and millihz > 0:
        return Fraction(millihz, 1000)
    value = mode.get("refresh_hz")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            numeric = float(value)
            if math.isfinite(numeric) and value > 0:
                return Fraction(str(value))
        except (OverflowError, ValueError, ZeroDivisionError):
            return None
    value = mode.get("vrefresh")
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return Fraction(value, 1)
    return None


def _selection_rate_fraction(mode: Mapping[str, Any]) -> Fraction | None:
    """Return the rate used to match the backend request, not the observed timing."""
    vrefresh = mode.get("vrefresh")
    if isinstance(vrefresh, int) and not isinstance(vrefresh, bool) and vrefresh > 0:
        return Fraction(vrefresh, 1)
    return _rate_fraction(mode)


def _valid_resolution(value: Any) -> str:
    if value == "auto":
        return "auto"
    if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]*x[1-9][0-9]*", value) is None:
        raise ValueError("resolution must be auto or positive WxH")
    width, height = (int(part) for part in value.split("x", 1))
    if width > 65535 or height > 65535:
        raise ValueError("resolution dimensions out of range")
    return value


def _valid_refresh(value: Any) -> int | float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("refresh_rate must be a positive finite number")
    try:
        finite = math.isfinite(float(value))
    except (OverflowError, ValueError):
        finite = False
    if not finite or value <= 0:
        raise ValueError("refresh_rate must be a positive finite number")
    return value


def validate_settings(values: Mapping[str, Any]) -> dict[str, Any]:
    """Validate only display resolution and refresh_rate, with missing defaults."""
    return {
        "resolution": _valid_resolution(values.get("resolution", "auto")),
        "refresh_rate": _valid_refresh(values.get("refresh_rate", DEFAULT_REFRESH_RATE)),
    }


def _loopback_url() -> str:
    raw = os.environ.get("CADUCEUS_URL", CADUCEUS_URL_DEFAULT).rstrip("/")
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Caduceus URL must be loopback HTTP(S) without credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Caduceus URL must not contain a query or fragment")
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise ValueError("Caduceus URL host must be a loopback address") from exc
    if not address.is_loopback:
        raise ValueError("Caduceus URL host must be a loopback address")
    return raw


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def _unread_defaults(reason: str) -> dict[str, Any]:
    print(DISPLAY_SETTING_UNREAD_DEFAULTS, file=sys.stderr)
    return {
        "resolution": "auto", "refresh_rate": DEFAULT_REFRESH_RATE,
        "source": "defaults", "fallback": reason,
        "defaulted": ["resolution", "refresh_rate"],
    }


def _read_config_settings() -> dict[str, Any]:
    from agathodaimon._envelope import appliance_runtime_path

    try:
        path = appliance_runtime_path("config")
        with path.open("rb") as stream:
            raw = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw) > MAX_CONFIG_BYTES:
            raise ValueError("config-size-limit")
        config = json.loads(raw.decode("utf-8"))
        if not isinstance(config, dict):
            raise ValueError("config-object-required")
        display = config.get("display", {})
        if not isinstance(display, dict):
            raise ValueError("display-object-required")
        values = {key: display[key] for key in ("resolution", "refresh_rate") if key in display}
        normalized = validate_settings(values)
        missing = [key for key in ("resolution", "refresh_rate") if key not in values]
        return {**normalized, "source": "appliance-config", "fallback": None, "defaulted": missing}
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError) as exc:
        return _unread_defaults(f"config-unreadable-or-malformed:{type(exc).__name__}")


def _read_caduceus_settings() -> dict[str, Any]:
    try:
        base = _loopback_url()
        request_envelope = {
            "schema": "caduceus.staff.v1",
            "intent_id": f"agathodaimon-display-read-{uuid.uuid4()}",
            "transition": DISPLAY_ROUTE,
            "target": "dark",
        }
        request = urllib.request.Request(
            base + DISPLAY_ROUTE,
            data=json.dumps(request_envelope, separators=(",", ":")).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="GET",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        with opener.open(request, timeout=3) as response:
            raw = response.read(MAX_HTTP_BYTES + 1)
        if len(raw) > MAX_HTTP_BYTES:
            raise ValueError("caduceus-response-size-limit")
        receipt = json.loads(raw.decode("utf-8"))
        if not isinstance(receipt, dict) or receipt.get("ok") is not True:
            raise ValueError("caduceus-read-refused")
        values = receipt.get("values")
        if not isinstance(values, dict):
            raise ValueError("caduceus-values-object-required")
        selected = {key: values[key] for key in ("resolution", "refresh_rate") if key in values}
        normalized = validate_settings(selected)
        missing = [key for key in ("resolution", "refresh_rate") if key not in selected]
        return {**normalized, "source": "caduceus-loopback", "fallback": None, "defaulted": missing}
    except (OSError, urllib.error.URLError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError) as exc:
        return _unread_defaults(f"caduceus-unreadable-or-refused:{type(exc).__name__}")


def load_settings() -> dict[str, Any]:
    """Load only the display mode pair from root config or the owner-facing staff door."""
    return _read_config_settings() if os.geteuid() == 0 else _read_caduceus_settings()


def _connector_rank(connector: Mapping[str, Any]) -> tuple[Any, ...]:
    modes_value = connector.get("modes")
    modes = modes_value if isinstance(modes_value, list) else []
    current = connector.get("current_mode") is not None or any(
        isinstance(mode, dict) and mode.get("current") is True for mode in modes
    )
    device = str(connector.get("device") or "")
    connector_id = connector.get("connector_id")
    return (0 if current else 1, device, connector_id if isinstance(connector_id, int) else 2**31,
            str(connector.get("connector_name") or connector.get("name") or ""))


def _is_eligible(mode: Mapping[str, Any]) -> bool:
    # KMS marks interlace explicitly; Sway-only observations preserve unknown as unknown.
    return mode.get("interlaced") is not True


def _mode_sort_key(connector: Mapping[str, Any], mode: Mapping[str, Any]) -> tuple[Any, ...]:
    width, height = int(mode.get("width", 0)), int(mode.get("height", 0))
    return (-width * height, -width, -height, _connector_rank(connector),
            0 if mode.get("current") is True else 1, str(mode.get("name") or ""))


def _refresh_choice(modes: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]], requested: Fraction
                   ) -> tuple[Mapping[str, Any], Mapping[str, Any], str] | None:
    rated = [(connector, mode, _selection_rate_fraction(mode)) for connector, mode in modes]
    rated = [(connector, mode, rate) for connector, mode, rate in rated if rate is not None]
    if not rated:
        return None
    exact = [entry for entry in rated if entry[2] == requested]
    if exact:
        pool, reason = exact, "refresh-exact"
    else:
        below = [entry for entry in rated if entry[2] <= requested]
        if below:
            best = max(entry[2] for entry in below)
            pool, reason = [entry for entry in below if entry[2] == best], "refresh-not-above"
        else:
            best = min(entry[2] for entry in rated)
            pool, reason = [entry for entry in rated if entry[2] == best], "refresh-closest-above"
    pool.sort(key=lambda entry: (
        _connector_rank(entry[0]), 0 if entry[1].get("current") is True else 1,
        0 if entry[1].get("preferred") is True else 1, str(entry[1].get("name") or ""),
        _rate_fraction(entry[1]) or Fraction(0, 1),
    ))
    connector, mode, _rate = pool[0]
    return connector, mode, reason


def _read_profile_name() -> str | None:
    try:
        from agathodaimon._envelope import appliance_runtime_path

        path = appliance_runtime_path("profile")
        with path.open("rb") as stream:
            raw = stream.read(MAX_PROFILE_BYTES + 1)
        if len(raw) > MAX_PROFILE_BYTES:
            return None
        identity = json.loads(raw.decode("utf-8"))
        if not isinstance(identity, dict):
            return None
        profile = identity.get("profile")
        return profile if isinstance(profile, str) else None
    except (ImportError, OSError, UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        return None


def _automatic_resolution_ceiling(profile: str | None) -> tuple[str | None, str, tuple[int, int]]:
    identity = _read_profile_name() if profile is None else profile
    selected = identity if isinstance(identity, str) and identity in AUTO_RESOLUTION_CEILINGS else "default"
    return identity, selected, AUTO_RESOLUTION_CEILINGS[selected]


def _automatic_resolution(connectors: Sequence[Mapping[str, Any]], ceiling: tuple[int, int]) -> tuple[
        tuple[int, int] | None, str, list[tuple[Mapping[str, Any], Mapping[str, Any]]]]:
    max_width, max_height = ceiling
    eligible: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for connector in connectors:
        modes = connector.get("modes")
        if not isinstance(modes, list):
            continue
        for mode in modes:
            if not isinstance(mode, dict) or not _is_eligible(mode):
                continue
            width, height = mode.get("width"), mode.get("height")
            if (isinstance(width, int) and not isinstance(width, bool)
                    and isinstance(height, int) and not isinstance(height, bool)
                    and 0 < width <= max_width and 0 < height <= max_height):
                eligible.append((connector, mode))
    if not eligible:
        return None, "no-progressive-mode-within-auto-cap", []
    known_progressive = [entry for entry in eligible if entry[1].get("interlaced") is False]
    candidates = known_progressive or [entry for entry in eligible if entry[1].get("interlaced") is None]
    if not candidates:
        return None, "no-progressive-mode-within-auto-cap", []
    preferred = [entry for entry in candidates
                 if entry[1].get("interlaced") is False and entry[1].get("preferred") is True]
    pool = preferred if preferred else candidates
    pool.sort(key=lambda entry: _mode_sort_key(*entry))
    chosen = pool[0][1]
    if preferred:
        reason = "preferred-progressive-resolution"
    elif chosen.get("interlaced") is None:
        reason = "largest-interlace-unclassified-resolution-within-auto-cap"
    else:
        reason = "largest-progressive-resolution-within-auto-cap"
    return (int(chosen["width"]), int(chosen["height"])), reason, eligible


def resolve_mode(connectors: Sequence[Mapping[str, Any]], settings: Mapping[str, Any], *,
                 profile: str | None = None) -> dict[str, Any]:
    """Resolve KMS or normalized Sway modes under the selected profile ceiling."""
    normalized = validate_settings(settings)
    profile_identity, selected_profile, auto_ceiling = _automatic_resolution_ceiling(profile)
    connected = [
        connector for connector in connectors
        if isinstance(connector, Mapping) and connector.get("connected", True) is True
    ]
    connected.sort(key=_connector_rank)
    common = {
        "requested": {"resolution": normalized["resolution"], "refresh_rate": normalized["refresh_rate"]},
        "multi_output_mapping_uncertain": len(connected) > 1,
        "automatic_resolution": {
            "profile": profile_identity,
            "ceiling_profile": selected_profile,
            "ceiling": {"width": auto_ceiling[0], "height": auto_ceiling[1]},
        },
    }
    if not connected:
        return {"ok": False, "connector": None, "mode": None, "reason": "no-connected-screen",
                "fallback": False, **common}
    requested = Fraction(str(normalized["refresh_rate"]))
    requested_resolution = normalized["resolution"]
    fallback = False
    resolution_reason = ""
    if requested_resolution == "auto":
        dimensions, resolution_reason, _eligible = _automatic_resolution(connected, auto_ceiling)
    else:
        width, height = (int(part) for part in requested_resolution.split("x", 1))
        advertised: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
        for connector in connected:
            connector_modes = connector.get("modes")
            if not isinstance(connector_modes, list):
                continue
            advertised.extend(
                (connector, mode)
                for mode in connector_modes
                if isinstance(mode, dict) and mode.get("width") == width and mode.get("height") == height
            )
        progressive = [entry for entry in advertised if _is_eligible(entry[1])]
        if not advertised:
            dimensions, auto_reason, _eligible = _automatic_resolution(connected, auto_ceiling)
            fallback = True
            resolution_reason = f"requested-resolution-not-advertised;auto:{auto_reason}"
        elif not progressive:
            return {"ok": False, "connector": None, "mode": None,
                    "reason": "requested-resolution-has-no-progressive-advertisement",
                    "fallback": False, **common}
        else:
            dimensions = (width, height)
            resolution_reason = "requested-resolution-advertised"
    if dimensions is None:
        return {"ok": False, "connector": None, "mode": None,
                "reason": resolution_reason or "no-progressive-mode-within-auto-cap",
                "fallback": fallback, **common}
    width, height = dimensions
    usable_candidates: list[tuple[Mapping[str, Any], Mapping[str, Any]]] = []
    for candidate_connector in connected:
        connector_modes = candidate_connector.get("modes")
        if not isinstance(connector_modes, list):
            continue
        usable_candidates.extend(
            (candidate_connector, candidate_mode)
            for candidate_mode in connector_modes
            if isinstance(candidate_mode, dict)
            and candidate_mode.get("width") == width and candidate_mode.get("height") == height
            and _is_eligible(candidate_mode) and _selection_rate_fraction(candidate_mode) is not None
        )
    if usable_candidates:
        target_connector = min((entry[0] for entry in usable_candidates), key=_connector_rank)
        candidates = [entry for entry in usable_candidates if entry[0] is target_connector]
    else:
        candidates = []
    choice = _refresh_choice(candidates, requested)
    if choice is None:
        return {"ok": False, "connector": None, "mode": None,
                "reason": f"{resolution_reason};no-usable-refresh-at-resolution",
                "fallback": fallback, **common}
    connector, mode, refresh_reason = choice
    actual_rate = _rate_fraction(mode)
    selection_rate = _selection_rate_fraction(mode)
    uncertainty = mode.get("interlaced") is None
    if uncertainty:
        refresh_reason += ";interlace-unknown-from-source"
    if len(connected) > 1:
        refresh_reason += ";multi-output-mapping-uncertain"
    return {
        "ok": True,
        "connector": dict(connector),
        "mode": dict(mode),
        "reason": f"{resolution_reason};{refresh_reason}",
        "fallback": fallback or refresh_reason.split(";", 1)[0] != "refresh-exact",
        "refresh_hz": float(actual_rate) if actual_rate is not None else None,
        "selection_refresh_hz": float(selection_rate) if selection_rate is not None else None,
        "interlace_unknown": uncertainty,
        **common,
    }


def normalize_sway_outputs(outputs: Any) -> list[dict[str, Any]]:
    """Normalize Sway IPC's live/current and advertised modes without inventing preferred flags."""
    if not isinstance(outputs, list):
        return []
    connectors: list[dict[str, Any]] = []
    for output in outputs[:MAX_CONNECTORS]:
        if not isinstance(output, dict) or output.get("active") is not True:
            continue
        name = output.get("name")
        if not isinstance(name, str) or not name or len(name) > 256:
            continue
        current = output.get("current_mode")
        current_key = None
        if isinstance(current, dict):
            refresh = current.get("refresh")
            if (isinstance(current.get("width"), int) and not isinstance(current.get("width"), bool)
                    and isinstance(current.get("height"), int) and not isinstance(current.get("height"), bool)
                    and isinstance(refresh, int) and not isinstance(refresh, bool) and refresh > 0):
                current_key = (current["width"], current["height"], refresh)
        modes: list[dict[str, Any]] = []
        source_modes = output.get("modes")
        if isinstance(source_modes, list):
            for raw_mode in source_modes[:MAX_MODES]:
                if not isinstance(raw_mode, dict):
                    continue
                width, height, refresh = raw_mode.get("width"), raw_mode.get("height"), raw_mode.get("refresh")
                if (not isinstance(width, int) or isinstance(width, bool) or width <= 0
                        or not isinstance(height, int) or isinstance(height, bool) or height <= 0
                        or not isinstance(refresh, int) or isinstance(refresh, bool) or refresh <= 0):
                    continue
                rate = Fraction(refresh, 1000)
                modes.append({
                    "device": None, "connector_id": None, "connector_name": name,
                    "width": width, "height": height, "name": raw_mode.get("name", ""),
                    "refresh_hz": float(rate), "refresh_num": rate.numerator,
                    "refresh_den": rate.denominator, "refresh_millihz": refresh,
                    "vrefresh": None, "interlaced": None, "preferred": None,
                    "current": current_key == (width, height, refresh), "source": "sway",
                })
        connectors.append({
            "device": None, "connector_id": None, "connector_name": name, "name": name,
            "connected": True, "connection": "active", "modes": modes,
            "current_mode": current if isinstance(current, dict) else None,
            "source": "sway", "preferred_source": "not-exposed-by-sway-ipc",
        })
    connectors.sort(key=_connector_rank)
    return connectors

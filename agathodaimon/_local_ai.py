"""Read-only model shelf/card and the two fixed model-slot process actions.

Processes are stateless; Command–Query Separation leaves reads trace-free.
Receipts go home. No backing store, outbox, queue or retained model data exists.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import fcntl
import json
import os
from pathlib import Path
import re
import selectors
import struct
import subprocess
import sys
import time

from agathodaimon._envelope import EnvelopeError, Request, appliance_runtime_path, attach, read

GIB = 1024 ** 3
ROLES = {"brain": "text-to-text", "embed": "embedding", "ear": "speech-to-text"}
DEFAULT_CTX = {"brain": 24576, "embed": 4096, "ear": 4608}
DEFAULT_PORT = {"brain": 8100, "embed": 8101, "ear": 8090}
SERVER = "/usr/local/bin/llama-server"  # HomeSI phase-4/upstream-binary-pin, b11819.
FORMULA = "blocks(model) = ceil((file_bytes + kv_bytes(ctx)) / GiB); GiB = 1073741824; file_bytes includes paired mmproj; kv_bytes(ctx) = ctx * kv_bytes_per_ctx"
KV_ESTIMATE = "f16 K+V: 2 * layers * kv_heads * (key_length + value_length) bytes per ctx token; missing dimensions estimated as 32 layers, 8 KV heads, 128 key/value dimensions"
MAX_HEADER = 128 * 1024 * 1024
_SCALARS = {0: "B", 1: "b", 2: "H", 3: "h", 4: "I", 5: "i", 6: "f", 7: "?", 10: "Q", 11: "q", 12: "d"}
_METADATA = re.compile(r"^(general\.(architecture|type|kind|name|basename)|[^.]+\.(pooling_type|block_count|embedding_length|attention\.(head_count|head_count_kv|key_length|value_length))|clip\.has_audio_encoder)$")


class LocalAIError(ValueError):
    pass


def _config() -> dict:
    try:
        with appliance_runtime_path("config").open("rb") as source:
            raw = source.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise LocalAIError("local-ai-config-size-limit")
        config = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LocalAIError("local-ai-config-unreadable") from error
    local = config.get("local_ai") if isinstance(config, dict) else None
    if not isinstance(local, dict):
        raise LocalAIError("local-ai-config-unavailable")
    if "schema" not in local:
        raise LocalAIError("local-ai-missing-schema")
    if local["schema"] != "appliance.local_ai.v1":
        raise LocalAIError("local-ai-foreign-schema")
    shelf = local.get("shelf")
    if not isinstance(shelf, str) or not Path(shelf).is_absolute():
        raise LocalAIError("local-ai-shelf-invalid")
    slots = local.get("slots")
    if not isinstance(slots, dict):
        raise LocalAIError("local-ai-slots-invalid")
    return local


def _slot(local: dict, name: str) -> dict:
    if name not in ROLES:
        raise LocalAIError("local-ai-slot-unknown")
    value = local["slots"].get(name, {})
    if not isinstance(value, dict) or value.get("role", ROLES[name]) != ROLES[name]:
        raise LocalAIError("local-ai-slot-role-invalid")
    value = dict(value)
    value.setdefault("role", ROLES[name])
    value.setdefault("model", None)
    value.setdefault("mmproj", None)
    value.setdefault("ctx", DEFAULT_CTX[name])
    value.setdefault("port", DEFAULT_PORT[name])
    value.setdefault("lan", False)
    if type(value["ctx"]) is not int or not 0 < value["ctx"] <= 16777216:
        raise LocalAIError("local-ai-slot-ctx-invalid")
    if type(value["port"]) is not int or not 0 < value["port"] < 65536:
        raise LocalAIError("local-ai-slot-port-invalid")
    if type(value["lan"]) is not bool:
        raise LocalAIError("local-ai-slot-lan-invalid")
    for field in ("model", "mmproj"):
        filename = value[field]
        if filename is not None and (not isinstance(filename, str) or not filename
                or filename in {".", ".."} or "/" in filename or "\\" in filename
                or any(ord(char) < 32 for char in filename) or not filename.lower().endswith(".gguf")):
            raise LocalAIError("local-ai-slot-file-invalid")
    return value


def _model_path(shelf: str, filename: str) -> Path:
    root = Path(shelf).resolve(strict=True)
    path = (root / filename).resolve(strict=True)
    if path.parent != root or not path.is_file():
        raise LocalAIError("local-ai-model-outside-shelf")
    return path


def gguf_metadata(path: Path) -> dict:
    """Read selected scalar metadata only; seek past arrays and never read tensors."""
    with path.open("rb") as source:
        size = os.fstat(source.fileno()).st_size

        def take(count: int) -> bytes:
            if count < 0 or source.tell() + count > min(size, MAX_HEADER):
                raise LocalAIError("local-ai-gguf-header-bounds")
            data = source.read(count)
            if len(data) != count:
                raise LocalAIError("local-ai-gguf-header-truncated")
            return data

        def number(fmt: str):
            return struct.unpack("<" + fmt, take(struct.calcsize(fmt)))[0]

        def skip(count: int) -> None:
            if count < 0 or source.tell() + count > min(size, MAX_HEADER):
                raise LocalAIError("local-ai-gguf-header-bounds")
            source.seek(count, os.SEEK_CUR)

        def string(keep: bool):
            length = number("Q")
            if keep:
                if length > 4096:
                    raise LocalAIError("local-ai-gguf-string-limit")
                return take(length).decode("utf-8")
            skip(length)
            return None

        def value(kind: int, keep: bool = False):
            if kind in _SCALARS:
                fmt = _SCALARS[kind]
                if keep:
                    return number(fmt)
                skip(struct.calcsize(fmt))
            elif kind == 8:
                return string(keep)
            elif kind == 9:
                element, count = number("I"), number("Q")
                if count > 1000000 or element == 9:
                    raise LocalAIError("local-ai-gguf-array-limit")
                if element in _SCALARS:
                    skip(count * struct.calcsize(_SCALARS[element]))
                elif element == 8:
                    for _ in range(count):
                        string(False)
                else:
                    raise LocalAIError("local-ai-gguf-value-type")
            else:
                raise LocalAIError("local-ai-gguf-value-type")
            return None

        if take(4) != b"GGUF" or number("I") not in (2, 3):
            raise LocalAIError("local-ai-gguf-format")
        number("Q")  # tensor count; tensor descriptors and tensor bytes are not read.
        count = number("Q")
        if count > 100000:
            raise LocalAIError("local-ai-gguf-metadata-limit")
        metadata = {}
        audio = False
        for _ in range(count):
            key = string(True)
            if not isinstance(key, str):
                raise LocalAIError("local-ai-gguf-key-invalid")
            kind = number("I")
            selected = bool(_METADATA.fullmatch(key))
            item = value(kind, selected)
            if selected and item is not None:
                metadata[key] = item
            audio = audio or key.startswith(("audio.", "whisper.", "granite_speech."))
        return {"values": metadata, "audio": audio, "header_bytes": source.tell()}


def _role(header: dict) -> str | None:
    values = header["values"]
    architecture = str(values.get("general.architecture", "")).lower()
    kind = " ".join(str(values.get("general." + key, "")) for key in ("type", "kind", "name", "basename")).lower()
    if architecture == "clip" or "mmproj" in kind or "projector" in kind:
        return None
    if (header["audio"] or any(part in architecture + " " + kind for part in
            ("speech", "audio", "whisper", "wavtokenizer", "parakeet"))):
        return "speech-to-text"
    pooling = values.get(architecture + ".pooling_type", 0)
    if "embed" in kind or architecture in {"bert", "nomic-bert", "jina-bert-v2"} or (type(pooling) is int and pooling > 0):
        return "embedding"
    return "text-to-text"


def _kv(header: dict) -> int:
    values = header["values"]
    prefix = str(values.get("general.architecture", "")) + "."

    def positive(key: str, default: int) -> int:
        value = values.get(prefix + key)
        return value if type(value) is int and value > 0 else default

    heads = positive("attention.head_count", 32)
    dimension = positive("embedding_length", heads * 128) // heads
    return (2 * positive("block_count", 32) * positive("attention.head_count_kv", 8)
            * (positive("attention.key_length", dimension) + positive("attention.value_length", dimension)))


def _save(local: dict, filename: str, *, slot: dict | None = None, projectors: list[str] | None = None, allow_unpaired: bool = False) -> dict:
    path = _model_path(local["shelf"], filename)
    header = gguf_metadata(path)
    role = _role(header)
    if role is None or filename.lower().startswith("mmproj"):
        raise LocalAIError("local-ai-projector-is-not-a-save")
    name = next(name for name, expected in ROLES.items() if expected == role)
    configured = _slot(local, name)
    ctx = (slot or configured)["ctx"]
    mmproj = None
    mmproj_bytes = 0
    if role == "speech-to-text":
        mmproj = slot.get("mmproj") if slot is not None else (
            configured.get("mmproj") if configured.get("model") == filename else None)
        if mmproj is None:
            candidates = projectors if projectors is not None else [
                item.name for item in Path(local["shelf"]).glob("*.gguf")
                if item.name.lower().startswith("mmproj")]
            matching = [item for item in candidates if Path(filename).stem.lower() in item.lower()]
            mmproj = matching[0] if len(matching) == 1 else candidates[0] if len(candidates) == 1 else None
        if mmproj is None:
            if not allow_unpaired:
                raise LocalAIError("local-ai-speech-projector-ambiguous-or-missing")
        else:
            projector = _model_path(local["shelf"], mmproj)
            if _role(gguf_metadata(projector)) is not None and not mmproj.lower().startswith("mmproj"):
                raise LocalAIError("local-ai-speech-projector-invalid")
            mmproj_bytes = projector.stat().st_size
    file_bytes = path.stat().st_size + mmproj_bytes
    per_ctx = _kv(header)
    kv_bytes = ctx * per_ctx
    return {"file": filename, "role": role, "bytes": path.stat().st_size,
            "mmproj": mmproj, "mmproj_bytes": mmproj_bytes, "file_bytes": file_bytes,
            "ctx": ctx, "kv_bytes_per_ctx": per_ctx, "kv_bytes": kv_bytes,
            "blocks": (file_bytes + kv_bytes + GIB - 1) // GIB,
            "architecture": header["values"].get("general.architecture"),
            "header_bytes": header["header_bytes"],
            "selectable": role != "speech-to-text" or mmproj is not None,
            "firstMissingSignal": "local-ai-speech-projector-ambiguous-or-missing" if role == "speech-to-text" and mmproj is None else "none"}


def library(local: dict) -> dict:
    root = Path(local["shelf"])
    if not root.is_dir():
        raise LocalAIError("local-ai-shelf-unavailable")
    files = sorted(item.name for item in root.iterdir() if item.name.lower().endswith(".gguf"))
    projectors, headers, failures = [], {}, {}
    for name in files:
        if name.lower().startswith("mmproj"):
            projectors.append(name)
            continue
        try:
            headers[name] = gguf_metadata(_model_path(local["shelf"], name))
            if _role(headers[name]) is None:
                projectors.append(name)
        except (LocalAIError, OSError, ValueError, UnicodeError) as error:
            failures[name] = str(error) if isinstance(error, LocalAIError) else "local-ai-gguf-unreadable"
    saves = []
    for name in files:
        if name in projectors:
            continue
        try:
            if name in failures:
                raise LocalAIError(failures[name])
            saves.append(_save(local, name, projectors=projectors, allow_unpaired=True))
        except (LocalAIError, OSError, ValueError, UnicodeError) as error:
            # A broken save remains visible; never hide the rest of the shelf.
            header = headers.get(name)
            try:
                size = _model_path(local["shelf"], name).stat().st_size
            except (OSError, LocalAIError):
                size = None
            saves.append({"file": name, "role": _role(header) if header else None,
                          "bytes": size, "blocks": None, "selectable": False,
                          "firstMissingSignal": str(error) if isinstance(error, LocalAIError) else "local-ai-save-unreadable"})
    return {"ok": True, "shelf": local["shelf"], "saves": saves,
            "unavailable_saves": sum(not save["selectable"] for save in saves),
            "formula": FORMULA, "kv_estimate": KV_ESTIMATE, "mutationPerformed": False}


def _vulkan_devices() -> list[dict]:
    """Use the loader, not a software Vulkan/CPU adapter as a GPU witness."""
    class InstanceInfo(ctypes.Structure):
        _fields_ = [("sType", ctypes.c_uint32), ("pNext", ctypes.c_void_p),
                    ("flags", ctypes.c_uint32), ("pApplicationInfo", ctypes.c_void_p),
                    ("enabledLayerCount", ctypes.c_uint32), ("ppEnabledLayerNames", ctypes.c_void_p),
                    ("enabledExtensionCount", ctypes.c_uint32), ("ppEnabledExtensionNames", ctypes.c_void_p)]

    instance = ctypes.c_void_p()
    loader = None
    try:
        loader = ctypes.CDLL(ctypes.util.find_library("vulkan") or "libvulkan.so.1")
        loader.vkCreateInstance.argtypes = [ctypes.POINTER(InstanceInfo), ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
        loader.vkEnumeratePhysicalDevices.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_void_p]
        loader.vkGetPhysicalDeviceProperties.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        loader.vkDestroyInstance.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        if loader.vkCreateInstance(ctypes.byref(InstanceInfo(sType=1)), None, ctypes.byref(instance)) != 0:
            raise LocalAIError("local-ai-vulkan-unavailable")
        count = ctypes.c_uint32()
        if loader.vkEnumeratePhysicalDevices(instance, ctypes.byref(count), None) != 0 or count.value > 32:
            raise LocalAIError("local-ai-vulkan-enumeration-failed")
        handles = (ctypes.c_void_p * count.value)()
        if loader.vkEnumeratePhysicalDevices(instance, ctypes.byref(count), handles) != 0:
            raise LocalAIError("local-ai-vulkan-enumeration-failed")
        devices = []
        for handle in handles[:count.value]:
            properties = ctypes.create_string_buffer(4096)
            loader.vkGetPhysicalDeviceProperties(handle, properties)
            _api, _driver, vendor, device, kind = struct.unpack_from("=5I", properties.raw)
            if kind in (1, 2):  # integrated or discrete GPU; never CPU or virtual/software.
                devices.append({"vendor": vendor, "device": device, "kind": kind,
                                "name": properties.raw[20:276].split(b"\0", 1)[0].decode("utf-8", "replace")})
        return devices
    except (OSError, AttributeError) as error:
        raise LocalAIError("local-ai-vulkan-unavailable") from error
    finally:
        if instance.value and loader is not None:
            loader.vkDestroyInstance(instance, None)


def _command(argv: list[str], timeout: float = 15) -> tuple[int, str]:
    """Bound output while streaming; a query creates no file or retained receipt."""
    environment = {key: value for key, value in os.environ.items() if not key.startswith("LLAMA_ARG_")}
    environment.update(LC_ALL="C", LANG="C")
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, env=environment, close_fds=True) as process:
        output = bytearray()
        assert process.stdout is not None
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + timeout
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LocalAIError("local-ai-command-timeout")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, 4096)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        output.extend(chunk)
                        if len(output) > 65536:
                            raise LocalAIError("local-ai-command-output-limit")
                code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return code, output.decode("utf-8", "replace")
        except BaseException:
            process.kill()
            process.wait()
            raise


def _amdgpu_integrated(card_path: Path) -> bool | None:
    """Read AMDGPU_INFO_DEV_INFO.ids_flags, independent of the Vulkan loader.

    Linux UAPI drm/amdgpu_drm.h: INFO=0x05, DEV_INFO=0x16,
    IDS_FLAGS_FUSION=1; ids_flags follows the fixed 136-byte device prefix.
    This query neither allocates GPU memory nor changes hardware settings.
    """
    for node in sorted((card_path / "device" / "drm").glob("renderD*")):
        try:
            result = ctypes.create_string_buffer(144)
            query = struct.pack("=QII16x", ctypes.addressof(result), len(result), 0x16)
            operation = (1 << 30) | (len(query) << 16) | (ord("d") << 8) | 0x45
            fd = os.open("/dev/dri/" + node.name, os.O_RDONLY | os.O_CLOEXEC)
            try:
                fcntl.ioctl(fd, operation, query)
            finally:
                os.close(fd)
            return bool(struct.unpack_from("=Q", result.raw, 136)[0] & 1)
        except OSError:
            continue
    return None


def _gpu_memory() -> dict:
    try:
        devices = _vulkan_devices()
    except LocalAIError:
        devices = []
    cards = sorted(Path("/sys/class/drm").glob("card[0-9]*"),
                   key=lambda path: int(path.name[4:]) if path.name[4:].isdigit() else 1000000)
    for card_path in cards:
        path = card_path / "device"
        try:
            vram = int((path / "mem_info_vram_total").read_text())
            vendor = int((path / "vendor").read_text(), 16)
            device = int((path / "device").read_text(), 16)
        except (OSError, ValueError):
            continue
        if vendor != 0x1002:
            continue
        matching = next((row for row in devices if row["vendor"] == vendor and row["device"] == device), None)
        source = path / "mem_info_vram_total"
        integrated = _amdgpu_integrated(card_path)
        if integrated is None and matching is not None:
            integrated = matching["kind"] == 1
        if integrated is None:
            raise LocalAIError("local-ai-amd-gpu-type-unavailable")
        if integrated:
            source = path / "mem_info_gtt_total"
            try:
                vram = int(source.read_text())
            except (OSError, ValueError) as error:
                raise LocalAIError("local-ai-apu-gtt-unreadable") from error
        if vram > 0:
            return {"bytes": vram, "source": str(source), "name": matching["name"] if matching else card_path.name}
    try:
        code, output = _command(["/usr/bin/nvidia-smi", "--query-gpu=memory.total", "--format=csv,noheader,nounits"])
        first = output.splitlines()[0] if code == 0 and output.splitlines() else ""
        if re.fullmatch(r"\s*\d+\s*", first) and int(first) > 0:
            return {"bytes": int(first) * 1024 ** 2, "source": "nvidia-smi:memory.total:first-gpu", "name": "NVIDIA GPU 0"}
    except OSError:
        pass
    raise LocalAIError("local-ai-no-gpu")


def card(local: dict) -> dict:
    gpu = _gpu_memory()
    slots = {}
    for name in ROLES:
        slot = _slot(local, name)
        save = _save(local, slot["model"], slot=slot) if slot["model"] is not None else None
        if save is not None and save["role"] != slot["role"]:
            raise LocalAIError("local-ai-slot-model-role-mismatch")
        slots[name] = {"role": slot["role"], "model": slot["model"], "blocks": save["blocks"] if save else 0,
                       "ctx": slot["ctx"], "kv_bytes_per_ctx": save["kv_bytes_per_ctx"] if save else 0}
    total = gpu["bytes"] // GIB
    used = sum(slot["blocks"] for slot in slots.values())
    return {"ok": True, "gpu": gpu, "total_blocks": total, "slots": slots,
            "free_blocks": max(0, total - used), "overcommitted_blocks": max(0, used - total),
            "formula": FORMULA, "kv_estimate": KV_ESTIMATE, "mutationPerformed": False}


def apply(local: dict, name: str) -> dict:
    slot = _slot(local, name)
    operation = "stop" if slot["model"] is None else "restart"
    unit = f"model-slot@{name}.service"
    argv = ["/usr/bin/sudo", "-n", "/usr/bin/systemctl", operation, unit]
    code, _output = _command(argv, timeout=60)
    state_code, output = _command(["/usr/bin/systemctl", "show", unit,
                                   "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus"])
    state = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    expected = "inactive" if operation == "stop" else "active"
    ok = code == 0 and state_code == 0 and state.get("ActiveState") == expected
    return {"ok": ok, "slot": name, "unit": unit, "operation": operation, "argv": argv,
            "state": state, "exit_code": code, "state_exit_code": state_code,
            "firstMissingSignal": "none" if ok else "local-ai-slot-apply-state-refused",
            "mutationPerformed": True}


def run(local: dict, name: str) -> dict:
    slot = _slot(local, name)
    if slot["model"] is None:
        return {"ok": True, "slot": name, "state": "empty", "mutationPerformed": False}
    save = _save(local, slot["model"], slot=slot)
    if save["role"] != slot["role"]:
        raise LocalAIError("local-ai-slot-model-role-mismatch")
    devices = _vulkan_devices()
    if not devices:
        raise LocalAIError("local-ai-no-vulkan-gpu")
    code, output = _command([SERVER, "--list-devices"])
    available = re.findall(r"^\s*(Vulkan\d+):\s*(.+)$", output, re.MULTILINE) if code == 0 else []
    selected = next((identifier for identifier, description in available
                     if any(device["name"] in description for device in devices)), None)
    if selected is None:
        raise LocalAIError("local-ai-no-vulkan-gpu")
    argv = [SERVER, "-m", str(_model_path(local["shelf"], slot["model"])),
            "-c", str(slot["ctx"]), "--port", str(slot["port"]),
            "--host", "0.0.0.0" if slot["lan"] else "127.0.0.1", "-ngl", "99",
            "--device", selected, "--fit", "off", "--parallel", "1"]
    if slot["role"] == "speech-to-text":
        argv.extend(["-mm", str(_model_path(local["shelf"], save["mmproj"]))])
    if slot["role"] == "embedding":
        argv.append("--embedding")  # pooling comes from this model's metadata.
    environment = {key: value for key, value in os.environ.items() if not key.startswith("LLAMA_ARG_")}
    # Native engine output streams to the caller; no retained log/receipt or CPU retry.
    os.execve(SERVER, argv, environment)
    raise AssertionError("execve returned")


def slot_arguments(*, argv=None, envelope=None) -> list[str]:
    """The PIN gate and execution share precisely the same action selector."""
    if argv:
        return list(argv)
    if not isinstance(envelope, dict):
        return []
    payload = envelope.get("payload") if "schema" in envelope else envelope
    if not isinstance(payload, dict):
        return []
    arguments = payload.get("args")
    if arguments is not None:
        return arguments if isinstance(arguments, list) and all(isinstance(item, str) for item in arguments) else []
    transition = envelope.get("transition", "")
    parts = [part for part in re.split(r"[./:]", transition) if part] if isinstance(transition, str) else []
    operation = payload.get("action", payload.get("op", parts[-1] if parts else None))
    name = payload.get("slot")
    return [operation, name] if isinstance(operation, str) and isinstance(name, str) else []


def slot_action(*, argv=None, envelope=None) -> str:
    arguments = slot_arguments(argv=argv, envelope=envelope)
    if len(arguments) != 2 or arguments[0] not in {"apply", "run"} or arguments[1] not in ROLES:
        raise LocalAIError("local-ai-slot-arguments-invalid")
    return arguments[0]


def _optional_request(*fields: str) -> Request | None:
    if sys.stdin.isatty():
        return None
    raw = sys.stdin.read()
    if not raw.strip():
        return None
    from io import StringIO
    original = sys.stdin
    try:
        sys.stdin = StringIO(raw)
        return read(known_fields=fields)
    finally:
        sys.stdin = original


def _request(args: list[str]) -> tuple[list[str], Request | None]:
    request = _optional_request("args", "slot", "action", "op")
    return slot_arguments(argv=args, envelope=request.value if request else None), request


def main(verb: str, args=None) -> int:
    arguments = list(args or [])
    request = None
    started = time.monotonic()
    attempted = False
    action = verb
    try:
        if verb == "slot":
            arguments, request = _request(arguments)
            if len(arguments) != 2 or arguments[0] not in {"apply", "run"}:
                raise LocalAIError("local-ai-slot-arguments-invalid")
            action, name = arguments
            local = _config()
            _slot(local, name)
            attempted = action == "apply"
            reply = apply(local, name) if action == "apply" else run(local, name)
        else:
            if arguments:
                raise LocalAIError("local-ai-read-arguments-invalid")
            request = _optional_request()
            reply = card(_config()) if verb == "card" else library(_config())
    except (LocalAIError, EnvelopeError, OSError, UnicodeError, ValueError, RecursionError, subprocess.TimeoutExpired) as error:
        signal = str(error) if isinstance(error, (LocalAIError, EnvelopeError)) else "local-ai-observation-failed:" + type(error).__name__
        reply = {"ok": False, "firstMissingSignal": signal, "mutationPerformed": attempted}
    if action == "apply":
        # Canonical Log Line: the deed only, never config, model bytes or a body.
        print(json.dumps({"who": "agathodaimon", "verb": "local-ai-slot-apply", "target": reply.get("unit", "model-slot"),
                          "outcome": "ok" if reply["ok"] else "failed", "duration_ms": int((time.monotonic() - started) * 1000),
                          "signal": reply.get("firstMissingSignal", "none")}, separators=(",", ":")), file=sys.stderr)
    print(json.dumps(attach(reply, request) if request is not None else reply, separators=(",", ":")))
    return 0 if reply["ok"] else 1

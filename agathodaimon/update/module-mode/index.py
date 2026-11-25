"""Set or observe the household Harmonia safe-module list."""
from importlib import import_module
import json
import os
import re
import stat
import tempfile

from agathodaimon import _deed, _envelope
from agathodaimon._nidus.lock import household_config_held
from agathodaimon._nidus.path import appliance_runtime_path

_writer = import_module("agathodaimon.update.module-toggle.index")
_MODULE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
_PREFIX = "agathodaimon-update-module-mode-"


class Refusal(ValueError):
    pass


def _receipt(module=None, mode=None, modules=None, *, ok=True, changed=False, signal="none"):
    return {"ok": ok, "module": module, "mode": mode, "safe_modules": modules if modules is not None else [],
            "changed": changed, "mutationPerformed": changed, "exceptionType": "",
            "firstMissingSignal": signal}


def _load(raw):
    try:
        document = _writer._load(raw)
    except _writer.ToggleError as error:
        suffix = "config-not-object" if str(error).endswith("config-not-object") else "config-invalid"
        raise Refusal(_PREFIX + suffix) from error
    section = document.get("harmonia", {})
    if not isinstance(section, dict):
        raise Refusal(_PREFIX + "harmonia-not-object")
    modules = section.get("safe_modules", [])
    if not isinstance(modules, list) or any(not isinstance(item, str) for item in modules):
        raise Refusal(_PREFIX + "safe-modules-invalid")
    return document, modules


def _splice(raw, document, modules):
    start, end, members = _writer._object_members(raw)
    rendered = json.dumps(modules, indent=2, ensure_ascii=False)
    if "harmonia" not in document:
        return _writer._insert_member(raw, start, end, "harmonia", json.dumps({"safe_modules": modules}, ensure_ascii=False))
    section_start, _ = members["harmonia"]
    section_start, section_end, section_members = _writer._object_members(raw, section_start)
    if "safe_modules" in section_members:
        a, b = section_members["safe_modules"]
        return raw[:a] + rendered + raw[b:]
    return _writer._insert_member(raw, section_start, section_end, "safe_modules", rendered)


def _atomic_write(path, payload, metadata):
    # Unlike the sibling helper, the replace is the last fallible step that
    # can change the answer. Directory sync and cleanup cannot undo the act.
    fd, temporary = tempfile.mkstemp(prefix=".config.", dir=path.parent)
    replaced = False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fchmod(handle.fileno(), stat.S_IMODE(metadata.st_mode))
            if os.geteuid() == 0:
                os.fchown(handle.fileno(), metadata.st_uid, metadata.st_gid)
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        replaced = True
    finally:
        if not replaced:
            try:
                os.unlink(temporary)
            except OSError:
                pass
    try:
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        pass


def _operate(module, mode):
    path = appliance_runtime_path("config")
    if module is None:
        try:
            raw = path.read_bytes().decode("utf-8")
        except FileNotFoundError as error:
            raise Refusal(_PREFIX + "config-missing") from error
        _, modules = _load(raw)
        return _receipt(modules=modules)

    committed = None
    try:
        with household_config_held():
            try:
                raw = path.read_bytes().decode("utf-8")
            except FileNotFoundError as error:
                raise Refusal(_PREFIX + "config-missing") from error
            document, previous = _load(raw)
            if (mode == "safe" and module in previous) or (mode == "developer" and module not in previous):
                return _receipt(module, mode, previous)
            modules = list(dict.fromkeys(previous))
            if mode == "safe" and module not in modules:
                modules.append(module)
            if mode == "developer":
                modules = [item for item in modules if item != module]
            if modules == previous:
                return _receipt(module, mode, modules)
            updated = _splice(raw, document, modules).encode("utf-8")
            metadata = path.stat()
            _atomic_write(path, updated, metadata)
            committed = _receipt(module, mode, modules, changed=True)
    except OSError:
        if committed is None:
            raise
    return committed


def _emit(result):
    if result["changed"] or not result["ok"]:
        try:
            _deed.send("sbin", "update-module-mode", result["ok"],
                       outcome="changed" if result["ok"] else None,
                       signal=result["firstMissingSignal"])
        except Exception:
            pass
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


def main(argv=None):
    del argv
    module = mode = None
    try:
        try:
            request = _envelope.read()
        except (_envelope.EnvelopeError, UnicodeError, RecursionError) as error:
            raise Refusal(_PREFIX + "arguments-invalid") from error
        payload = request.value.get("payload") if request.envelope else request.value
        if not isinstance(payload, dict):
            raise Refusal(_PREFIX + "arguments-invalid")
        has_module, has_mode = "module" in payload, "mode" in payload
        module, mode = payload.get("module"), payload.get("mode")
        if has_module != has_mode or (has_mode and (not isinstance(mode, str) or mode not in ("safe", "developer"))):
            raise Refusal(_PREFIX + "arguments-invalid")
        if has_module and (not isinstance(module, str) or not _MODULE.fullmatch(module)):
            raise Refusal(_PREFIX + "module-invalid")
        return _emit(_operate(module, mode))
    except (_envelope.EnvelopeError, UnicodeError, OSError, Refusal) as error:
        signal = _PREFIX + "arguments-invalid" if isinstance(error, _envelope.EnvelopeError) else str(error)
        return _emit(_receipt(module if isinstance(module, str) else None,
                              mode if isinstance(mode, str) else None, ok=False, signal=signal))


if __name__ == "__main__":
    raise SystemExit(main())

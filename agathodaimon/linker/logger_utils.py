"""Linker deeds use the staff's one appliance log; verbose reads stay silent."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import logging
import os
import time
import uuid

from agathodaimon._envelope import appliance_runtime_path

_quiet = ContextVar("linker_quiet_mutations", default=False)
_batch: ContextVar[_Batch | None] = ContextVar("linker_mutation_batch", default=None)
MUTATIONS = frozenset({"deploy", "delete", "rename", "mkdir"})


def get_logger(name="linker"):
    """Retain donor diagnostic calls without routing reads or bodies to a log."""
    logger = logging.getLogger(name)
    logger.disabled = True
    logger.propagate = False
    return logger


def record_deed(verb, ok, signal, started):
    line = json.dumps({
        "who": "agathodaimon", "verb": "linker-" + verb, "target": "nas",
        "outcome": "ok" if ok else "failed",
        "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
        "id": uuid.uuid4().hex, "signal": signal,
        "first_missing_field": None if ok else "linker/" + verb,
    }, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(line) >= 1024:
        raise OSError("linker-ledger-line-too-large")
    path = appliance_runtime_path("config").parents[2] / "var/log/appliance/appliance.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o640)
    try:
        if os.write(descriptor, line) != len(line):
            raise OSError("linker-ledger-write-failed")
    finally:
        os.close(descriptor)


@contextmanager
def quiet_mutations():
    """The staff receipt or JSON adapter, not each core call, owns its deed."""
    token = _quiet.set(True)
    try:
        yield
    finally:
        _quiet.reset(token)


class _Batch:
    def __init__(self):
        self.ok = True
        self.calls = 0

    def observe(self, result):
        self.calls += 1
        self.ok = self.ok and (result.get("ok") is True if isinstance(result, dict) else result is True)


@contextmanager
def _deed(verb):
    started = time.monotonic()
    batch = _Batch()
    token = _batch.set(batch)
    try:
        yield batch
    except BaseException:
        batch.ok = False
        raise
    finally:
        _batch.reset(token)
        record_deed(verb, batch.ok, "none" if batch.ok else "linker-" + verb + "-failed", started)


def mutation(verb):
    """Record a direct core mutation once, or fold it into its caller's deed."""
    def decorate(function):
        @wraps(function)
        def invoke(*args, **kwargs):
            if _quiet.get():
                return function(*args, **kwargs)
            batch = _batch.get()
            if batch is not None:
                result = function(*args, **kwargs)
                batch.observe(result)
                return result
            with _deed(verb) as batch:
                result = function(*args, **kwargs)
                batch.observe(result)
                return result
        return invoke
    return decorate


def deploy_deed(function):
    """One TUI deploy gesture can call the core for several selected sources."""
    @wraps(function)
    def invoke(self, *args, **kwargs):
        expected = len(self.selected)
        if not expected:
            return function(self, *args, **kwargs)
        with _deed("deploy") as batch:
            result = function(self, *args, **kwargs)
            batch.ok = batch.ok and batch.calls == expected
            return result
    return invoke


def json_deed(function):
    @wraps(function)
    def invoke(request):
        verb = request.get("operation")
        if verb not in MUTATIONS:
            return function(request)
        started = time.monotonic()
        ok = False
        try:
            with quiet_mutations():
                result = function(request)
            ok = result[0].get("ok") is True
            return result
        finally:
            record_deed(verb, ok, "none" if ok else "linker-" + verb + "-failed", started)
    return invoke

"""Transient staff load tracing carried only by the active reply."""
from __future__ import annotations

import base64
import contextvars
import copy
import json
import os
import platform
import sys
import time
import uuid
from collections import OrderedDict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Iterator, Mapping
from urllib.parse import urlsplit
from urllib.request import Request as UrlRequest, urlopen

LOAD_CONTEXT_SCHEMA = "appliance.load.context.v1"
BENCHMARK_SCHEMA = "caduceus.benchmark.v1"
STAFF_NAMESPACE = "agathodaimon.load_trace.v1"
CADUCEUS_NAMESPACE = "caduceus.load_trace.v1"
CLI_REPLY_MAX_BYTES = 1024 * 1024
MAX_CONTEXT_BYTES = 16 * 1024
MAX_STAMPS = 64
MAX_STAMP_BYTES = 2048
MAX_CORRELATION_BYTES = 256
_SCHEMA_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_SCHEMA_LOCK = RLock()

BENCHMARK_CONTEXT: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "agathodaimon_benchmark", default=None
)
_ACTIVE: contextvars.ContextVar[InvocationHandle | None] = contextvars.ContextVar(
    "agathodaimon_load_trace", default=None
)
_ACTIVE_SPAN: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "agathodaimon_load_trace_span", default=None
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _compact(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _serialized_size_bounded(value: Any, limit: int) -> int | None:
    """Measure compact UTF-8 JSON without allocating an oversized encoded body."""
    total = 0
    encoder = json.JSONEncoder(separators=(",", ":"), ensure_ascii=False)
    try:
        for chunk in encoder.iterencode(value):
            if len(chunk) > limit - total:
                return None
            size = len(chunk.encode("utf-8"))
            if size > limit - total:
                return None
            total += size
    except (TypeError, ValueError, UnicodeError):
        return None
    return total


def _process_boot_elapsed_ms() -> tuple[int, bool]:
    """Return the real process-start-to-now CLOCK_BOOTTIME measurement."""
    try:
        stat_text = Path("/proc/self/stat").read_text(encoding="ascii")
        closing = stat_text.rfind(")")
        if closing < 0:
            return 0, False
        fields = stat_text[closing + 1 :].split()
        if len(fields) <= 19:
            return 0, False
        start_ticks = int(fields[19])
        ticks_per_second = int(os.sysconf("SC_CLK_TCK"))
        if start_ticks < 0 or ticks_per_second <= 0:
            return 0, False
        process_start_ns = start_ticks * 1_000_000_000 // ticks_per_second
        boot_now_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        elapsed_ns = boot_now_ns - process_start_ns
        if elapsed_ns < 0:
            return 0, False
        return elapsed_ns // 1_000_000, True
    except (OSError, ValueError, IndexError, AttributeError, OverflowError):
        return 0, False


def process_boot_elapsed_ms() -> tuple[int, bool]:
    """Face adapter for the shared, real process-boot measurement."""
    return _process_boot_elapsed_ms()


def _benchmark_enabled(request: Any) -> bool:
    if getattr(request, "envelope", False):
        value = getattr(request, "value", None)
        flags = value.get("flags") if isinstance(value, Mapping) else None
        if isinstance(flags, Mapping) and flags.get("benchmark") is True:
            return True
    context = getattr(request, "load_context", None)
    return bool(
        getattr(request, "load_context_present", False)
        and isinstance(context, Mapping)
        and context.get("benchmark") is True
    )


def benchmark_enabled(request: Any) -> bool:
    """Preserve the existing face benchmark-flag presence semantics."""
    return _benchmark_enabled(request)


def benchmark_requested(envelope: Any) -> bool:
    """Read existing flag detail or canonical load-context detail without narrowing."""
    if not isinstance(envelope, Mapping):
        return False
    flags = envelope.get("flags")
    if isinstance(flags, Mapping) and flags.get("benchmark") is True:
        return True
    payload = envelope.get("payload")
    for container in (payload, envelope):
        if not isinstance(container, Mapping):
            continue
        scoped_flags = container.get("flags")
        context = scoped_flags.get("load_context") if isinstance(scoped_flags, Mapping) else None
        if isinstance(context, Mapping) and context.get("benchmark") is True:
            return True
    return False


def _benchmark_call(
    locus: str,
    operation: Callable[[], Any],
    *,
    success: Callable[[Any], bool] | None = None,
) -> Any:
    context = BENCHMARK_CONTEXT.get()
    if context is None:
        return operation()
    try:
        started_ns = time.perf_counter_ns()
    except Exception:
        try:
            operation_result = operation()
        except BaseException:
            context["timings"].append({"locus": locus, "elapsed_ms": 0, "ok": False})
            raise
        context["timings"].append({"locus": locus, "elapsed_ms": 0, "ok": False})
        return operation_result
    ok = False
    try:
        result = operation()
        ok = success(result) if success is not None else True
        return result
    except BaseException:
        ok = False
        raise
    finally:
        try:
            elapsed_ns = time.perf_counter_ns() - started_ns
            if elapsed_ns < 0:
                elapsed_ns = 0
                ok = False
        except Exception:
            elapsed_ns = 0
            ok = False
        context["timings"].append({
            "locus": locus,
            "elapsed_ms": elapsed_ns // 1_000_000,
            "ok": bool(ok),
        })


def benchmark_call(
    locus: str,
    operation: Callable[[], Any],
    *,
    success: Callable[[Any], bool] | None = None,
) -> Any:
    """Face adapter for the single shared timing engine."""
    return _benchmark_call(locus, operation, success=success)


def _benchmark_boot_entry() -> dict[str, Any]:
    elapsed_ms, ok = _process_boot_elapsed_ms()
    return {"locus": "staff.boot", "elapsed_ms": elapsed_ms, "ok": ok}


def benchmark_boot_entry() -> dict[str, Any]:
    """Face adapter for the legacy benchmark boot row."""
    return _benchmark_boot_entry()


def extract_load_context(envelope: Any) -> tuple[bool, Any]:
    """Return the caller's raw optional flags.load_context without narrowing it."""
    if not isinstance(envelope, Mapping):
        return False, None
    payload = envelope.get("payload")
    for container in (payload, envelope):
        if not isinstance(container, Mapping):
            continue
        flags = container.get("flags")
        if isinstance(flags, Mapping) and "load_context" in flags:
            raw = flags["load_context"]
            if raw is None:
                return False, None
            if _serialized_size_bounded(raw, MAX_CONTEXT_BYTES) is None:
                return True, raw
            return True, copy.deepcopy(raw)
    return False, None


def _caduceus_base_url() -> str:
    # The runtime config remains the sole source for the local Caduceus door.
    from agathodaimon._envelope import appliance_runtime_path

    value = json.loads(appliance_runtime_path("config").read_text(encoding="utf-8"))
    bind = value["caduceus"]["bind"]
    if not isinstance(bind, str) or not bind.strip():
        raise ValueError("caduceus-bind-invalid")
    bind = bind.strip()
    if "://" not in bind:
        bind = "http://" + bind
    parsed = urlsplit(bind)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.port:
        raise ValueError("caduceus-bind-invalid")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("caduceus-bind-credentials-refused")
    host = parsed.hostname
    if host in {"0.0.0.0", "::", "[::]", "localhost"}:
        host = "127.0.0.1"
    else:
        import ipaddress

        address = ipaddress.ip_address(host)
        if not address.is_loopback:
            raise ValueError("caduceus-bind-not-local")
        host = "127.0.0.1"
    return f"{parsed.scheme}://{host}:{parsed.port}"


def _load_seat(schema_id: str, base: str) -> dict[str, Any]:
    with _SCHEMA_LOCK:
        cached = _SCHEMA_CACHE.get(schema_id)
        if cached is not None:
            _SCHEMA_CACHE.move_to_end(schema_id)
            return cached
    request = UrlRequest(
        f"{base}/api/v1/schema/{schema_id}",
        headers={"Accept": "application/json"},
        method="GET",
    )
    with urlopen(request, timeout=2.0) as response:
        raw = response.read(64 * 1024 + 1)
    if len(raw) > 64 * 1024:
        raise ValueError("schema-seat-too-large")
    seat = json.loads(raw.decode("utf-8"))
    if not isinstance(seat, dict) or seat.get("schema") != schema_id:
        raise ValueError("schema-seat-identity-mismatch")
    with _SCHEMA_LOCK:
        _SCHEMA_CACHE[schema_id] = seat
        _SCHEMA_CACHE.move_to_end(schema_id)
        while len(_SCHEMA_CACHE) > 2:
            _SCHEMA_CACHE.popitem(last=False)
    return seat


def _load_limits() -> tuple[dict[str, int], str | None]:
    try:
        with _SCHEMA_LOCK:
            context_seat = _SCHEMA_CACHE.get(LOAD_CONTEXT_SCHEMA)
            benchmark_seat = _SCHEMA_CACHE.get(BENCHMARK_SCHEMA)
        if context_seat is None or benchmark_seat is None:
            base = _caduceus_base_url()
            if context_seat is None:
                context_seat = _load_seat(LOAD_CONTEXT_SCHEMA, base)
            if benchmark_seat is None:
                benchmark_seat = _load_seat(BENCHMARK_SCHEMA, base)
        budgets = context_seat.get("budgets")
        if not isinstance(budgets, Mapping):
            raise ValueError("context-seat-budgets-missing")
        seat_limits = {
            "context_bytes": budgets.get("encoded_context_bytes"),
            "stamps": budgets.get("stamps"),
            "stamp_bytes": budgets.get("serialized_stamp_bytes"),
            "benchmark_rows": budgets.get("benchmark_rows_per_stamp"),
        }
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in seat_limits.values()):
            raise ValueError("context-seat-budget-invalid")
        if benchmark_seat.get("schema") != BENCHMARK_SCHEMA:
            raise ValueError("benchmark-seat-identity-mismatch")
        return {
            "context_bytes": min(seat_limits["context_bytes"], MAX_CONTEXT_BYTES),
            "stamps": min(seat_limits["stamps"], MAX_STAMPS),
            "stamp_bytes": min(seat_limits["stamp_bytes"], MAX_STAMP_BYTES),
            "benchmark_rows": min(seat_limits["benchmark_rows"], 1),
        }, None
    except Exception:
        return {}, "load-trace-canonical-seat-unavailable"


def _valid_context(value: Any) -> bool:
    if not isinstance(value, Mapping) or value.get("schema") != LOAD_CONTEXT_SCHEMA:
        return False
    correlation_id = value.get("correlation_id")
    if not isinstance(correlation_id, str) or not correlation_id:
        return False
    try:
        if len(correlation_id.encode("utf-8")) > MAX_CORRELATION_BYTES:
            return False
    except UnicodeError:
        return False
    return isinstance(value.get("stamps"), list)


def _context_fits(value: Any, limits: Mapping[str, int]) -> bool:
    if not _valid_context(value):
        return False
    try:
        if _serialized_size_bounded(value, limits["context_bytes"]) is None:
            return False
        stamps = value["stamps"]
        if len(stamps) > limits["stamps"]:
            return False
        for stamp in stamps:
            if _serialized_size_bounded(stamp, limits["stamp_bytes"]) is None:
                return False
            benchmark = stamp.get("benchmark") if isinstance(stamp, Mapping) else None
            timings = benchmark.get("timings") if isinstance(benchmark, Mapping) else None
            if isinstance(timings, list) and len(timings) > limits["benchmark_rows"]:
                return False
    except Exception:
        return False
    return True


def _diagnostic_only_context(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and "schema" not in value
        and bool(value)
        and set(value).issubset({"trace_unavailable", "trace_incomplete"})
    )


def _merge_contexts(target: Any, returned: Any) -> Any:
    """Merge only same-correlation additive fields and append-only stamp suffixes."""
    if not isinstance(target, dict) or not isinstance(returned, Mapping):
        return copy.deepcopy(target)
    result = copy.deepcopy(target)
    if not _valid_context(target) or not _valid_context(returned):
        return result
    if target.get("correlation_id") != returned.get("correlation_id"):
        result.setdefault("trace_incomplete", "load-trace-correlation-mismatch")
        return result
    target_stamps = result.get("stamps")
    returned_stamps = returned.get("stamps")
    if isinstance(target_stamps, list) and isinstance(returned_stamps, list):
        if returned_stamps[: len(target_stamps)] == target_stamps:
            result["stamps"] = copy.deepcopy(returned_stamps)
        elif target_stamps[: len(returned_stamps)] != returned_stamps:
            result.setdefault("trace_incomplete", "load-trace-returned-stamp-prefix-mismatch")
    for key, value in returned.items():
        if key == "stamps":
            continue
        if key == "next_hop_ancestry" and isinstance(value, list):
            prior = result.get(key)
            if isinstance(prior, list):
                for link in value:
                    if link not in prior:
                        prior.append(copy.deepcopy(link))
            elif key not in result:
                result[key] = copy.deepcopy(value)
        elif key not in result:
            result[key] = copy.deepcopy(value)
    return result


class _TraceState:
    def __init__(self, raw_context: Any, limits: dict[str, int], unavailable: str | None):
        self.limits = limits
        self.unavailable = unavailable
        self.incomplete: str | None = None
        self.raw: dict[str, Any] | None = None
        self.correlation_id: str | None = None
        self.root_parent: str | None = None
        self.forwardable = False
        if unavailable is not None:
            self.raw = dict(raw_context) if isinstance(raw_context, Mapping) else None
            self.forwardable = self._can_forward(raw_context)
            return
        if not _valid_context(raw_context):
            self.unavailable = "load-trace-context-invalid"
            self.raw = dict(raw_context) if isinstance(raw_context, Mapping) else None
            return
        encoded_size = _serialized_size_bounded(raw_context, limits["context_bytes"])
        self.raw = dict(raw_context) if encoded_size is None else copy.deepcopy(dict(raw_context))
        self.correlation_id = raw_context["correlation_id"]
        stamps = self.raw.get("stamps")
        self.root_parent = self._parent_from_context(self.raw)
        if encoded_size is None:
            self.incomplete = "load-trace-context-byte-limit"
            return
        if len(stamps) > limits["stamps"]:
            self.incomplete = "load-trace-context-stamp-limit"
            return
        for stamp in stamps:
            if not isinstance(stamp, Mapping) or _serialized_size_bounded(stamp, limits["stamp_bytes"]) is None:
                self.incomplete = "load-trace-stamp-byte-limit"
                return
            benchmark = stamp.get("benchmark")
            timings = benchmark.get("timings") if isinstance(benchmark, Mapping) else None
            if isinstance(timings, list) and len(timings) > limits["benchmark_rows"]:
                self.incomplete = "load-trace-benchmark-row-limit"
                return
        self.forwardable = True

    @staticmethod
    def _can_forward(raw_context: Any) -> bool:
        return _context_fits(
            raw_context,
            {
                "context_bytes": MAX_CONTEXT_BYTES,
                "stamps": MAX_STAMPS,
                "stamp_bytes": MAX_STAMP_BYTES,
                "benchmark_rows": 1,
            },
        )

    @staticmethod
    def _parent_from_context(value: Mapping[str, Any]) -> str | None:
        ancestry = value.get("next_hop_ancestry")
        if isinstance(ancestry, list):
            for link in reversed(ancestry):
                if (
                    isinstance(link, Mapping)
                    and link.get("namespace") == CADUCEUS_NAMESPACE
                    and isinstance(link.get("parent_span_id"), str)
                    and link.get("parent_span_id")
                ):
                    return link["parent_span_id"]
        stamps = value.get("stamps")
        if isinstance(stamps, list):
            for stamp in reversed(stamps):
                if isinstance(stamp, Mapping) and isinstance(stamp.get("span_id"), str) and stamp.get("span_id"):
                    return stamp["span_id"]
        parent = value.get("parent_span_id")
        return parent if isinstance(parent, str) and parent else None

    def _mark_incomplete(self, signal: str) -> None:
        if self.incomplete is None:
            self.incomplete = signal

    def add_stamp(self, stamp: dict[str, Any]) -> bool:
        if self.unavailable is not None or self.raw is None or self.incomplete is not None:
            return False
        try:
            if _serialized_size_bounded(stamp, self.limits["stamp_bytes"]) is None:
                self._mark_incomplete("load-trace-stamp-byte-limit")
                return False
            candidate = copy.deepcopy(self.raw)
            stamps = candidate.get("stamps")
            if not isinstance(stamps, list):
                self._mark_incomplete("load-trace-stamps-invalid")
                return False
            if len(stamps) >= self.limits["stamps"]:
                self._mark_incomplete("load-trace-context-stamp-limit")
                return False
            stamps.append(stamp)
            if _serialized_size_bounded(candidate, self.limits["context_bytes"]) is None:
                self._mark_incomplete("load-trace-context-byte-limit")
                return False
        except Exception:
            self._mark_incomplete("load-trace-context-serialization-failed")
            return False
        self.raw = candidate
        return True

    def merge_returned(self, returned: Any) -> bool:
        if self.unavailable is not None or self.raw is None or not _valid_context(returned):
            return False
        if returned.get("correlation_id") != self.correlation_id:
            self._mark_incomplete("load-trace-correlation-mismatch")
            return False
        current_stamps = self.raw.get("stamps")
        returned_stamps = returned.get("stamps")
        if not isinstance(current_stamps, list) or not isinstance(returned_stamps, list):
            self._mark_incomplete("load-trace-stamps-invalid")
            return False
        if returned_stamps[: len(current_stamps)] != current_stamps:
            self._mark_incomplete("load-trace-returned-stamp-prefix-mismatch")
            return False
        if len(returned_stamps) > self.limits["stamps"]:
            self._mark_incomplete("load-trace-context-stamp-limit")
            return False
        for stamp in returned_stamps[len(current_stamps) :]:
            if not isinstance(stamp, Mapping) or _serialized_size_bounded(stamp, self.limits["stamp_bytes"]) is None:
                self._mark_incomplete("load-trace-stamp-byte-limit")
                return False
            benchmark = stamp.get("benchmark")
            timings = benchmark.get("timings") if isinstance(benchmark, Mapping) else None
            if isinstance(timings, list) and len(timings) > self.limits["benchmark_rows"]:
                self._mark_incomplete("load-trace-benchmark-row-limit")
                return False
        candidate = _merge_contexts(self.raw, returned)
        try:
            if _serialized_size_bounded(candidate, self.limits["context_bytes"]) is None:
                self._mark_incomplete("load-trace-context-byte-limit")
                return False
        except Exception:
            self._mark_incomplete("load-trace-context-serialization-failed")
            return False
        self.raw = candidate
        return True

    def response(self) -> Any:
        if self.raw is None:
            if self.incomplete is not None:
                return {"trace_incomplete": self.incomplete}
            return {"trace_unavailable": {"signal": self.unavailable or "load-trace-context-unavailable"}}
        result = copy.deepcopy(self.raw)
        if self.unavailable is not None:
            result["trace_unavailable"] = {"signal": self.unavailable}
        if self.incomplete is not None:
            result["trace_incomplete"] = self.incomplete
        limit = self.limits.get("context_bytes", MAX_CONTEXT_BYTES)
        if _serialized_size_bounded(result, limit) is None:
            diagnostics: dict[str, Any] = {"load_context": copy.deepcopy(self.raw)}
            if self.unavailable is not None:
                diagnostics["trace_unavailable"] = {"signal": self.unavailable}
            if self.incomplete is not None:
                diagnostics["trace_incomplete"] = self.incomplete
            return diagnostics
        return result

    def forward(self) -> dict[str, Any] | None:
        if not self.forwardable or not isinstance(self.raw, dict):
            return None
        correlation_id = self.raw.get("correlation_id")
        if not isinstance(correlation_id, str) or not correlation_id:
            return None
        return copy.deepcopy(self.raw)


class _Span:
    def __init__(
        self,
        state: _TraceState,
        operation: str,
        parent_span_id: str | None,
        road: str,
        source_state: str,
        cache_state: str,
    ):
        self.state = state
        self.operation = operation
        self.span_id = str(uuid.uuid4())
        self.invocation_id = self.span_id
        self.parent_span_id = parent_span_id
        self.road = road
        self.source_state = source_state
        self.cache_state = cache_state
        self.started_at_utc = _utc_now()
        try:
            self.started_ns: int | None = time.perf_counter_ns()
        except Exception:
            self.started_ns = None
        self.outcome = "ok"

    def fail(self) -> None:
        self.outcome = "failed"

    def finish(self) -> None:
        returned_at = _utc_now()
        elapsed_ms: int | None = None
        timing_ok = False
        timing_signal: str | None = None
        if self.started_ns is not None:
            try:
                elapsed_ns = time.perf_counter_ns() - self.started_ns
                if elapsed_ns >= 0:
                    elapsed_ms = elapsed_ns // 1_000_000
                    timing_ok = True
                else:
                    timing_signal = "monotonic-clock-negative"
            except Exception:
                timing_signal = "monotonic-clock-unavailable"
        else:
            timing_signal = "monotonic-clock-unavailable"
        stamp = {
            "namespace": STAFF_NAMESPACE,
            "hop": "agathodaimon",
            "span_id": self.span_id,
            "invocation_id": self.invocation_id,
            "parent_span_id": self.parent_span_id,
            "operation": self.operation,
            "received_at_utc": self.started_at_utc,
            "returned_at_utc": returned_at,
            "at_utc": returned_at,
            "build_identity": {
                "component": "agathodaimon",
                "runtime": f"{platform.python_implementation()} {platform.python_version()}",
                "source_revision": "unknown",
            },
            "outcome": self.outcome,
            "road": self.road,
            "source_state": self.source_state,
            "cache_state": self.cache_state,
            "staff_instrumented": True,
        }
        if timing_ok:
            stamp["benchmark"] = {
                "schema": BENCHMARK_SCHEMA,
                "timings": [{
                    "locus": self.operation,
                    "elapsed_ms": elapsed_ms,
                    "ok": bool(self.outcome == "ok"),
                }],
            }
        else:
            stamp["benchmark"] = None
            stamp["timing_observation"] = {
                "locus": self.operation,
                "elapsed_ms": None,
                "availability": "unknown",
                "signal": timing_signal,
            }
        self.state.add_stamp(stamp)


class InvocationHandle:
    """One transient invocation and its sole raw load-context carrier."""

    def __init__(self, raw_context: Any, benchmark: bool, trace_present: bool):
        self.benchmark_context = {"timings": []} if benchmark else None
        self.state: _TraceState | None = None
        self.root: _Span | None = None
        self.outcome = "ok"
        self.raw_context = raw_context
        self.trace_unavailable_signal: str | None = None
        if trace_present:
            try:
                if _valid_context(raw_context):
                    limits, unavailable = _load_limits()
                else:
                    limits, unavailable = {}, "load-trace-context-invalid"
                self.state = _TraceState(raw_context, limits, unavailable)
                if self.state.unavailable is None:
                    self.root = _Span(
                        self.state,
                        "agathodaimon.staff.operation",
                        self.state.root_parent,
                        "staff",
                        "staff-process",
                        "not-applicable",
                    )
                    self._add_boot_stamp()
                elif self.benchmark_context is not None:
                    self.benchmark_context["timings"].append(_benchmark_boot_entry())
            except Exception:
                self.root = None
                self.trace_unavailable_signal = "load-trace-instrumentation-unavailable"
                if self.state is not None:
                    self.state.unavailable = self.trace_unavailable_signal
                if self.benchmark_context is not None and not self.benchmark_context["timings"]:
                    self.benchmark_context["timings"].append(_benchmark_boot_entry())
        elif self.benchmark_context is not None:
            self.benchmark_context["timings"].append(_benchmark_boot_entry())

    def _add_boot_stamp(self) -> None:
        if self.state is None or self.root is None:
            return
        elapsed_ms, measured = _process_boot_elapsed_ms()
        returned_at = _utc_now()
        received_at = returned_at
        if measured:
            try:
                received_at = (
                    datetime.now(timezone.utc) - timedelta(milliseconds=elapsed_ms)
                ).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            except (OverflowError, ValueError):
                measured = False
        row: dict[str, Any] = {
            "locus": "staff.boot",
            "elapsed_ms": elapsed_ms if measured else None,
            "ok": bool(measured),
        }
        if not measured:
            row["availability"] = "unknown"
            row["signal"] = "process-boot-time-unavailable"
        boot = {
            "namespace": STAFF_NAMESPACE,
            "hop": "agathodaimon",
            "span_id": str(uuid.uuid4()),
            "invocation_id": None,
            "parent_span_id": self.state.root_parent,
            "operation": "agathodaimon.staff.boot",
            "received_at_utc": received_at,
            "returned_at_utc": returned_at,
            "at_utc": returned_at,
            "build_identity": {
                "component": "agathodaimon",
                "runtime": f"{platform.python_implementation()} {platform.python_version()}",
                "source_revision": "unknown",
            },
            "outcome": "ok" if measured else "unknown",
            "road": "staff",
            "source_state": "process-start",
            "cache_state": "not-applicable",
            "staff_instrumented": True,
        }
        if measured:
            boot["benchmark"] = {"schema": BENCHMARK_SCHEMA, "timings": [row]}
        else:
            boot["benchmark"] = None
            boot["timing_observation"] = {
                "locus": "staff.boot",
                "elapsed_ms": None,
                "availability": "unknown",
                "signal": "process-boot-time-unavailable",
            }
        boot["invocation_id"] = boot["span_id"]
        self.state.add_stamp(boot)
        if self.benchmark_context is not None:
            self.benchmark_context["timings"].append(_benchmark_boot_entry())

    def set_outcome(self, outcome: str) -> None:
        self.outcome = "ok" if outcome == "ok" else "failed"
        if self.root is not None:
            self.root.outcome = self.outcome

    def response_context(self) -> Any:
        if self.state is None:
            if self.trace_unavailable_signal is None:
                return None
            if isinstance(self.raw_context, Mapping):
                result = dict(self.raw_context)
                result["trace_unavailable"] = {"signal": self.trace_unavailable_signal}
                if _serialized_size_bounded(result, MAX_CONTEXT_BYTES) is None:
                    return {
                        "load_context": dict(self.raw_context),
                        "trace_unavailable": {"signal": self.trace_unavailable_signal},
                    }
                return result
            return {"trace_unavailable": {"signal": self.trace_unavailable_signal}}
        try:
            return self.state.response()
        except Exception:
            self.mark_incomplete("load-trace-reply-enrichment-unavailable")
            return {"trace_unavailable": {"signal": "load-trace-reply-enrichment-unavailable"}}

    def mark_incomplete(self, signal: str) -> None:
        if self.state is not None:
            self.state._mark_incomplete(signal)

    def benchmark_report(self) -> dict[str, Any] | None:
        if self.benchmark_context is None:
            return None
        return {
            "schema": BENCHMARK_SCHEMA,
            "timings": [dict(row) for row in self.benchmark_context["timings"]],
        }

    def finish(self) -> None:
        if self.root is not None:
            self.root.outcome = self.outcome
            try:
                self.root.finish()
            except Exception:
                self.mark_incomplete("load-trace-finalization-unavailable")


def _new_handle(raw_context: Any, benchmark: bool, trace_present: bool) -> InvocationHandle:
    return InvocationHandle(raw_context, benchmark, trace_present)


@contextmanager
def invocation(
    raw_context: Any = None,
    *,
    trace_present: bool = False,
    benchmark: bool = False,
    operation: str = "agathodaimon.staff.operation",
) -> Iterator[InvocationHandle | None]:
    """Scope one complete invocation; nested CLI/face scopes borrow it unchanged."""
    current = _ACTIVE.get()
    if current is not None:
        yield current
        return
    if not trace_present and not benchmark:
        yield None
        return
    handle = _new_handle(raw_context, benchmark, trace_present)
    if handle.root is not None:
        handle.root.operation = operation
    active_token = _ACTIVE.set(handle)
    span_token = _ACTIVE_SPAN.set(handle.root.span_id if handle.root is not None else None)
    benchmark_token = BENCHMARK_CONTEXT.set(handle.benchmark_context) if handle.benchmark_context is not None else None
    try:
        yield handle
    except BaseException:
        handle.set_outcome("failed")
        handle.finish()
        raise
    else:
        handle.finish()
    finally:
        try:
            if handle.benchmark_context is not None:
                handle.benchmark_context["timings"].clear()
        finally:
            try:
                if benchmark_token is not None:
                    BENCHMARK_CONTEXT.reset(benchmark_token)
            finally:
                try:
                    _ACTIVE_SPAN.reset(span_token)
                finally:
                    _ACTIVE.reset(active_token)


@contextmanager
def span(
    operation: str,
    *,
    road: str = "staff",
    source_state: str = "staff-work",
    cache_state: str = "not-applicable",
) -> Iterator[_Span | None]:
    """Record one actual bounded stage only inside a valid active load context."""
    handle = _ACTIVE.get()
    if handle is None or handle.state is None or handle.state.unavailable is not None:
        yield None
        return
    parent = _ACTIVE_SPAN.get() or handle.root.span_id if handle.root is not None else None
    try:
        stage = _Span(handle.state, operation, parent, road, source_state, cache_state)
    except Exception:
        handle.mark_incomplete("load-trace-span-unavailable")
        yield None
        return
    token = _ACTIVE_SPAN.set(stage.span_id)
    try:
        yield stage
    except BaseException:
        stage.fail()
        raise
    finally:
        _ACTIVE_SPAN.reset(token)
        try:
            stage.finish()
        except Exception:
            handle.mark_incomplete("load-trace-span-finalization-unavailable")


def response_context() -> Any:
    handle = _ACTIVE.get()
    return handle.response_context() if handle is not None else None


def context_active() -> bool:
    """Report only whether this transaction has an active optional context."""
    handle = _ACTIVE.get()
    return handle is not None and handle.state is not None


def _attach_context_value(value: dict[str, Any], context: Any) -> dict[str, Any]:
    result = dict(value)
    if (
        isinstance(context, Mapping)
        and "schema" not in context
        and "load_context" in context
        and set(context).issubset({"load_context", "trace_unavailable", "trace_incomplete"})
    ):
        raw_context = context["load_context"]
        if "load_context" in result:
            result["load_context"] = _merge_contexts(result["load_context"], raw_context)
        else:
            result["load_context"] = copy.deepcopy(raw_context)
        for key in ("trace_unavailable", "trace_incomplete"):
            if key in context:
                result.setdefault(key, copy.deepcopy(context[key]))
        return result
    if _diagnostic_only_context(context):
        for key in ("trace_unavailable", "trace_incomplete"):
            if key in context:
                result.setdefault(key, copy.deepcopy(context[key]))
        return result
    if "load_context" in result:
        result["load_context"] = _merge_contexts(result["load_context"], context)
    else:
        result["load_context"] = copy.deepcopy(context)
    return result


def attach_context(value: Any, explicit_context: Any = None) -> Any:
    """Add the active reply carrier without touching raw_envelope or typed fields."""
    if not isinstance(value, dict):
        return value
    try:
        context = response_context()
        if context is None:
            context = explicit_context
        if context is None:
            return value
        return _attach_context_value(value, context)
    except Exception:
        handle = _ACTIVE.get()
        if handle is not None:
            handle.mark_incomplete("load-trace-reply-enrichment-unavailable")
        return value


def _returned_context(reply: Any) -> Any:
    if not isinstance(reply, Mapping):
        return None
    for container in (reply, reply.get("payload")):
        if not isinstance(container, Mapping):
            continue
        if "load_context" in container:
            return container["load_context"]
        for envelope_key in ("envelope",):
            envelope = container.get(envelope_key)
            if isinstance(envelope, Mapping):
                flags = envelope.get("flags")
                if isinstance(flags, Mapping) and "load_context" in flags:
                    return flags["load_context"]
        flags = container.get("flags")
        if isinstance(flags, Mapping) and "load_context" in flags:
            return flags["load_context"]
    return None


def merge_reply_context(reply: Any) -> bool:
    """Merge a whole loopback reply's context before its business projection."""
    handle = _ACTIVE.get()
    if handle is None or handle.state is None:
        return False
    try:
        returned = _returned_context(reply)
        if returned is None:
            return False
        return handle.state.merge_returned(returned)
    except Exception:
        handle.mark_incomplete("load-trace-returned-context-unavailable")
        return False


def loopback_headers() -> dict[str, str]:
    """Encode the current raw context for the Caduceus HTTP round trip."""
    handle = _ACTIVE.get()
    if handle is None or handle.state is None:
        return {}
    try:
        context = handle.state.forward()
        if context is None:
            return {}
        correlation_id = context.get("correlation_id")
        if not isinstance(correlation_id, str) or not correlation_id:
            return {}
        correlation_bytes = correlation_id.encode("ascii")
        if len(correlation_bytes) > MAX_CORRELATION_BYTES or any(
            byte < 0x20 or byte > 0x7E for byte in correlation_bytes
        ):
            handle.mark_incomplete("load-trace-correlation-header-unavailable")
            return {}
        encoded = base64.urlsafe_b64encode(_compact(context)).decode("ascii").rstrip("=")
    except Exception:
        handle.mark_incomplete("load-trace-context-serialization-failed")
        return {}
    return {
        "X-Correlation-Id": correlation_id,
        "X-Alkahest-Context": encoded,
    }


class _BoundedTextCapture:
    """Transaction-only JSON output adapter with pass-through after its hard cap."""

    def __init__(self, downstream: Any, limit: int = CLI_REPLY_MAX_BYTES):
        self.downstream = downstream
        self.limit = limit
        self.parts: list[str] = []
        self.size = 0
        self.overflow = False
        self.encoding = getattr(downstream, "encoding", "utf-8")
        self.errors = getattr(downstream, "errors", "strict")

    def write(self, value: str) -> int:
        text = str(value)
        if not text:
            return 0
        if self.overflow:
            return self.downstream.write(text)
        remaining = self.limit - self.size
        if len(text) > remaining:
            size = self.limit + 1
        else:
            size = len(text.encode("utf-8", "surrogatepass"))
        if self.size + size > self.limit:
            self.overflow = True
            buffered = "".join(self.parts)
            self.parts.clear()
            self.size = 0
            if buffered:
                self.downstream.write(buffered)
            return self.downstream.write(text)
        self.parts.append(text)
        self.size += size
        return len(text)

    def flush(self) -> None:
        if self.overflow:
            self.downstream.flush()

    def getvalue(self) -> str:
        return "" if self.overflow else "".join(self.parts)

    def isatty(self) -> bool:
        return bool(self.downstream.isatty())

    def fileno(self) -> int:
        return self.downstream.fileno()

    def writable(self) -> bool:
        return True


def _reply_failed(text: str) -> bool:
    """Observe only public outcome booleans; never retain a reply body in trace state."""
    try:
        value = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return isinstance(value, Mapping) and (value.get("ok") is False or value.get("converged") is False)


def _inject_context(text: str, context: Any) -> str:
    try:
        value = json.loads(text)
    except (TypeError, ValueError, json.JSONDecodeError):
        return text
    if not isinstance(value, dict):
        return text
    value = _attach_context_value(value, context)
    output = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return output + ("\n" if text.endswith(("\n", "\r")) else "")


def run_cli(envelope: Any, operation: str, callback: Callable[[], Any]) -> Any:
    """Scope imports+operation before returning one bounded, enriched CLI JSON reply."""
    present, raw_context = extract_load_context(envelope)
    if not present or _ACTIVE.get() is not None:
        return callback()
    downstream = sys.stdout
    capture = _BoundedTextCapture(downstream)
    sys_module = sys
    handle: InvocationHandle | None = None
    result: Any = None
    try:
        sys_module.stdout = capture
        with invocation(raw_context, trace_present=True, benchmark=benchmark_requested(envelope), operation=operation) as active:
            handle = active
            result = callback()
            if isinstance(result, int) and result != 0 and handle is not None:
                handle.set_outcome("failed")
    finally:
        sys_module.stdout = downstream
        if capture.overflow:
            if handle is not None:
                handle.mark_incomplete("load-trace-cli-reply-byte-limit")
        else:
            payload = capture.getvalue()
            if payload:
                try:
                    context = handle.response_context() if handle is not None else None
                    if context is not None:
                        payload = _inject_context(payload, context)
                except Exception:
                    if handle is not None:
                        handle.mark_incomplete("load-trace-reply-enrichment-unavailable")
                downstream.write(payload)
                downstream.flush()
        capture.parts.clear()
        capture.size = 0
    return result


def enrich_reply(value: Any) -> Any:
    """Reply adapter for standalone emitters; never starts or retains a trace."""
    return attach_context(value)

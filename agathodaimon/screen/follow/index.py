"""Run one owner-Sway screen-supervisor reconciliation pass."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import select
import signal
import subprocess
import sys
import time
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

_write_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    from agathodaimon._envelope import EnvelopeError, attach, read
    from agathodaimon.settings.display import backends
finally:
    sys.dont_write_bytecode = _write_bytecode

PROFILE_PATH = Path("/etc/appliance/profile.json")
DRM_ROOT = Path("/sys/class/drm")
HDMI_CONNECTOR = re.compile(r"^card[0-9]+-(HDMI-[A-Za-z0-9-]+)$")
OUTPUT_SUBSCRIPTION = '["output"]'


def _receipt(signal="none", *, observed=None, could_change_to=None, attempt=None,
             final_receipt=None, outputs_after=None, mutation_performed=False):
    ok = signal == "none"
    return {
        "ok": ok,
        "firstMissingSignal": signal,
        "mutationPerformed": mutation_performed,
        "observed": observed or {"connector": None, "sway": None},
        "could_change_to": could_change_to,
        "attempt": attempt or {"attempted": False, "commands": []},
        "final_receipt": final_receipt or {
            "ok": ok,
            "firstMissingSignal": signal,
            "mutationPerformed": mutation_performed,
        },
        "outputs_after": outputs_after,
    }


def _profile_follower():
    try:
        value = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    except OSError:
        return "none", "unavailable", "appliance-profile-unreadable"
    except (UnicodeError, ValueError):
        return "none", "invalid", "appliance-profile-invalid"
    if not isinstance(value, dict):
        return "none", "invalid", "appliance-profile-invalid"
    profile = value.get("profile")
    if not isinstance(profile, str) or not profile:
        return "none", "missing", "appliance-profile-missing"
    if profile == "homesi":
        return "sunshine", "homesi", None
    return "none", "other", None


def _read_hdmi_connectors():
    if not DRM_ROOT.is_dir():
        return {"ok": False, "connectors": [], "connected": []}, "hdmi-sysfs-unavailable"
    try:
        entries = list(DRM_ROOT.glob("card*-HDMI-*"))
        entries.sort(key=lambda path: path.name)
    except OSError:
        return {"ok": False, "connectors": [], "connected": []}, "hdmi-sysfs-unavailable"

    if not entries:
        return {"ok": False, "connectors": [], "connected": []}, "hdmi-connector-not-found"
    connectors = []
    for entry in entries:
        match = HDMI_CONNECTOR.fullmatch(entry.name)
        if match is None:
            continue
        try:
            status = (entry / "status").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            connectors.append({"name": match.group(1), "status": None})
            return {
                "ok": False,
                "connectors": connectors,
                "connected": sorted(item["name"] for item in connectors if item["status"] == "connected"),
            }, "hdmi-sysfs-status-unavailable"
        if status not in {"connected", "disconnected"}:
            connectors.append({"name": match.group(1), "status": status})
            return {
                "ok": False,
                "connectors": connectors,
                "connected": sorted(item["name"] for item in connectors if item["status"] == "connected"),
            }, "hdmi-sysfs-status-invalid"
        connectors.append({"name": match.group(1), "status": status})
    return {
        "ok": True,
        "connectors": connectors,
        "connected": sorted({item["name"] for item in connectors if item["status"] == "connected"}),
    }, None


def _supervisor_path():
    return Path(__file__).resolve().parents[2] / "screen-supervisor" / "sway-seat-screen-supervisor"


def _load_supervisor():
    path = _supervisor_path()
    loader = SourceFileLoader("agathodaimon_screen_follow_supervisor", str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise ImportError("screen-supervisor-loader-unavailable")
    module = importlib.util.module_from_spec(spec)
    write_bytecode = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = write_bytecode
    return module


def _observe_sway(supervisor):
    try:
        outputs = supervisor.get_outputs()
        physical = supervisor.physical_outputs(outputs)
    except (OSError, RuntimeError, ValueError, TypeError, subprocess.SubprocessError) as error:
        return {"ok": False, "outputs": None, "physical_outputs": None}, (
            "sway-output-observation-failed:" + type(error).__name__
        )
    return {
        "ok": True,
        "outputs": outputs,
        "physical_outputs": physical,
        "hdmi_outputs": sorted(
            item["name"] for item in physical
            if isinstance(item.get("name"), str) and item["name"].startswith("HDMI-")
        ),
    }, None


def _signals_mismatch(connector, sway):
    if not connector.get("ok") or not sway.get("ok"):
        return None
    return set(connector.get("connected", [])) != set(sway.get("hdmi_outputs", []))


def _target(supervisor, sway):
    if not sway.get("ok"):
        return None
    physical = supervisor.physical_outputs(sway["outputs"])
    return physical[0]["name"] if physical else supervisor.VIRTUAL_OUTPUT


def _argv_strings(argv):
    if isinstance(argv, (str, bytes, os.PathLike)):
        return [os.fsdecode(argv)]
    try:
        return [os.fsdecode(part) if isinstance(part, (bytes, os.PathLike)) else str(part) for part in argv]
    except TypeError:
        return [str(argv)]


def _is_mutation_command(argv, is_sway):
    if is_sway:
        command = argv[1].lstrip() if len(argv) > 1 else ""
        first = command.split(None, 1)[0] if command else ""
        return first in {"output", "workspace", "move", "focus"}
    if argv and Path(argv[0]).name == "systemctl":
        return any(item in {"restart", "start", "stop", "enable", "disable"} for item in argv[1:])
    return False


def _install_sway_run_wrapper(supervisor, socket, commands, capture):
    original_subprocess = supervisor.subprocess
    real_run = subprocess.run

    def wrapped_run(argv, *args, **kwargs):
        requested = _argv_strings(argv)
        is_sway = bool(requested and Path(requested[0]).name == "swaymsg")
        actual = argv
        if is_sway:
            actual, _runtime, _uid = backends._sway_argv(socket, requested[1:])
        elif requested and Path(requested[0]).name == "systemctl":
            from agathodaimon.settings._cmd import owner_session_command
            actual, environment = owner_session_command(["pactl"])
            actual = [*actual[:-1], *requested]
            if environment is not None:
                kwargs["env"] = environment
        actual_strings = _argv_strings(actual)
        entry = {
            "argv": actual_strings,
            "requested_argv": requested,
            "mutation": _is_mutation_command(requested, is_sway),
        }
        try:
            result = real_run(actual, *args, **kwargs)
        except Exception as error:
            entry["ok"] = False
            entry["returncode"] = getattr(error, "returncode", None)
            entry["error"] = type(error).__name__
            if capture[0]:
                commands.append(entry)
            raise
        entry["ok"] = result.returncode == 0
        entry["returncode"] = result.returncode
        if capture[0]:
            commands.append(entry)
        return result

    supervisor.subprocess = SimpleNamespace(
        run=wrapped_run,
        Popen=subprocess.Popen,
        DEVNULL=subprocess.DEVNULL,
        PIPE=subprocess.PIPE,
        SubprocessError=subprocess.SubprocessError,
        TimeoutExpired=subprocess.TimeoutExpired,
    )
    return original_subprocess


def _wait_for_output_event(socket):
    argv, _runtime, _uid = backends._sway_argv(
        socket, ["-m", "-t", "subscribe", OUTPUT_SUBSCRIPTION]
    )
    result = {
        "attempted": True,
        "argv": _argv_strings(argv),
        "event_received": False,
        "timed_out": False,
        "signal": None,
    }
    process = None
    try:
        started = time.monotonic()
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        if process.stdout is None:
            result["signal"] = "sway-output-subscription-no-stdout"
        else:
            remaining = max(0.0, 5.0 - (time.monotonic() - started))
            readable, _, _ = select.select([process.stdout], [], [], remaining)
            if readable:
                line = os.read(process.stdout.fileno(), 4096)
                result["event_received"] = bool(line)
                if not line:
                    result["signal"] = "sway-output-subscription-ended"
            else:
                result["timed_out"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        result["signal"] = "sway-output-subscription-failed:" + type(error).__name__
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                result["signal"] = result["signal"] or "sway-output-subscription-stop-timeout"
            if process.stdout is not None:
                process.stdout.close()
    return result


def _configured_environment(socket, runtime, follower):
    names = ("SWAYSOCK", "XDG_RUNTIME_DIR", "SCREEN_SUPERVISOR_FOLLOWER")
    prior = {name: os.environ.get(name) for name in names}
    os.environ["SWAYSOCK"] = socket
    os.environ["XDG_RUNTIME_DIR"] = runtime
    os.environ["SCREEN_SUPERVISOR_FOLLOWER"] = follower
    return prior


def _restore_environment(prior):
    for name, value in prior.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _add_signal(signals, signal):
    if isinstance(signal, str) and signal and signal not in signals:
        signals.append(signal)


def _run(dry_run):
    selected = backends.select_backend()
    if not isinstance(selected, dict) or selected.get("kind") != "sway":
        return _receipt("sway-session-unavailable")
    socket = selected.get("socket")
    if not isinstance(socket, str) or not socket:
        return _receipt("sway-socket-unavailable")
    try:
        _argv, runtime, _uid = backends._sway_argv(socket, [])
    except (OSError, KeyError, TypeError, ValueError) as error:
        return _receipt("sway-owner-environment-unavailable:" + type(error).__name__)
    if not isinstance(runtime, str) or not runtime:
        return _receipt("sway-owner-runtime-unavailable")

    follower, profile_state, profile_signal = _profile_follower()
    if profile_signal:
        return _receipt(profile_signal, observed={"connector": None, "sway": None, "profile": profile_state})
    prior_environment = _configured_environment(socket, runtime, follower)
    signals = []
    _add_signal(signals, profile_signal)
    try:
        try:
            supervisor = _load_supervisor()
        except (OSError, ImportError, ValueError) as error:
            _add_signal(signals, "screen-supervisor-load-failed:" + type(error).__name__)
            signal = signals[0] if signals else "screen-supervisor-load-failed"
            return _receipt(
                signal,
                observed={"connector": None, "sway": None, "profile": profile_state},
                could_change_to={"follower": follower},
            )

        commands = []
        capture = [False]
        original_subprocess = _install_sway_run_wrapper(supervisor, socket, commands, capture)
        connector_before, connector_signal = _read_hdmi_connectors()
        sway_before, sway_signal = _observe_sway(supervisor)
        _add_signal(signals, connector_signal)
        _add_signal(signals, sway_signal)
        observed = {
            "connector": connector_before,
            "sway": sway_before,
            "profile": profile_state,
        }
        initial_target = _target(supervisor, sway_before)
        could_change_to = {"target": initial_target, "follower": follower}

        if not connector_before.get("ok") or not sway_before.get("ok"):
            signal = signals[0] if signals else "screen-observation-unavailable"
            return _receipt(
                signal,
                observed=observed,
                could_change_to=could_change_to,
                final_receipt={"ok": False, "firstMissingSignal": signal, "mutationPerformed": False},
            )

        initial_mismatch = _signals_mismatch(connector_before, sway_before)
        if dry_run:
            signal = signals[0] if signals else "none"
            return _receipt(
                signal,
                observed=observed,
                could_change_to={**could_change_to, "hdmi_matches_sway": not initial_mismatch},
                attempt={"attempted": False, "dry_run": True, "commands": []},
                final_receipt={
                    "ok": signal == "none",
                    "firstMissingSignal": signal,
                    "mutationPerformed": False,
                    "dry_run": True,
                    "target": initial_target,
                },
                outputs_after=sway_before["outputs"],
            )

        wait = {"attempted": False, "event_received": False, "timed_out": False, "signal": None}
        current_connector = connector_before
        current_sway = sway_before
        if initial_mismatch:
            wait = _wait_for_output_event(socket)
            connector_after_wait, connector_wait_signal = _read_hdmi_connectors()
            sway_after_wait, sway_wait_signal = _observe_sway(supervisor)
            _add_signal(signals, wait.get("signal"))
            _add_signal(signals, connector_wait_signal)
            _add_signal(signals, sway_wait_signal)
            if connector_after_wait.get("ok"):
                current_connector = connector_after_wait
            if sway_after_wait.get("ok"):
                current_sway = sway_after_wait
            observed["after_wait"] = {
                "connector": connector_after_wait,
                "sway": sway_after_wait,
            }
            if not connector_after_wait.get("ok") or not sway_after_wait.get("ok") or _signals_mismatch(current_connector, current_sway):
                _add_signal(signals, "hdmi-sway-outputs-mismatch-after-subscription")
                signal = signals[0]
                return _receipt(
                    signal, observed=observed, could_change_to=could_change_to,
                    attempt={"attempted": False, "commands": [], "output_subscription": wait},
                    final_receipt={"ok": False, "firstMissingSignal": signal, "mutationPerformed": False},
                    outputs_after=current_sway.get("outputs"),
                )
            could_change_to = {
                "target": _target(supervisor, current_sway),
                "follower": follower,
            }

        reported_errors = []

        def capture_supervisor_error(message):
            if message != getattr(supervisor, "last_error", None):
                reported_errors.append(str(message))
                setattr(supervisor, "last_error", message)

        setattr(supervisor, "report_error", capture_supervisor_error)
        reconcile_error = None
        try:
            capture[0] = True
            supervisor.reconcile()
        except Exception as error:
            reconcile_error = "screen-reconcile-failed:" + type(error).__name__
        finally:
            capture[0] = False

        outputs_after = None
        sway_after_signal = None
        connector_after = None
        connector_after_signal = None
        try:
            sway_after, sway_after_signal = _observe_sway(supervisor)
            outputs_after = sway_after.get("outputs") if sway_after.get("ok") else None
            connector_after, connector_after_signal = _read_hdmi_connectors()
        finally:
            setattr(supervisor, "subprocess", original_subprocess)

        _add_signal(signals, reconcile_error)
        _add_signal(signals, sway_after_signal)
        _add_signal(signals, connector_after_signal)
        for message in reported_errors:
            _add_signal(signals, "supervisor-error:" + message)

        target_after = supervisor.selected_physical_output or supervisor.VIRTUAL_OUTPUT
        mutation_performed = any(
            command.get("mutation") and command.get("returncode") is not None
            for command in commands
        )
        if outputs_after is not None:
            active = supervisor.active_names(outputs_after)
            if target_after not in active:
                _add_signal(signals, "target-output-not-active-after-reconcile")
            physical_after = {item["name"] for item in supervisor.physical_outputs(outputs_after)}
            if target_after != supervisor.VIRTUAL_OUTPUT and physical_after != {target_after}:
                _add_signal(signals, "physical-output-set-mismatch-after-reconcile")
            if target_after == supervisor.VIRTUAL_OUTPUT and physical_after:
                _add_signal(signals, "unexpected-physical-output-after-reconcile")

        signal = signals[0] if signals else "none"
        ok = signal == "none" and outputs_after is not None
        final_receipt = {
            "ok": ok,
            "firstMissingSignal": signal,
            "mutationPerformed": mutation_performed,
            "target": target_after,
            "supervisor_errors": reported_errors,
            "connector_after": connector_after,
        }
        attempt = {
            "attempted": True,
            "step": "reconcile",
            "commands": commands,
            "output_subscription": wait,
        }
        return _receipt(
            signal,
            observed=observed,
            could_change_to=could_change_to,
            attempt=attempt,
            final_receipt=final_receipt,
            outputs_after=outputs_after,
            mutation_performed=mutation_performed,
        )
    finally:
        _restore_environment(prior_environment)


def main(argv=None):
    request = None
    try:
        request = read(known_fields=("dry-run",))
        dry_run = request.payload.get("dry-run", False)
        if not isinstance(dry_run, bool):
            result = _receipt("dry-run-invalid")
        else:
            result = _run(dry_run)
        result = attach(result, request)
    except (EnvelopeError, ValueError, OSError, TypeError) as error:
        result = _receipt("screen-follow-request-failed:" + type(error).__name__)
        if request is not None:
            result = attach(result, request)
    except Exception as error:
        result = _receipt("screen-follow-failed:" + type(error).__name__)
        if request is not None:
            result = attach(result, request)
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())

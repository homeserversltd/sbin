"""Restore HDMI sound routing after a connector change."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
from typing import Any

from agathodaimon._envelope import EnvelopeError, attach, read
from agathodaimon.settings._cmd import owner_session_command

HDMI_STATUS_ROOT = Path("/sys/class/drm")
HDMI_PROFILE_PREFIX = "output:hdmi-stereo"
PREFERRED_PROFILE = "output:hdmi-stereo+input:analog-stereo"


class FollowError(ValueError):
    def __init__(self, signal_name: str):
        super().__init__(signal_name)
        self.signal_name = signal_name


def _command_for_owner(argv: list[str], *, metadata: bool = False) -> tuple[list[str], dict[str, str] | None]:
    if not metadata:
        return owner_session_command(argv)
    # pw-metadata is not in the desktop helper's tool allowlist. Reuse its
    # owner wrapper and environment so this metadata read addresses the same
    # PipeWire session as pactl.
    pactl_argv, environment = owner_session_command(["pactl"])
    if environment is None:
        return argv, None
    return [*pactl_argv[:-1], *argv], environment


def _run_command(argv: list[str], *, timeout: float = 8.0, metadata: bool = False) -> subprocess.CompletedProcess[str]:
    command_argv, environment = _command_for_owner(argv, metadata=metadata)
    try:
        return subprocess.run(
            command_argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except subprocess.TimeoutExpired as error:
        raise FollowError("sound-command-timeout") from error
    except OSError as error:
        raise FollowError("sound-command-unavailable") from error


def _pactl_text(argv: list[str], signal_name: str) -> str:
    result = _run_command(argv)
    if result.returncode != 0:
        raise FollowError(signal_name)
    return (result.stdout or "").strip()


def _read_default_sink() -> str | None:
    text = _pactl_text(["pactl", "get-default-sink"], "pactl-default-sink-read-failed")
    return text or None


def _read_cards() -> list[dict[str, Any]]:
    text = _pactl_text(["pactl", "-f", "json", "list", "cards"], "pactl-cards-read-failed")
    try:
        value = json.loads(text)
    except (TypeError, ValueError) as error:
        raise FollowError("pactl-cards-json-invalid") from error
    if not isinstance(value, list) or not all(isinstance(card, dict) for card in value):
        raise FollowError("pactl-cards-json-invalid")
    return value


def _read_sinks() -> list[dict[str, Any]]:
    text = _pactl_text(["pactl", "-f", "json", "list", "sinks"], "pactl-sinks-read-failed")
    try:
        value = json.loads(text)
    except (TypeError, ValueError) as error:
        raise FollowError("pactl-sinks-json-invalid") from error
    if not isinstance(value, list) or not all(isinstance(sink, dict) for sink in value):
        raise FollowError("pactl-sinks-json-invalid")
    return value


def _read_configured_sink() -> str | None:
    result = _run_command(
        ["pw-metadata", "-n", "default", "0", "default.configured.audio.sink"],
        metadata=True,
    )
    if result.returncode != 0:
        raise FollowError("wireplumber-configured-sink-read-failed")
    text = result.stdout or ""
    key = "default.configured.audio.sink"
    line = next((candidate for candidate in text.splitlines() if key in candidate), None)
    if line is None:
        return None
    match = re.search(r"\bvalue:\s*(['\"])(.*?)\1", line)
    if match is None:
        match = re.search(r"\bvalue:\s*([^\s]+)", line)
    if match is None:
        raise FollowError("wireplumber-configured-sink-metadata-invalid")
    value = match.group(2) if match.lastindex == 2 else match.group(1)
    value = value.strip()
    if value.startswith(("{", '"')):
        try:
            decoded = json.loads(value)
        except ValueError as error:
            raise FollowError("wireplumber-configured-sink-metadata-invalid") from error
        if isinstance(decoded, dict):
            decoded = decoded.get("name")
        if not isinstance(decoded, str) or not decoded:
            raise FollowError("wireplumber-configured-sink-metadata-invalid")
        value = decoded
    if value in {"", "null", "None"}:
        return None
    return value


def _hdmi_statuses() -> list[dict[str, str]]:
    try:
        paths = sorted(HDMI_STATUS_ROOT.glob("*-HDMI-*/status"))
    except OSError as error:
        raise FollowError("hdmi-connector-status-unavailable") from error
    if not paths:
        raise FollowError("hdmi-connector-not-found")
    statuses = []
    for path in paths:
        try:
            status = path.read_text(encoding="utf-8").strip().lower()
        except (OSError, UnicodeError) as error:
            raise FollowError("hdmi-connector-status-unavailable") from error
        if status not in {"connected", "disconnected"}:
            raise FollowError("hdmi-connector-status-invalid")
        parent = path.parent.name
        connector = parent.split("-", 1)[1] if "-" in parent else parent
        statuses.append({"connector": connector, "status": status})
    return statuses


def _profile_items(card: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    profiles = card.get("profiles")
    if isinstance(profiles, dict):
        items = [(name, info) for name, info in profiles.items() if isinstance(name, str) and isinstance(info, dict)]
    elif isinstance(profiles, list):
        items = []
        for info in profiles:
            if not isinstance(info, dict):
                continue
            name = info.get("name")
            if isinstance(name, str):
                items.append((name, info))
    else:
        items = []
    return [(name, info) for name, info in items if name.startswith(HDMI_PROFILE_PREFIX)]


def _active_profile(card: dict[str, Any]) -> str | None:
    active = card.get("active_profile")
    if isinstance(active, dict):
        active = active.get("name")
    return active if isinstance(active, str) else None


def _profile_available(info: dict[str, Any]) -> bool:
    available = info.get("available")
    return available is True or (isinstance(available, str) and available.lower() == "yes")


def _profile_priority(info: dict[str, Any]) -> float:
    priority = info.get("priority")
    if isinstance(priority, bool) or not isinstance(priority, (int, float)):
        return 0.0
    return float(priority)


def _best_profile(items: list[tuple[str, dict[str, Any]]]) -> tuple[str, dict[str, Any]] | None:
    if not items:
        return None
    return sorted(
        items,
        key=lambda item: (
            _profile_priority(item[1]),
            item[0] == PREFERRED_PROFILE,
            item[0],
        ),
        reverse=True,
    )[0]


def _profile_choice(card: dict[str, Any]) -> tuple[tuple[str, dict[str, Any]] | None, bool]:
    profiles = _profile_items(card)
    available = [item for item in profiles if _profile_available(item[1])]
    return _best_profile(available) or _best_profile(profiles), bool(available)


def _card_index(card: dict[str, Any]) -> str:
    index = card.get("index")
    return str(index) if isinstance(index, (str, int)) and not isinstance(index, bool) else ""


def _card_name(card: dict[str, Any]) -> str:
    name = card.get("name")
    return name if isinstance(name, str) else ""


def _card_rank(card: dict[str, Any]) -> tuple[Any, ...]:
    profiles = _profile_items(card)
    choice, available = _profile_choice(card)
    active = _active_profile(card)
    index = _card_index(card)
    try:
        stable_index = -int(index)
    except ValueError:
        stable_index = 0
    return (
        active is not None and active.startswith("output:hdmi-"),
        available,
        _profile_priority(choice[1]) if choice is not None else 0.0,
        choice is not None and choice[0] == PREFERRED_PROFILE,
        stable_index,
        _card_name(card),
        bool(profiles),
    )


def _choose_card(cards: list[dict[str, Any]]) -> dict[str, Any] | None:
    candidates = [card for card in cards if _profile_items(card)]
    if not candidates:
        return None
    return sorted(candidates, key=_card_rank, reverse=True)[0]


def _card_identity(card: dict[str, Any]) -> dict[str, Any]:
    return {"name": _card_name(card) or None, "index": card.get("index")}


def _card_selector(card: dict[str, Any]) -> str | None:
    return _card_name(card) or (_card_index(card) or None)


def _find_card(cards: list[dict[str, Any]], identity: dict[str, Any]) -> dict[str, Any] | None:
    index = identity.get("index")
    name = identity.get("name")
    if index is not None:
        match = next((card for card in cards if str(card.get("index")) == str(index)), None)
        if match is not None:
            return match
    if isinstance(name, str):
        return next((card for card in cards if card.get("name") == name), None)
    return None


def _read_card_change() -> str:
    # grep parks on the subscription pipe and exits at the first card change;
    # unrelated server events do not consume the one permitted wait.
    command_argv, environment = _command_for_owner(["pactl"])
    command_argv = [*command_argv[:-1], "sh", "-c", "stdbuf -oL pactl subscribe | grep --line-buffered -m 1 -E \"^Event 'change' on card #[0-9]+$\""]
    process = None
    try:
        process = subprocess.Popen(
            command_argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=environment,
            start_new_session=True,
        )
        if process.stdout is None:
            return "pactl-subscribe-unavailable"
        ready, _, _ = select.select([process.stdout], [], [], 5.0)
        if not ready:
            return "pactl-card-change-timeout"
        event = os.read(process.stdout.fileno(), 4096).decode("utf-8", "replace")
        if not event:
            return "pactl-subscribe-exited"
        if re.match(r"^\s*Event 'change' on card #\d+\s*$", event):
            return "pactl-card-change-observed"
        return "pactl-card-change-not-observed"
    except (OSError, ValueError, TypeError):
        return "pactl-subscribe-unavailable"
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait()
            except OSError:
                pass
            if process.stdout is not None:
                process.stdout.close()


def _read_sinks_for_card(sinks: list[dict[str, Any]], card: dict[str, Any]) -> list[dict[str, Any]]:
    card_index = _card_index(card)
    card_name = _card_name(card)
    same_card = [
        sink for sink in sinks
        if (card_index and str(sink.get("card")) == card_index)
        or (card_name and sink.get("card") == card_name)
    ]
    named_hdmi = [
        sink for sink in same_card
        if "hdmi" in " ".join(
            [
                str(sink.get("name", "")),
                str(sink.get("description", "")),
                str(sink.get("active_port", "")),
                json.dumps(sink.get("properties", {}), sort_keys=True),
            ]
        ).lower()
    ]
    return sorted(named_hdmi, key=lambda sink: str(sink.get("name", "")))


def _sink_name(sink: dict[str, Any] | None) -> str | None:
    name = sink.get("name") if isinstance(sink, dict) else None
    return name if isinstance(name, str) and name else None


def _target_sink(
    sinks: list[dict[str, Any]], configured_pick: str | None, card: dict[str, Any]
) -> tuple[str | None, str]:
    available_names = {_sink_name(sink) for sink in sinks}
    if configured_pick and configured_pick in available_names:
        return configured_pick, "wireplumber-configured"
    hdmi_sink = next((_sink_name(sink) for sink in _read_sinks_for_card(sinks, card) if _sink_name(sink)), None)
    return hdmi_sink, "hdmi"


def _response(
    ok: bool,
    *,
    observed: dict[str, Any] | None,
    could_change_to: dict[str, Any] | None,
    attempt: dict[str, Any] | list[Any] | None,
    final_receipt: dict[str, Any],
    default_sink_after: str | None,
    first_missing: str | None = None,
    changed: bool = False,
    mutation_performed: bool = False,
    skipped: str | None = None,
) -> dict[str, Any]:
    result = {
        "ok": ok,
        "changed": changed,
        "mutationPerformed": mutation_performed,
        "observed": observed,
        "could_change_to": could_change_to,
        "attempt": attempt,
        "final_receipt": final_receipt,
        "default_sink_after": default_sink_after,
    }
    if first_missing is not None:
        result["firstMissingSignal"] = first_missing
    if skipped is not None:
        result["skipped"] = skipped
    return result


def _follow(request: Any) -> dict[str, Any]:
    dry_run = request.payload.get("dry-run", False)
    if not isinstance(dry_run, bool):
        return _response(
            False,
            observed=None,
            could_change_to=None,
            attempt=None,
            final_receipt={"ok": False, "firstMissingSignal": "sound-follow-dry-run-invalid"},
            default_sink_after=None,
            first_missing="sound-follow-dry-run-invalid",
        )

    observed: dict[str, Any] = {
        "connector": None,
        "connector_status": None,
        "card": None,
        "active_profile": None,
        "configured_pick": None,
        "default_sink_before": None,
        "connector_statuses": [],
    }
    could_change_to: dict[str, Any] | None = None
    attempt: dict[str, Any] = {
        "dry_run": dry_run,
        "card_change_wait": None,
        "profile": {"attempted": False, "card": None, "profile": None, "returncode": None},
        "default_sink": {"attempted": False, "target": None, "returncode": None},
    }
    default_sink_after = None
    changed = False
    mutation_performed = False
    active_after = None

    try:
        statuses = _hdmi_statuses()
        observed["connector_statuses"] = statuses
        connected = [row for row in statuses if row["status"] == "connected"]
        if not connected:
            return _response(
                True,
                observed=observed,
                could_change_to=None,
                attempt=attempt,
                final_receipt={"ok": True, "skipped": "hdmi-disconnected"},
                default_sink_after=None,
                skipped="hdmi-disconnected",
            )
        observed["connector"] = connected[0]["connector"]
        observed["connector_status"] = "connected"

        cards = _read_cards()
        card = _choose_card(cards)
        if card is None:
            raise FollowError("hdmi-stereo-card-not-found")
        initial_identity = _card_identity(card)
        observed["card"] = initial_identity
        observed["active_profile"] = _active_profile(card)

        default_before = _read_default_sink()
        observed["default_sink_before"] = default_before
        configured_pick = _read_configured_sink()
        observed["configured_pick"] = configured_pick

        profile_choice, profile_available = _profile_choice(card)
        active = _active_profile(card)
        if active is None or not active.startswith("output:hdmi-"):
            if profile_choice is None:
                raise FollowError("hdmi-stereo-profile-not-found")
            if not profile_available:
                wait_signal = _read_card_change()
                attempt["card_change_wait"] = {
                    "signal": wait_signal,
                    "timeout_seconds": 5,
                }
                cards = _read_cards()
                card = _choose_card(cards)
                if card is None:
                    raise FollowError("hdmi-stereo-card-not-found-after-wait")
                observed["card_after_wait"] = _card_identity(card)
                observed["active_profile_after_wait"] = _active_profile(card)
                profile_choice, profile_available = _profile_choice(card)
                active = _active_profile(card)
                if active is None or not active.startswith("output:hdmi-"):
                    if profile_choice is None:
                        raise FollowError("hdmi-stereo-profile-not-found-after-wait")
                    if not profile_available:
                        raise FollowError("hdmi-stereo-profile-unavailable-after-wait")

        if active is not None and active.startswith("output:hdmi-"):
            target_profile = active
        elif profile_choice is not None and profile_available:
            target_profile = profile_choice[0]
        else:
            raise FollowError("hdmi-stereo-profile-unavailable")

        card_selector = _card_selector(card)
        if card_selector is None:
            raise FollowError("hdmi-stereo-card-identity-missing")
        profile_change_needed = active is None or not active.startswith("output:hdmi-")
        attempt["profile"].update(card=_card_identity(card), profile=target_profile)

        if dry_run:
            sinks = _read_sinks()
            target_sink, target_source = _target_sink(sinks, configured_pick, card)
            attempt["default_sink"].update(target=target_sink, source=target_source)
            could_change_to = {
                "card": _card_identity(card),
                "profile": target_profile,
                "default_sink": target_sink,
                "default_sink_source": target_source,
                "sink_available_before_profile_change": target_sink is not None,
            }
            default_sink_after = _read_default_sink()
            return _response(
                True,
                observed=observed,
                could_change_to=could_change_to,
                attempt=attempt,
                final_receipt={
                    "ok": True,
                    "dry_run": True,
                    "profile_after": active,
                    "default_sink_after": default_sink_after,
                },
                default_sink_after=default_sink_after,
            )

        card_after = card
        if profile_change_needed:
            attempt["profile"]["attempted"] = True
            mutation_performed = True
            result = _run_command(["pactl", "set-card-profile", card_selector, target_profile])
            attempt["profile"]["returncode"] = result.returncode
            if result.returncode != 0:
                raise FollowError("pactl-set-card-profile-failed")
            cards_after = _read_cards()
            card_after = _find_card(cards_after, _card_identity(card))
            if card_after is None:
                raise FollowError("hdmi-card-profile-readback-missing")
            active_after = _active_profile(card_after)
            if active_after != target_profile:
                raise FollowError("hdmi-card-profile-readback-mismatch")
            changed = True
        else:
            active_after = active

        sinks = _read_sinks()
        target_sink, target_source = _target_sink(sinks, configured_pick, card_after)
        could_change_to = {
            "card": _card_identity(card_after),
            "profile": target_profile,
            "default_sink": target_sink,
            "default_sink_source": target_source,
        }
        if target_sink is None:
            raise FollowError("hdmi-sink-not-found")

        current_default = default_before
        if profile_change_needed:
            current_default = _read_default_sink()
            default_sink_after = current_default
        attempt["default_sink"].update(target=target_sink, source=target_source)
        if current_default != target_sink:
            attempt["default_sink"]["attempted"] = True
            mutation_performed = True
            default_sink_after = None
            result = _run_command(["pactl", "set-default-sink", target_sink])
            attempt["default_sink"]["returncode"] = result.returncode
            default_sink_after = _read_default_sink()
            if result.returncode != 0:
                raise FollowError("pactl-set-default-sink-failed")
        else:
            default_sink_after = _read_default_sink()
        if default_sink_after != target_sink:
            raise FollowError("default-sink-readback-mismatch")
        if current_default != target_sink:
            changed = True

        return _response(
            True,
            observed=observed,
            could_change_to=could_change_to,
            attempt=attempt,
            final_receipt={
                "ok": True,
                "profile_after": active_after,
                "default_sink_after": default_sink_after,
            },
            default_sink_after=default_sink_after,
            changed=changed,
            mutation_performed=mutation_performed,
        )
    except FollowError as error:
        return _response(
            False,
            observed=observed,
            could_change_to=could_change_to,
            attempt=attempt,
            final_receipt={"ok": False, "firstMissingSignal": error.signal_name},
            default_sink_after=default_sink_after,
            first_missing=error.signal_name,
            changed=changed,
            mutation_performed=mutation_performed,
        )
    except Exception:
        return _response(
            False,
            observed=observed,
            could_change_to=could_change_to,
            attempt=attempt,
            final_receipt={"ok": False, "firstMissingSignal": "sound-follow-failed"},
            default_sink_after=default_sink_after,
            first_missing="sound-follow-failed",
            changed=changed,
            mutation_performed=mutation_performed,
        )


def main(argv: list[str] | None = None) -> int:
    try:
        request = read(known_fields=("dry-run",))
        result = _follow(request)
        result = attach(result, request)
    except (EnvelopeError, ValueError) as error:
        signal_name = str(error) or "sound-follow-request-invalid"
        result = {
            "ok": False,
            "changed": False,
            "mutationPerformed": False,
            "observed": None,
            "could_change_to": None,
            "attempt": None,
            "final_receipt": {"ok": False, "firstMissingSignal": signal_name},
            "default_sink_after": None,
            "firstMissingSignal": signal_name,
        }
    print(json.dumps(result, sort_keys=True))
    return 0 if result.get("ok") else 1

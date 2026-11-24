"""Read the shared Caduceus seats from the body at launch."""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


_STAFF_SCHEMA = "caduceus.staff.v1"
SHARED_SEAT_IDS = (
    _STAFF_SCHEMA,
    "caduceus.staff.receipt.v1",
    "caduceus.chord.v1",
    "caduceus.chord.receipt.v1",
)


class ForeignSeat(ValueError):
    def __init__(self, seat_id: str, found: Any):
        self.seat_id = seat_id
        self.found = found
        super().__init__(seat_id)


def read_seats(folder: Path) -> dict[str, dict[str, Any]]:
    """Return each seat and its state; an unreadable seat is absent."""
    seats = {}
    for seat_id in SHARED_SEAT_IDS:
        try:
            seat = json.loads((folder / (seat_id + ".json")).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError, RecursionError):
            seat = None
        if not isinstance(seat, dict):
            seats[seat_id] = {"state": "absent", "schema_version": None, "seat": None}
            continue
        if seat.get("schema") != seat_id:
            raise ForeignSeat(seat_id, seat.get("schema"))
        seats[seat_id] = {"state": "loaded", "schema_version": seat.get("schema_version"), "seat": seat}
    return seats


class _ObjectPairs(list):
    """Keep duplicate members until their values have been decoded."""


@dataclass(frozen=True, slots=True)
class _IntentNumber:
    """A JSON number lexeme checked by the decoder; never round it to float."""

    literal: str


def dump_intent_projection(value: Any, *, separators: tuple[str, str] = (", ", ": ")) -> str:
    """Render projected help without narrowing Caduceus's arbitrary-precision numbers."""
    item_sep, key_sep = separators

    def encode(item: Any) -> str:
        if isinstance(item, _IntentNumber):
            return item.literal
        if isinstance(item, dict):
            return "{" + item_sep.join(json.dumps(key) + key_sep + encode(child)
                                       for key, child in item.items()) + "}"
        if isinstance(item, list):
            return "[" + item_sep.join(encode(child) for child in item) + "]"
        return json.dumps(item)

    return encode(value)


def _invalid_json_constant(value: str) -> None:
    raise ValueError("not a JSON constant: " + value)


def _intent_value(value: Any, depth: int = 0) -> Any:
    if isinstance(value, list):
        # serde_json's Value reader rejects the 128th nested container.
        if depth >= 127:
            raise ValueError("intent seat nesting limit")
        if isinstance(value, _ObjectPairs):
            return {_intent_value(key): _intent_value(child, depth + 1) for key, child in value}
        return [_intent_value(child, depth + 1) for child in value]
    if isinstance(value, str):
        # json.loads also accepts isolated escaped surrogates; serde_json doesn't.
        value.encode("utf-8")
    return value


def _read_intent_seat(name: str, directory_fd: int, intent: str) -> dict[str, Any] | None:
    try:
        intent.encode("utf-8")
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return None
            with os.fdopen(fd, encoding="utf-8", closefd=False) as file:
                seat = _intent_value(json.load(file, parse_constant=_invalid_json_constant,
                                               parse_int=_IntentNumber, parse_float=_IntentNumber,
                                               object_pairs_hook=_ObjectPairs))
        finally:
            os.close(fd)
    except (OSError, ValueError, RecursionError):
        return None
    if (isinstance(seat, dict) and seat.get("schema") == _STAFF_SCHEMA
            and isinstance(seat.get("intent"), str) and seat["intent"] == intent):
        return seat
    return None


@lru_cache(maxsize=1)
def read_intent_seats(folder: Path) -> tuple[dict[str, dict[str, Any]], list[str]] | None:
    """Load one process snapshot; None means there is no real intents directory."""
    root = folder / "intents"
    try:
        if not stat.S_ISDIR(root.lstat().st_mode):
            return None
    except OSError:
        return None

    seats = {}
    invalid = []
    try:
        for directory, _, names, directory_fd in os.fwalk(root, follow_symlinks=False):
            for name in names:
                path = Path(directory) / name
                if path.suffix != ".json":
                    continue
                try:
                    if not stat.S_ISREG(os.stat(name, dir_fd=directory_fd, follow_symlinks=False).st_mode):
                        continue
                except OSError:
                    continue
                intent = path.relative_to(root).with_suffix("").as_posix()
                seat = _read_intent_seat(name, directory_fd, intent)
                if seat is None:
                    invalid.append("intents/" + os.fsencode(intent).decode("utf-8", errors="replace"))
                else:
                    seats[intent] = seat
    except OSError:
        # An unreadable directory does not turn a seat census into a refusal.
        pass
    return seats, sorted(invalid)

"""Read the shared Caduceus seats from the body at launch."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


SHARED_SEAT_IDS = (
    "caduceus.staff.v1",
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

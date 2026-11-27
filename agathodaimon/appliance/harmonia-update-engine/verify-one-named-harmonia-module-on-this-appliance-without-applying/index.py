"""Execute only this Harmonia act through the shared band."""
from __future__ import annotations

from typing import Sequence

from agathodaimon._nidus import harmonia_band
from agathodaimon._nidus.harmonia_band import _HARMONIA, _IDENTIFIER, _PROFILE_INDEX


def _allowed_argv(command: list[str]) -> bool:
    return (len(command) == 5 and command[:2] == [_HARMONIA, "update-module"] and _PROFILE_INDEX.fullmatch(command[2]) is not None and command[3] == "--module" and _IDENTIFIER.fullmatch(command[4]) is not None)


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    return harmonia_band.main(_allowed_argv)

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SBIN_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Actuator:
    id: str
    family: str
    receipt_schema: str
    legacy_script: str
    launcher: str
    default_args: tuple[str, ...] = ()
    description: str = ""

    @property
    def legacy_path(self) -> Path:
        return SBIN_ROOT / self.legacy_script


ACTUATORS: dict[str, Actuator] = {
    "backblaze-recover": Actuator(
        id="backblaze-recover",
        family="backup",
        receipt_schema="caduceus.staff.backblaze.recover.v1",
        legacy_script="homeserver-backblaze-tab-b2-disaster-recovery.py",
        launcher="caduceus-backblaze-recover",
        description="Backblaze B2 disaster recovery membrane.",
    ),
    "forgejo-backup-b2": Actuator(
        id="forgejo-backup-b2",
        family="backup",
        receipt_schema="caduceus.staff.forgejo.backup_b2.v1",
        legacy_script="homeserver-forgejo-backup-to-b2.sh",
        launcher="caduceus-forgejo-backup-b2",
        description="Forgejo backup-to-B2 membrane.",
    ),
    "forgejo-migrate": Actuator(
        id="forgejo-migrate",
        family="backup",
        receipt_schema="caduceus.staff.forgejo.migrate.v1",
        legacy_script="homeserver-forgejo-migrate.py",
        launcher="caduceus-forgejo-migrate",
        description="Forgejo export/restore/migration membrane.",
    ),
    "calibre-helper": Actuator(
        id="calibre-helper",
        family="service",
        receipt_schema="caduceus.staff.calibre.helper.v1",
        legacy_script="calibreHelperDaemon.sh",
        launcher="caduceus-calibre-helper",
        default_args=("status", "system"),
        description="Calibre feeder/watcher service helper membrane.",
    ),
    "calibre-watch": Actuator(
        id="calibre-watch",
        family="service",
        receipt_schema="caduceus.staff.calibre.watch.v1",
        legacy_script="calibreSimpleWatcher.sh",
        launcher="caduceus-calibre-watch",
        description="Calibre upload watcher membrane.",
    ),
}


def list_actuators() -> Iterable[Actuator]:
    return ACTUATORS.values()


def get_actuator(actuator_id: str) -> Actuator:
    try:
        return ACTUATORS[actuator_id]
    except KeyError as exc:
        raise SystemExit(f"unknown actuator: {actuator_id}") from exc

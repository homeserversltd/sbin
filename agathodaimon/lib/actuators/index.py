from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


SBIN_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True)
class Actuator:
    id: str
    family: str
    receipt_schema: str
    legacy_script: str
    launcher: str
    default_args: tuple[str, ...] = ()
    cli_path: str = "/usr/local/sbin/agathodaimon/cli.py"
    cli_noun: str = ""
    cli_verbs: tuple[str, ...] = ()
    # legacy_script remains only as a custody reference, not a launcher. tuple[str, ...] = ()
    description: str = ""

    @property
    def legacy_path(self) -> Path:
        return SBIN_ROOT / self.legacy_script


ACTUATORS: dict[str, Actuator] = {
    "backblaze-recover": Actuator(
        id="backblaze-recover",
        family="backup",
        receipt_schema="caduceus.staff.backblaze.recover.v1",
        legacy_script="agathodaimon/storage/backup/homeserver-backblaze-tab-b2-disaster-recovery.py",
        launcher="", cli_path="/usr/local/sbin/agathodaimon/cli.py", cli_noun="backup", cli_verbs=("backblaze-config",),
        description="Backblaze B2 disaster recovery membrane.",
    ),
    "forgejo-backup-b2": Actuator(
        id="forgejo-backup-b2",
        family="backup",
        receipt_schema="caduceus.staff.forgejo.backup_b2.v1",
        legacy_script="agathodaimon/storage/backup/homeserver-forgejo-backup-to-b2.sh",
        launcher="", cli_path="/usr/local/sbin/agathodaimon/cli.py", cli_noun="storage", cli_verbs=("backup", "forgejo", "backup-b2"),
        description="Forgejo backup-to-B2 membrane.",
    ),
    "forgejo-migrate": Actuator(
        id="forgejo-migrate",
        family="backup",
        receipt_schema="caduceus.staff.forgejo.migrate.v1",
        legacy_script="agathodaimon/storage/backup/homeserver-forgejo-migrate.py",
        launcher="", cli_path="/usr/local/sbin/agathodaimon/cli.py", cli_noun="storage", cli_verbs=("backup", "forgejo", "migrate"),
        description="Forgejo export/restore/migration membrane.",
    ),
    "calibre-helper": Actuator(
        id="calibre-helper",
        family="service",
        receipt_schema="caduceus.staff.calibre.helper.v1",
        legacy_script="agathodaimon/portals/calibre/calibreHelperDaemon.sh",
        launcher="agathodaimon-calibre-helper",
        default_args=("status", "system"),
        description="Calibre feeder/watcher service helper membrane.",
    ),
    "calibre-watch": Actuator(
        id="calibre-watch",
        family="service",
        receipt_schema="caduceus.staff.calibre.watch.v1",
        legacy_script="agathodaimon/portals/calibre/calibreSimpleWatcher.sh",
        launcher="agathodaimon-calibre-watch",
        description="Calibre upload watcher membrane.",
    ),
}


READ_ACTUATORS: dict[str, Actuator] = {
}


WRITE_ACTUATORS: dict[str, Actuator] = {
}


def actuator_ids() -> set[str]:
    return set(ACTUATORS) | set(READ_ACTUATORS) | set(WRITE_ACTUATORS)

def list_actuators() -> Iterable[Actuator]:
    return ACTUATORS.values()


def get_actuator(actuator_id: str) -> Actuator:
    try:
        return ACTUATORS.get(actuator_id) or READ_ACTUATORS.get(actuator_id) or WRITE_ACTUATORS[actuator_id]
    except KeyError as exc:
        raise SystemExit(f"unknown actuator: {actuator_id}") from exc

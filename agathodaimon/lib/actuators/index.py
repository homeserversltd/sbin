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
        legacy_script="homeserver-backblaze-tab-b2-disaster-recovery.py",
        launcher="", cli_path="/usr/local/sbin/agathodaimon/cli.py", cli_noun="backup", cli_verbs=("backblaze-config",),
        description="Backblaze B2 disaster recovery membrane.",
    ),
    "forgejo-backup-b2": Actuator(
        id="forgejo-backup-b2",
        family="backup",
        receipt_schema="caduceus.staff.forgejo.backup_b2.v1",
        legacy_script="homeserver-forgejo-backup-to-b2.sh",
        launcher="", cli_path="/usr/local/sbin/agathodaimon/cli.py", cli_noun="forgejo", cli_verbs=("backup-b2",),
        description="Forgejo backup-to-B2 membrane.",
    ),
    "forgejo-migrate": Actuator(
        id="forgejo-migrate",
        family="backup",
        receipt_schema="caduceus.staff.forgejo.migrate.v1",
        legacy_script="homeserver-forgejo-migrate.py",
        launcher="", cli_path="/usr/local/sbin/agathodaimon/cli.py", cli_noun="forgejo", cli_verbs=("migrate",),
        description="Forgejo export/restore/migration membrane.",
    ),
    "calibre-helper": Actuator(
        id="calibre-helper",
        family="service",
        receipt_schema="caduceus.staff.calibre.helper.v1",
        legacy_script="calibreHelperDaemon.sh",
        launcher="agathodaimon-calibre-helper",
        default_args=("status", "system"),
        description="Calibre feeder/watcher service helper membrane.",
    ),
    "calibre-watch": Actuator(
        id="calibre-watch",
        family="service",
        receipt_schema="caduceus.staff.calibre.watch.v1",
        legacy_script="calibreSimpleWatcher.sh",
        launcher="agathodaimon-calibre-watch",
        description="Calibre upload watcher membrane.",
    ),
}


READ_ACTUATORS: dict[str, Actuator] = {
    "network.dhcp.status": Actuator("network.dhcp.status", "network", "caduceus.staff.network.dhcp.v1", "agathodaimon/cli.py", "network dhcp", ("status",), "Kea service and configuration readback."),
    "network.dhcp.leases": Actuator("network.dhcp.leases", "network", "caduceus.staff.network.dhcp.v1", "agathodaimon/cli.py", "network dhcp", ("leases",), "Active, MAC-normalized Kea leases."),
    "network.dhcp.reservations": Actuator("network.dhcp.reservations", "network", "caduceus.staff.network.dhcp.v1", "agathodaimon/cli.py", "network dhcp", ("reservations",), "Declared Kea reservations."),
    "network.dhcp.boundary": Actuator("network.dhcp.boundary", "network", "caduceus.staff.network.dhcp.v1", "agathodaimon/cli.py", "network dhcp", ("boundary",), "Loaded Kea reservation boundary."),
    "network.dns.read": Actuator("network.dns.read", "network", "caduceus.network.dns.v1", "agathodaimon/cli.py", "network dns", ("read",), "Owned Unbound record readback."),
    "network.dns.status": Actuator("network.dns.status", "network", "caduceus.network.dns.v1", "agathodaimon/cli.py", "network dns", ("status",), "Unbound owned include status."),
    "network.identity.device_list": Actuator("network.identity.device_list", "network", "caduceus.staff.network.identity.v1", "agathodaimon/cli.py", "network identity", ("device-list",), "MAC-keyed declared, observed, and DNS roster."),
}


WRITE_ACTUATORS: dict[str, Actuator] = {
    "network.dns.device_name.create": Actuator("network.dns.device_name.create", "network", "caduceus.network.dns.v1", "agathodaimon/cli.py", "network dns", ("device-name", "create"), "Owned paired Unbound A and PTR projection."),
    "network.dns.device_name.remove": Actuator("network.dns.device_name.remove", "network", "caduceus.network.dns.v1", "agathodaimon/cli.py", "network dns", ("device-name", "remove"), "Owned paired Unbound A and PTR removal."),
    "network.dns.alias.create": Actuator("network.dns.alias.create", "network", "caduceus.network.dns.v1", "agathodaimon/cli.py", "network dns", ("alias", "create"), "Owned DNS-only CNAME projection."),
    "network.dns.alias.remove": Actuator("network.dns.alias.remove", "network", "caduceus.network.dns.v1", "agathodaimon/cli.py", "network dns", ("alias", "remove"), "Owned DNS-only CNAME removal."),
    "network.identity.claim": Actuator("network.identity.claim", "network", "caduceus.staff.network.identity.v1", "agathodaimon/cli.py", "network identity", ("claim",), "Lock-held DHCP and DNS identity claim."),
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

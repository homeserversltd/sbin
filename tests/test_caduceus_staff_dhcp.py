from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from caduceus_staff.network.dhcp import DhcpError, DhcpManager


@pytest.fixture
def dhcp(tmp_path: Path) -> DhcpManager:
    fixtures = ROOT / "tests" / "fixtures" / "dhcp"
    config = tmp_path / "kea-dhcp4.conf"
    leases = tmp_path / "kea-leases4.csv"
    shutil.copyfile(fixtures / config.name, config)
    shutil.copyfile(fixtures / leases.name, leases)
    updater = tmp_path / "update.py"
    updater.write_text(
        "#!/usr/bin/python3\nimport os,shutil,sys\nshutil.copyfile(sys.argv[1], os.environ['CADUCEUS_DHCP_CONFIG'])\n",
        encoding="utf-8",
    )
    updater.chmod(0o755)
    os.environ["CADUCEUS_DHCP_CONFIG"] = str(config)
    return DhcpManager(config, leases, updater, now=lambda: 1_900_000_000)


def test_reads_config_reservations_leases_and_statistics(dhcp: DhcpManager) -> None:
    assert dhcp.get_config()["Dhcp4"]["subnet4"][0]["subnet"] == "192.168.123.0/24"
    assert dhcp.get_reservations()[0]["hostname"] == "alpha"
    assert dhcp.get_leases() == [{"ip-address": "192.168.123.56", "hw-address": "aa:bb:cc:dd:ee:02", "hostname": "beta-new", "expire": "2100000000", "state": "0"}]
    assert dhcp.get_current_boundary() == 48
    assert dhcp.get_statistics() == {"homeserver_ip": "192.168.123.1", "reservations_count": 1, "reservations_total": 48, "leases_count": 1, "leases_total": 201}


def test_add_update_and_remove_reservation_through_atomic_script(dhcp: DhcpManager) -> None:
    added = dhcp.add_reservation("AA-BB-CC-DD-EE-04", hostname="gamma")
    assert added["ip-address"] == "192.168.123.3"
    updated = dhcp.update_reservation_ip("aa:bb:cc:dd:ee:04", "192.168.123.4")
    assert updated["ip-address"] == "192.168.123.4"
    assert dhcp.remove_reservation("192.168.123.4") is True
    assert dhcp.remove_reservation("missing") is False


def test_pool_boundary_mutation_and_constraints(dhcp: DhcpManager) -> None:
    assert dhcp.update_pool_boundary(60)
    assert dhcp.get_current_boundary() == 60
    with pytest.raises(DhcpError, match="below current count"):
        dhcp.update_pool_boundary(0)


def test_duplicate_and_invalid_reservations_are_rejected(dhcp: DhcpManager) -> None:
    with pytest.raises(DhcpError, match="MAC address already exists"):
        dhcp.add_reservation("aa:bb:cc:dd:ee:01")
    with pytest.raises(DhcpError, match="invalid MAC"):
        dhcp.add_reservation("not-a-mac")


def test_cli_read_and_mutate_receipts(dhcp: DhcpManager) -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "CADUCEUS_DHCP_LEASES": str(dhcp.lease_db_path), "CADUCEUS_DHCP_UPDATE_SCRIPT": str(dhcp.update_script)}
    read = subprocess.run([sys.executable, "-m", "caduceus_staff.network.dhcp", "reservations"], cwd=ROOT, env=env, text=True, capture_output=True, check=True)
    assert json.loads(read.stdout)["result"][0]["hostname"] == "alpha"
    mutate = subprocess.run([str(ROOT / "caduceus-dhcp"), "add-reservation", "aa:bb:cc:dd:ee:05", "--hostname", "delta"], cwd=ROOT, env={**env, "CADUCEUS_STAFF_PYTHON": sys.executable}, text=True, capture_output=True, check=True)
    receipt = json.loads(mutate.stdout)
    assert receipt["ok"] and receipt["action"] == "add-reservation"

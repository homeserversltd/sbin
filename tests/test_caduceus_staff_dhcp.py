from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from agathodaimon.network.dhcp.index import DhcpError, DhcpManager


@pytest.fixture
def dhcp(tmp_path: Path):
    fixtures = ROOT / "tests" / "fixtures" / "dhcp"
    config = tmp_path / "kea-dhcp4.conf"
    shutil.copyfile(fixtures / config.name, config)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "payload": {"result": [{"ip-address": "192.168.123.56", "hw-address": "aa:bb:cc:dd:ee:02", "hostname": "beta-new", "expire": "2100000000", "state": "0"}]}}).encode())
        def log_message(self, format, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    appliance = tmp_path / "appliance.json"
    appliance.write_text(json.dumps({"caduceus": {"bind": f"0.0.0.0:{server.server_port}"}}), encoding="utf-8")
    os.environ["CADUCEUS_APPLIANCE_CONFIG"] = str(appliance)
    updater = tmp_path / "update.py"
    updater.write_text(
        "#!/usr/bin/python3\nimport os,shutil,sys\nshutil.copyfile(sys.argv[1], os.environ['CADUCEUS_DHCP_CONFIG'])\n",
        encoding="utf-8",
    )
    updater.chmod(0o755)
    os.environ["CADUCEUS_DHCP_CONFIG"] = str(config)
    manager = DhcpManager(config, updater, now=lambda: 1_900_000_000)
    yield manager
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def test_reads_config_reservations_leases_and_statistics(dhcp: DhcpManager) -> None:
    assert dhcp.get_config()["Dhcp4"]["subnet4"][0]["subnet"] == "192.168.123.0/24"
    assert dhcp.get_reservations()[0]["hostname"] == "alpha"
    assert dhcp.get_leases() == [{"ip-address": "192.168.123.56", "hw-address": "aa:bb:cc:dd:ee:02", "hostname": "beta-new", "expire": "2100000000", "state": "0"}]
    assert dhcp.get_current_boundary() == 48
    assert dhcp.get_statistics() == {"homeserver_ip": "192.168.123.1", "reservations_count": 1, "reservations_total": 48, "leases_count": 1, "leases_total": 201, "host_count": 2, "lease_ratio": 0.004975124378109453, "pool_boundary": [{"subnet": "192.168.123.0/24", "start": "192.168.123.1", "end": "192.168.123.49", "discovery": "loaded-kea-pool-boundary"}]}


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
    env = {**os.environ, "PYTHONPATH": str(ROOT), "CADUCEUS_APPLIANCE_CONFIG": str(dhcp.appliance_config_path), "CADUCEUS_DHCP_UPDATE_SCRIPT": str(dhcp.update_script)}
    read = subprocess.run([sys.executable, "agathodaimon/cli.py", "network", "dhcp", "statistics"], cwd=ROOT, env=env, text=True, capture_output=True, check=True)
    assert json.loads(read.stdout)["result"]["leases_count"] == 1
    boundary = subprocess.run([sys.executable, "agathodaimon/cli.py", "network", "dhcp", "boundary", "show"], cwd=ROOT, env=env, text=True, capture_output=True, check=True)
    boundary_receipt = json.loads(boundary.stdout)
    assert boundary_receipt["result"] == dhcp.boundary()
    assert boundary_receipt["active_leases_count"] == 1
    mutate = subprocess.run([sys.executable, str(ROOT / "agathodaimon" / "cli.py"), "network", "dhcp", "add-reservation", "aa:bb:cc:dd:ee:05", "--hostname", "delta"], cwd=ROOT, env={**env, "CADUCEUS_STAFF_PYTHON": sys.executable}, text=True, capture_output=True, check=True)
    receipt = json.loads(mutate.stdout)
    assert receipt["ok"] and receipt["action"] == "add-reservation"

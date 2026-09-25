from __future__ import annotations

import importlib.util
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

LEASE_ENVELOPE = {
    "actuatorId": "network.dhcp.leases",
    "command": "network dhcp leases",
    "firstMissingSignal": "none",
    "ok": True,
    "payload": {
        "action": "leases",
        "actuator": "network.dhcp.leases",
        "firstMissingSignal": "none",
        "mutationPerformed": False,
        "ok": True,
        "result": [
            {"hostname": "coltin-s-s25", "ip": "192.168.123.13", "last_activity": "1790377721", "mac": "3e:62:89:98:e6:84", "provenance": "observed"},
            {"hostname": "laptop-02", "ip": "192.168.123.21", "last_activity": "1790378655", "mac": "44:f7:9f:a3:d6:25", "provenance": "observed"},
        ],
        "schema": "caduceus.staff.network.dhcp.v1",
    },
    "schema": "caduceus.network.read.v1",
}


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
            self.wfile.write(json.dumps(getattr(self.server, "envelope")).encode())
        def log_message(self, format, *args):
            pass
    server = HTTPServer(("127.0.0.1", 0), Handler)
    setattr(server, "envelope", json.loads(json.dumps(LEASE_ENVELOPE)))
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
    setattr(manager, "_lease_server", server)
    yield manager
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def test_reads_config_reservations_leases_and_statistics(dhcp: DhcpManager, monkeypatch: pytest.MonkeyPatch) -> None:
    expected_internal = [
        {"ip-address": "192.168.123.13", "hw-address": "3e:62:89:98:e6:84", "hostname": "coltin-s-s25", "last_activity": "1790377721", "provenance": "observed"},
        {"ip-address": "192.168.123.21", "hw-address": "44:f7:9f:a3:d6:25", "hostname": "laptop-02", "last_activity": "1790378655", "provenance": "observed"},
    ]
    expected_projected = [
        {"mac": "3e:62:89:98:e6:84", "ip": "192.168.123.13", "hostname": "coltin-s-s25", "last_activity": "1790377721", "provenance": "observed"},
        {"mac": "44:f7:9f:a3:d6:25", "ip": "192.168.123.21", "hostname": "laptop-02", "last_activity": "1790378655", "provenance": "observed"},
    ]
    assert dhcp.get_config()["Dhcp4"]["subnet4"][0]["subnet"] == "192.168.123.0/24"
    assert dhcp.get_reservations()[0]["hostname"] == "alpha"
    assert dhcp.get_leases() == expected_internal
    assert dhcp.leases() == expected_projected
    assert dhcp.get_current_boundary() == 48
    statistics = dhcp.get_statistics()
    assert statistics["reservations_count"] == 1
    assert statistics["leases_count"] == 2
    assert statistics["host_count"] == 3
    assert statistics["leases_total"] == 201
    assert dhcp.boundary() == [{"subnet": "192.168.123.0/24", "start": "192.168.123.1", "end": "192.168.123.49", "discovery": "loaded-kea-pool-boundary"}]

    spec = importlib.util.spec_from_file_location("child_device_test_module", ROOT / "agathodaimon/network/child-device/index.py")
    assert spec and spec.loader
    child_device = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(child_device)
    monkeypatch.setattr(child_device, "_neighbors", lambda: ())
    assert child_device.observed() == [
        {"mac": row["mac"], "ip": row["ip"], "hostname": row["hostname"], "sources": ["kea-lease"]}
        for row in expected_projected
    ]


@pytest.mark.parametrize(
    ("row", "signal"),
    [
        ({"ip": "192.168.123.13", "hostname": "missing-mac", "last_activity": "1", "provenance": "observed"}, "missing-mac"),
        ({"mac": "3e:62:89:98:e6:84", "hostname": "missing-ip", "last_activity": "1", "provenance": "observed"}, "missing-ip"),
    ],
)
def test_missing_native_lease_identity_is_named_malformed(dhcp: DhcpManager, row: dict[str, str], signal: str) -> None:
    envelope = json.loads(json.dumps(LEASE_ENVELOPE))
    envelope["payload"]["result"] = [row]
    setattr(getattr(dhcp, "_lease_server"), "envelope", envelope)
    with pytest.raises(DhcpError, match=f"caduceus-leases-malformed:{signal}"):
        dhcp.get_leases()


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
    assert json.loads(read.stdout)["result"]["leases_count"] == 2
    boundary = subprocess.run([sys.executable, "agathodaimon/cli.py", "network", "dhcp", "boundary", "show"], cwd=ROOT, env=env, text=True, capture_output=True, check=True)
    boundary_receipt = json.loads(boundary.stdout)
    assert boundary_receipt["result"] == dhcp.boundary()
    assert boundary_receipt["active_leases_count"] == 2
    mutate = subprocess.run([sys.executable, str(ROOT / "agathodaimon" / "cli.py"), "network", "dhcp", "add-reservation", "aa:bb:cc:dd:ee:05", "--hostname", "delta"], cwd=ROOT, env={**env, "CADUCEUS_STAFF_PYTHON": sys.executable}, text=True, capture_output=True, check=True)
    receipt = json.loads(mutate.stdout)
    assert receipt["ok"] and receipt["action"] == "add-reservation"

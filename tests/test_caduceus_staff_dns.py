from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from caduceus_staff.network.dns import DnsError, DnsManager

PAYLOAD = '''server:
    local-data: "laptop.home.arpa. IN A 192.168.123.19"
    local-data: "laptop.home.arpa. IN A 192.168.123.20"
'''


class Runner:
    def __init__(self, fail: str | None = None) -> None:
        self.fail = fail
        self.failed = False
        self.commands: list[list[str]] = []

    def __call__(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        command_list = list(command)
        self.commands.append(command_list)
        text = " ".join(command_list)
        if self.fail and self.fail in text and not self.failed:
            self.failed = True
            return subprocess.CompletedProcess(command_list, 1, "", "fixture failure")
        return subprocess.CompletedProcess(command_list, 0, "", "")


class DnsManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name)
        self.root = self.base / "unbound.conf"
        self.dropins = self.base / "unbound.conf.d"
        self.dropins.mkdir()
        self.root.write_text(f'server:\ninclude-toplevel: "{self.dropins}/*.conf"\n', encoding="utf-8")
        (self.dropins / "neighbor.conf").write_text('server:\n    local-data: "unchanged.home.arpa. IN A 192.168.123.7"\n', encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def subject(self, runner: Runner) -> DnsManager:
        return DnsManager(self.root, self.dropins, command_runner=runner)

    def test_apply_stages_validates_reloads_and_preserves_neighbor(self) -> None:
        runner = Runner()
        receipt = self.subject(runner).apply({"target": "laptop-home-arpa.conf", "dropIn": PAYLOAD})
        self.assertTrue(receipt["ok"])
        self.assertTrue(receipt["mutationPerformed"])
        self.assertTrue(receipt["stagedValidation"])
        self.assertTrue(receipt["liveValidation"])
        self.assertEqual(receipt["reload"], "reloaded")
        self.assertEqual((self.dropins / "laptop-home-arpa.conf").read_text(encoding="utf-8"), PAYLOAD)
        self.assertTrue((self.dropins / "neighbor.conf").read_text(encoding="utf-8").endswith("192.168.123.7\"\n"))
        checks = [command for command in runner.commands if command[0] == "unbound-checkconf"]
        self.assertNotEqual(checks[0][1], str(self.root))
        self.assertEqual(checks[1], ["unbound-checkconf", str(self.root)])
        self.assertIn(["systemctl", "reload", "unbound"], runner.commands)

    def test_idempotence_validates_but_does_not_reload(self) -> None:
        target = self.dropins / "laptop-home-arpa.conf"
        target.write_text(PAYLOAD, encoding="utf-8")
        runner = Runner()
        receipt = self.subject(runner).apply({"dropIn": PAYLOAD})
        self.assertTrue(receipt["ok"])
        self.assertFalse(receipt["mutationPerformed"])
        self.assertEqual(receipt["reload"], "not-needed-idempotent")
        self.assertNotIn(["systemctl", "reload", "unbound"], runner.commands)

    def test_rejects_malformed_payload_and_wrong_target(self) -> None:
        subject = self.subject(Runner())
        with self.assertRaisesRegex(DnsError, "dns-payload-not-admitted"):
            subject.apply({"dropIn": "server:\n    interface: 0.0.0.0\n"})
        with self.assertRaisesRegex(DnsError, "dns-target-not-admitted"):
            subject.apply({"target": "../../etc/shadow", "dropIn": PAYLOAD})

    def test_payload_requires_exact_laptop_rrset(self) -> None:
        single_19 = '''server:
    local-data: "laptop.home.arpa. IN A 192.168.123.19"
'''
        single_20 = '''server:
    local-data: "laptop.home.arpa. IN A 192.168.123.20"
'''
        reversed_both = '''server:
    local-data: "laptop.home.arpa. IN A 192.168.123.20"
    local-data: "laptop.home.arpa. IN A 192.168.123.19"
'''
        duplicate_19 = '''server:
    local-data: "laptop.home.arpa. IN A 192.168.123.19"
    local-data: "laptop.home.arpa. IN A 192.168.123.19"
'''
        extra_21 = '''server:
    local-data: "laptop.home.arpa. IN A 192.168.123.19"
    local-data: "laptop.home.arpa. IN A 192.168.123.20"
    local-data: "laptop.home.arpa. IN A 192.168.123.21"
'''
        self.assertEqual(DnsManager._validate_payload(PAYLOAD), PAYLOAD.encode("utf-8"))
        self.assertEqual(DnsManager._validate_payload(reversed_both), reversed_both.encode("utf-8"))
        for payload in (single_19, single_20, duplicate_19, extra_21):
            with self.subTest(payload=payload), self.assertRaisesRegex(DnsError, "dns-payload-not-admitted"):
                DnsManager._validate_payload(payload)

    def test_rejects_symlink_and_missing_include(self) -> None:
        target = self.dropins / "laptop-home-arpa.conf"
        target.symlink_to(self.base / "outside")
        with self.assertRaisesRegex(DnsError, "dns-target-symlink-refused"):
            self.subject(Runner()).apply({"dropIn": PAYLOAD})
        target.unlink()
        self.root.write_text("server:\n", encoding="utf-8")
        with self.assertRaisesRegex(DnsError, "dns-managed-include-missing"):
            self.subject(Runner()).apply({"dropIn": PAYLOAD})

    def test_checkconf_failure_does_not_replace_target(self) -> None:
        target = self.dropins / "laptop-home-arpa.conf"
        target.write_text("old", encoding="utf-8")
        with self.assertRaisesRegex(DnsError, "command failed"):
            self.subject(Runner("unbound-checkconf")).apply({"dropIn": PAYLOAD})
        self.assertEqual(target.read_text(encoding="utf-8"), "old")

    def test_reload_failure_restores_target_and_revalidates(self) -> None:
        target = self.dropins / "laptop-home-arpa.conf"
        target.write_text("old", encoding="utf-8")
        runner = Runner("systemctl reload unbound")
        receipt = self.subject(runner).apply({"dropIn": PAYLOAD})
        self.assertFalse(receipt["ok"])
        self.assertEqual(receipt["rollback"], "restored-and-revalidated")
        self.assertEqual(target.read_text(encoding="utf-8"), "old")
        self.assertEqual(runner.commands.count(["systemctl", "reload", "unbound"]), 2)

    def test_receipt_is_hash_only_and_cli_binds_intent(self) -> None:
        bin_dir = self.base / "bin"
        bin_dir.mkdir()
        checker = bin_dir / "unbound-checkconf"
        checker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        checker.chmod(0o755)
        env = {
            **os.environ,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "PYTHONPATH": str(ROOT),
            "CADUCEUS_UNBOUND_CONFIG": str(self.root),
            "CADUCEUS_UNBOUND_DROPIN_DIR": str(self.dropins),
        }
        process = subprocess.run(
            [sys.executable, "-m", "caduceus_staff.network.dns", "intent", "POST", "/api/dns/unbound/drop-in", "--metadata-json", json.dumps({"dropIn": PAYLOAD, "dryRun": True})],
            cwd=ROOT, env=env, text=True, capture_output=True, check=True,
        )
        receipt = json.loads(process.stdout)
        self.assertEqual(receipt["action"], "plan-managed-drop-in")
        self.assertTrue(receipt["afterHash"])
        self.assertNotIn(PAYLOAD, process.stdout)
        self.assertNotIn("dropIn", receipt)
        refused = subprocess.run(
            [sys.executable, "-m", "caduceus_staff.network.dns", "intent", "GET", "/api/dns/unbound/drop-in", "--metadata-json", "{}"],
            cwd=ROOT, env=env, text=True, capture_output=True,
        )
        self.assertEqual(refused.returncode, 1)
        self.assertEqual(json.loads(refused.stdout)["firstMissingSignal"], "dns-intent-not-admitted")


if __name__ == "__main__":
    unittest.main()

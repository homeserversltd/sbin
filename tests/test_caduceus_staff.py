import json
import stat
import subprocess
import sys
import unittest
from pathlib import Path

from agathodaimon.lib.actuators import ACTUATORS

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    proc = subprocess.run(
        [sys.executable, "agathodaimon/cli.py", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if not proc.stdout:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


class CaduceusStaffTests(unittest.TestCase):
    def test_lists_staff_actuators(self):
        data = run()
        self.assertEqual(data["schema"], "agathodaimon.cli.spine.v1")
        ids = set(data["nouns"])
        legacy_ids = {
            "backblaze-recover",
            "forgejo-backup-b2",
            "forgejo-migrate",
            "calibre-helper",
            "calibre-watch",
        }
        self.assertIn("network", ids)
        self.assertIn("lib", ids)


    def test_band_lists_verbs(self):
        data = run("network")
        self.assertEqual(data["noun"], "network")
        self.assertEqual(data["verbs"], ["dhcp", "dns", "firewall", "identity", "child-device", "wake-on-lan", "linker", "cert"])

    def test_read_only_exemplar_is_truthful(self):
        data = run("network", "dhcp", "status")
        self.assertFalse(data.get("mutationPerformed", False))
        self.assertIn("ok", data)


    def test_directly_executed_python_staff_have_shebang(self):
        paths = [ROOT / "agathodaimon/cli.py"]
        paths.extend(
            sorted(
                path
                for path in (ROOT / "agathodaimon").rglob("*.py")
                if path.stat().st_mode & stat.S_IXUSR
            )
        )
        for path in paths:
            self.assertTrue(
                path.read_bytes().startswith(b"#!/usr/bin/env python3\n"),
                path,
            )


if __name__ == "__main__":
    unittest.main()

import json
import subprocess
import sys
import unittest
from pathlib import Path

from caduceus_staff.actuators import ACTUATORS

ROOT = Path(__file__).resolve().parents[1]


def run(*args):
    proc = subprocess.run(
        [sys.executable, "-m", "caduceus_staff", *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr)
    return json.loads(proc.stdout)


class CaduceusStaffTests(unittest.TestCase):
    def test_lists_staff_actuators(self):
        data = run("list")
        self.assertEqual(data["schema"], "caduceus.staff.library.list.v1")
        ids = {item["id"] for item in data["actuators"]}
        legacy_ids = {
            "backblaze-recover",
            "forgejo-backup-b2",
            "forgejo-migrate",
            "calibre-helper",
            "calibre-watch",
        }
        self.assertLessEqual(legacy_ids, ids)
        self.assertEqual(ids, set(ACTUATORS))
        for actuator in data["actuators"]:
            self.assertTrue(
                {
                    "id",
                    "family",
                    "receipt_schema",
                    "legacy_script",
                    "legacyPath",
                    "launcher",
                    "default_args",
                    "description",
                }.issubset(actuator)
            )
            for key in (
                "id",
                "family",
                "receipt_schema",
                "legacy_script",
                "legacyPath",
                "launcher",
                "description",
            ):
                self.assertIsInstance(actuator[key], str)
                self.assertTrue(actuator[key])
            self.assertIsInstance(actuator["default_args"], list)
            self.assertTrue(all(isinstance(arg, str) for arg in actuator["default_args"]))

    def test_status_reads_preserved_legacy_script_without_executing(self):
        data = run("status", "calibre-helper")
        self.assertEqual(data["schema"], "caduceus.staff.calibre.helper.v1")
        self.assertTrue(data["legacy"]["path"].endswith("calibreHelperDaemon.sh"))
        self.assertTrue(data["legacy"]["exists"])
        self.assertEqual(data["mode"], "additive-python-membrane")

    def test_run_defaults_to_dry_run_plan(self):
        data = run("run", "backblaze-recover", "--", "--help")
        self.assertEqual(data["schema"], "caduceus.staff.backblaze.recover.v1")
        self.assertEqual(data["action"], "plan")
        self.assertFalse(data["mutationPerformed"])
        self.assertIn("--help", data["argv"])


if __name__ == "__main__":
    unittest.main()
